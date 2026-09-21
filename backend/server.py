import asyncio
import os
import queue
import tempfile
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel

from backend.sniffer import LiveSniffer, get_interfaces
from backend.analyzer import PacketAnalyzer

# Create directory path variables
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FRONTEND_DIR = os.path.join(BASE_DIR, "frontend")

app = FastAPI(title="Apex Packet Sniffer API")

# Enable CORS for development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

import datetime

def log_debug(msg):
    try:
        log_path = os.path.join(BASE_DIR, "app.log")
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(f"{datetime.datetime.now().isoformat()} - SERVER: {msg}\n")
    except Exception as e:
        print(f"Logging failed: {e}")

# Shared state
analyzer = PacketAnalyzer()
packet_queue = queue.Queue(maxsize=2000)

def packet_captured_callback(packet):
    """
    Invoked by Scapy sniffer thread on packet capture.
    Parses the packet, updates analyzer state, and puts the result in the queue.
    """
    try:
        parsed = analyzer.process_packet(packet)
        try:
            packet_queue.put_nowait(parsed)
        except queue.Full:
            # Drop packets if the queue is overloaded to protect memory/performance
            pass
    except Exception as e:
        log_debug(f"Error processing packet callback: {e}")
        print(f"Error processing packet: {e}")

# Sniffer instance
sniffer = LiveSniffer(packet_captured_callback)

# WebSocket Connection Manager
class ConnectionManager:
    def __init__(self):
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception:
                # Disconnect handled separately or connection closed
                pass

manager = ConnectionManager()

# Background async task to drain the queue and broadcast packets/stats
async def ws_broadcast_loop():
    last_stats_sent = 0.0
    while True:
        now = asyncio.get_event_loop().time()
        
        # 1. Gather packet batch from thread-safe queue
        packet_batch = []
        while not packet_queue.empty():
            try:
                pkt = packet_queue.get_nowait()
                packet_batch.append(pkt)
                packet_queue.task_done()
                if len(packet_batch) >= 50:  # Batch limit
                    break
            except queue.Empty:
                break
                
        # 2. Broadcast packets if any
        if packet_batch:
            await manager.broadcast({
                "type": "packets",
                "data": packet_batch
            })
            
        # 3. Broadcast stats and alerts every 1 second
        if now - last_stats_sent >= 1.0:
            stats = analyzer.get_stats()
            await manager.broadcast({
                "type": "stats",
                "data": stats
            })
            await manager.broadcast({
                "type": "alerts",
                "data": analyzer.alerts
            })
            last_stats_sent = now
            
        await asyncio.sleep(0.1)

# Start background loop on startup
broadcast_task = None

@app.on_event("startup")
async def startup_event():
    global broadcast_task
    broadcast_task = asyncio.create_task(ws_broadcast_loop())

@app.on_event("shutdown")
async def shutdown_event():
    if broadcast_task:
        broadcast_task.cancel()
    sniffer.stop()

# ==========================================
# REST API Endpoints
# ==========================================

class StartRequest(BaseModel):
    interface_id: str | None = None
    filter_str: str | None = None

@app.get("/api/interfaces")
def list_adapters():
    """
    Returns all active and inactive network interfaces on the host.
    """
    log_debug("GET /api/interfaces called")
    try:
        ifaces = get_interfaces()
        log_debug(f"Found {len(ifaces)} interfaces.")
        return ifaces
    except Exception as e:
        log_debug(f"EXCEPTION in list_adapters: {e}")
        import traceback
        log_debug(traceback.format_exc())
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/start")
def start_capture(req: StartRequest):
    """
    Starts sniffing on the chosen interface with the optional BPF filter.
    """
    log_debug(f"POST /api/start called with interface_id={req.interface_id}, filter={req.filter_str}")
    try:
        # Empty queue and reset analyzer stats for a clean start
        analyzer.reset()
        while not packet_queue.empty():
            try:
                packet_queue.get_nowait()
                packet_queue.task_done()
            except queue.Empty:
                break
                
        sniffer.clear()
        
        success = sniffer.start(interface=req.interface_id, filter_str=req.filter_str)
        log_debug(f"sniffer.start returned success={success}")
        if not success:
            raise HTTPException(status_code=400, detail="Sniffer is already running or failed to start.")
            
        return {"status": "started", "interface": req.interface_id, "filter": req.filter_str}
    except Exception as e:
        log_debug(f"EXCEPTION in start_capture endpoint: {e}")
        import traceback
        log_debug(traceback.format_exc())
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/stop")
def stop_capture():
    """
    Stops the live sniffer.
    """
    success = sniffer.stop()
    if not success:
        return {"status": "already stopped"}
    return {"status": "stopped"}

@app.post("/api/clear")
def clear_capture():
    """
    Clears all captured packet history, statistics, and threat logs.
    """
    sniffer.clear()
    analyzer.reset()
    while not packet_queue.empty():
        try:
            packet_queue.get_nowait()
            packet_queue.task_done()
        except queue.Empty:
            break
    return {"status": "cleared"}

@app.get("/api/download-pcap")
def download_pcap():
    """
    Saves current memory buffer to a temporary file and returns it as a download.
    """
    # Create a temporary file
    temp_dir = tempfile.gettempdir()
    pcap_path = os.path.join(temp_dir, "apex_capture.pcap")
    
    success = sniffer.save_pcap(pcap_path)
    if not success:
        raise HTTPException(status_code=400, detail="No packets captured to export.")
        
    return FileResponse(
        path=pcap_path,
        media_type="application/octet-stream",
        filename="apex_capture.pcap"
    )

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    # Send current stats & alerts immediately
    await websocket.send_json({"type": "stats", "data": analyzer.get_stats()})
    await websocket.send_json({"type": "alerts", "data": analyzer.alerts})
    
    try:
        while True:
            # Keep connection alive, listen for messages if needed
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception:
        manager.disconnect(websocket)

# Mount frontend files (fallback to index.html for root)
if os.path.exists(FRONTEND_DIR):
    app.mount("/", StaticFiles(directory=FRONTEND_DIR, html=True), name="frontend")
else:
    print(f"Warning: Frontend folder '{FRONTEND_DIR}' not found. UI files will not be served.")
