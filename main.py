import sys
import os
import threading
import time
import uvicorn
import webview

def start_server():
    """
    Launches Uvicorn to serve the FastAPI application.
    """
    config = uvicorn.Config(
        "backend.server:app",
        host="127.0.0.1",
        port=8000,
        log_level="warning",  # Keep console output clean
        reload=False
    )
    server = uvicorn.Server(config)
    server.run()

if __name__ == "__main__":
    print("Starting backend web server...")
    # Start the backend server on a background daemon thread
    server_thread = threading.Thread(target=start_server, daemon=True)
    server_thread.start()
    
    # Give the server a moment to spin up and bind to the port
    time.sleep(1.5)
    
    print("Launching Desktop Application GUI...")
    # Initialize and configure the native desktop window
    # Standard 1280x850 provides ample space for charts, packet logs, and sidebar inspectors
    webview.create_window(
        title="Apex Network Sniffer & Threat Detector",
        url="http://127.0.0.1:8000",
        width=1280,
        height=850,
        resizable=True,
        min_size=(1024, 700)
    )
    
    # Starts the GUI loop. When the window closes, this call blocks no longer,
    # and the python script will exit, killing the daemon server thread.
    webview.start()
    print("Apex Packet Sniffer shutdown successfully.")
