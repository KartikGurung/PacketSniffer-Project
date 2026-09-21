import threading
import os
from scapy.all import sniff, wrpcap, conf, get_if_list

def get_interfaces():
    """
    Lists all available network interfaces on the system.
    Tries to retrieve human-readable names and IP/MAC addresses.
    """
    interfaces = []
    
    # Try Windows specific interface retrieval first
    try:
        from scapy.arch.windows import get_windows_if_list
        win_ifaces = get_windows_if_list()
        for face in win_ifaces:
            guid = face.get("guid") or face.get("name")
            desc = face.get("description") or face.get("name")
            ips = face.get("ips", [])
            ip = ips[0] if ips else "No IP"
            mac = face.get("mac") or "No MAC"
            
            # Filter out loopback or meaningless adapters if they clutter, but keep them for sniffing
            interfaces.append({
                "id": guid,
                "name": desc,
                "ip": ip,
                "mac": mac,
                "status": "Active" if ip != "No IP" else "Inactive"
            })
    except Exception as e:
        print(f"Windows interfaces fetch failed: {e}. Falling back to conf.ifaces.")
        # Fallback to Scapy conf.ifaces
        try:
            for name, iface in conf.ifaces.items():
                interfaces.append({
                    "id": iface.name,
                    "name": iface.description or iface.name,
                    "ip": iface.ip or "No IP",
                    "mac": iface.mac or "No MAC",
                    "status": "Active" if iface.ip else "Inactive"
                })
        except Exception as e2:
            print(f"Scapy conf.ifaces failed: {e2}. Falling back to get_if_list.")
            # Fallback to basic interface list
            try:
                for name in get_if_list():
                    interfaces.append({
                        "id": name,
                        "name": name,
                        "ip": "Unknown",
                        "mac": "Unknown",
                        "status": "Unknown"
                    })
            except Exception as e3:
                print(f"Basic get_if_list failed: {e3}")
    
    # Ensure there is at least a loopback interface
    if not interfaces:
        interfaces.append({
            "id": "loopback",
            "name": "Loopback Pseudo-Interface",
            "ip": "127.0.0.1",
            "mac": "00:00:00:00:00:00",
            "status": "Active"
        })
        
    return interfaces


import datetime

def log_debug(msg):
    try:
        log_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "app.log")
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(f"{datetime.datetime.now().isoformat()} - SNIFFER: {msg}\n")
    except Exception as e:
        print(f"Logging failed: {e}")

class LiveSniffer:
    """
    Thread-safe packet sniffer utilizing Scapy's sniffing loop.
    Runs in a background thread to prevent locking the web server.
    """
    def __init__(self, packet_callback):
        self.packet_callback = packet_callback
        self.thread = None
        self.is_running = False
        self.interface = None
        self.filter_str = None
        self.captured_packets = []  # Keep a buffer of packet objects for PCAP export
        self._stop_event = threading.Event()
        self._lock = threading.Lock()

    def _sniffer_loop(self):
        log_debug(f"Sniffer thread active. Target interface={self.interface}, BPF Filter={self.filter_str}")
        try:
            sniff_args = {
                "prn": self._handle_packet,
                "stop_filter": lambda x: self._stop_event.is_set(),
                "store": False
            }
            if self.interface:
                # Resolve GUID string/name to Scapy NetworkInterface object
                scapy_iface = None
                for iface_key, iface_obj in conf.ifaces.items():
                    if (self.interface == iface_key or 
                        self.interface == iface_obj.name or 
                        self.interface == getattr(iface_obj, "guid", "") or
                        self.interface == getattr(iface_obj, "network_name", "")):
                        scapy_iface = iface_obj
                        break
                
                if scapy_iface:
                    log_debug(f"Resolved interface '{self.interface}' to Scapy NetworkInterface: {scapy_iface}")
                    sniff_args["iface"] = scapy_iface
                else:
                    log_debug(f"Could not resolve '{self.interface}' in conf.ifaces. Using as raw string.")
                    sniff_args["iface"] = self.interface
                    
            if self.filter_str and self.filter_str.strip():
                sniff_args["filter"] = self.filter_str.strip()

            sniff(**sniff_args)
            log_debug("Sniffer sniff() loop completed successfully.")
        except Exception as e:
            log_debug(f"EXCEPTION in Scapy sniffing loop: {e}")
            import traceback
            log_debug(traceback.format_exc())
            print(f"Error in Scapy sniffing loop: {e}")
        finally:
            with self._lock:
                self.is_running = False
            log_debug("Sniffer thread terminated.")

    def _handle_packet(self, packet):
        with self._lock:
            # Store packet for PCAP export. Limit queue to prevent memory leak
            self.captured_packets.append(packet)
            if len(self.captured_packets) > 10000:
                self.captured_packets.pop(0)
        
        # Fire callback to process packet
        try:
            self.packet_callback(packet)
        except Exception as e:
            print(f"Error executing packet callback: {e}")

    def start(self, interface=None, filter_str=None):
        with self._lock:
            if self.is_running:
                log_debug("start() called but sniffer is already running.")
                return False
            
            self.interface = interface
            self.filter_str = filter_str
            self._stop_event.clear()
            self.is_running = True
            
            log_debug(f"Launching sniffer thread on interface: {interface}...")
            self.thread = threading.Thread(target=self._sniffer_loop, daemon=True)
            self.thread.start()
            return True

    def stop(self):
        with self._lock:
            if not self.is_running:
                return False
            self._stop_event.set()
        
        # Wait for thread to finish
        if self.thread:
            self.thread.join(timeout=3.0)
            
        with self._lock:
            self.is_running = False
        return True

    def clear(self):
        with self._lock:
            self.captured_packets.clear()

    def save_pcap(self, filepath):
        with self._lock:
            if not self.captured_packets:
                return False
            try:
                wrpcap(filepath, self.captured_packets)
                return True
            except Exception as e:
                print(f"Failed to write PCAP file: {e}")
                return False
