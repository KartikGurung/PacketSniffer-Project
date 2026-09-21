import time
import base64
from collections import defaultdict
from scapy.all import IP, IPv6, TCP, UDP, ICMP, ARP, DNS, Raw, Ether

class PacketAnalyzer:
    """
    Parses live packets, maintains traffic statistics, 
    and implements simple intrusion detection algorithms.
    """
    def __init__(self):
        self.reset()

    def reset(self):
        self.total_packets = 0
        self.total_bytes = 0
        self.protocol_counts = {
            "TCP": 0,
            "UDP": 0,
            "ICMP": 0,
            "DNS": 0,
            "ARP": 0,
            "Other": 0
        }
        
        # Real-time metrics
        self.bandwidth_window = []  # list of tuples: (timestamp, byte_size)
        self.pps_window = []        # list of timestamps
        
        # IDS (Intrusion Detection System) state
        # 1. Port Scan Detection: {src_ip: {set of unique destination ports}}
        self.port_scan_cache = defaultdict(set)
        self.port_scan_timestamps = defaultdict(float)
        
        # 2. SYN Flood Detection: {src_ip: count of SYN packets}
        self.syn_flood_cache = defaultdict(int)
        self.syn_flood_timestamps = defaultdict(float)
        
        # 3. ARP Spoofing Detection: {ip_address: mac_address}
        self.arp_table = {}
        
        self.alerts = []

    def get_stats(self):
        """
        Returns calculated metrics: packets/sec, bytes/sec, and cumulative counts.
        """
        now = time.time()
        
        # Clean rolling windows (older than 3 seconds)
        self.bandwidth_window = [x for x in self.bandwidth_window if now - x[0] <= 3.0]
        self.pps_window = [x for x in self.pps_window if now - x <= 3.0]
        
        # Calculate rates
        bytes_sec = sum(x[1] for x in self.bandwidth_window) / 3.0 if self.bandwidth_window else 0.0
        packets_sec = len(self.pps_window) / 3.0 if self.pps_window else 0.0
        
        return {
            "total_packets": self.total_packets,
            "total_bytes": self.total_bytes,
            "protocol_counts": self.protocol_counts,
            "bytes_sec": round(bytes_sec, 2),
            "packets_sec": round(packets_sec, 1),
            "alerts_count": len(self.alerts)
        }

    def process_packet(self, packet):
        """
        Parses a packet, updates metrics, checks for security alerts,
        and returns a detailed serializable dictionary.
        """
        self.total_packets += 1
        pkt_len = len(packet)
        self.total_bytes += pkt_len
        
        now = time.time()
        self.bandwidth_window.append((now, pkt_len))
        self.pps_window.append(now)
        
        # Primary attributes
        pkt_id = self.total_packets
        src = "Unknown"
        dst = "Unknown"
        proto = "Other"
        info = "Raw Packet"
        
        # JSON layers container for inspection
        layers = {}
        
        # Parse Link Layer (Ethernet)
        if Ether in packet:
            eth = packet[Ether]
            src = eth.src
            dst = eth.dst
            proto = "Ethernet"
            info = f"MAC: {eth.src} -> {eth.dst}"
            layers["Ethernet"] = {
                "Source MAC": eth.src,
                "Destination MAC": eth.dst,
                "Type": hex(eth.type)
            }
            
        # Parse Network Layer (IP / IPv6 / ARP)
        ip_src = None
        ip_dst = None
        
        if IP in packet:
            ip = packet[IP]
            src = ip_src = ip.src
            dst = ip_dst = ip.dst
            proto = "IPv4"
            info = f"{ip.src} -> {ip.dst}"
            layers["IPv4"] = {
                "Version": ip.version,
                "Header Length": ip.ihl * 4,
                "TTL": ip.ttl,
                "Protocol": ip.proto,
                "Total Length": ip.len,
                "Checksum": hex(ip.chksum)
            }
        elif IPv6 in packet:
            ipv6 = packet[IPv6]
            src = ip_src = ipv6.src
            dst = ip_dst = ipv6.dst
            proto = "IPv6"
            info = f"{ipv6.src} -> {ipv6.dst}"
            layers["IPv6"] = {
                "Version": ipv6.version,
                "Traffic Class": ipv6.tc,
                "Flow Label": ipv6.fl,
                "Payload Length": ipv6.plen,
                "Next Header": ipv6.nh,
                "Hop Limit": ipv6.hlim
            }
        elif ARP in packet:
            arp = packet[ARP]
            src = arp.psrc
            dst = arp.pdst
            proto = "ARP"
            
            if arp.op == 1:
                info = f"Who has {arp.pdst}? Tell {arp.psrc}"
            elif arp.op == 2:
                info = f"{arp.psrc} is at {arp.hwsrc}"
                
            layers["ARP"] = {
                "Hardware Type": arp.hwtype,
                "Protocol Type": arp.ptype,
                "Hardware Size": arp.hwlen,
                "Protocol Size": arp.plen,
                "Opcode": "request (1)" if arp.op == 1 else "reply (2)",
                "Sender MAC": arp.hwsrc,
                "Sender IP": arp.psrc,
                "Target MAC": arp.hwdst,
                "Target IP": arp.pdst
            }
            self.protocol_counts["ARP"] += 1
            
            # ARP Spoofing IDS Check
            self._check_arp_spoofing(arp)
            
        # Parse Transport Layer (TCP / UDP / ICMP)
        if TCP in packet:
            tcp = packet[TCP]
            proto = "TCP"
            info = f"{ip_src}:{tcp.sport} -> {ip_dst}:{tcp.dport} [{tcp.flags}]"
            layers["TCP"] = {
                "Source Port": tcp.sport,
                "Destination Port": tcp.dport,
                "Seq Number": tcp.seq,
                "Ack Number": tcp.ack,
                "Data Offset": tcp.dataofs,
                "Flags": str(tcp.flags),
                "Window Size": tcp.window,
                "Checksum": hex(tcp.chksum)
            }
            self.protocol_counts["TCP"] += 1
            
            # TCP IDS Checks
            if ip_src and ip_dst:
                self._check_port_scan(ip_src, tcp.dport)
                self._check_syn_flood(ip_src, tcp.flags)
                
        elif UDP in packet:
            udp = packet[UDP]
            proto = "UDP"
            info = f"{ip_src}:{udp.sport} -> {ip_dst}:{udp.dport}"
            layers["UDP"] = {
                "Source Port": udp.sport,
                "Destination Port": udp.dport,
                "Length": udp.len,
                "Checksum": hex(udp.chksum)
            }
            self.protocol_counts["UDP"] += 1
            
            # UDP IDS Checks
            if ip_src and ip_dst:
                self._check_port_scan(ip_src, udp.dport)
                
            # Check for DNS inside UDP
            if DNS in packet:
                dns = packet[DNS]
                proto = "DNS"
                dns_queries = []
                if dns.qd:
                    # Parse DNS query name
                    qname = dns.qd.qname.decode(errors="ignore") if hasattr(dns.qd, "qname") else "unknown"
                    dns_queries.append(qname)
                    info = f"DNS Query: {qname}"
                else:
                    info = "DNS Query/Response"
                    
                layers["DNS"] = {
                    "Transaction ID": hex(dns.id),
                    "Query/Response": "Response" if dns.qr else "Query",
                    "Opcode": dns.opcode,
                    "Authoritative": dns.aa,
                    "Truncated": dns.tc,
                    "Recursion Desired": dns.rd,
                    "Rcode": dns.rcode,
                    "Questions Count": dns.qdcount,
                    "Answers Count": dns.ancount
                }
                if dns_queries:
                    layers["DNS"]["Queries"] = dns_queries
                    
                self.protocol_counts["DNS"] += 1
                
                # Check for DNS Anomaly (Tunneling or suspicious queries)
                if ip_src and dns_queries:
                    self._check_dns_anomaly(ip_src, dns_queries[0])
                    
        elif ICMP in packet:
            icmp = packet[ICMP]
            proto = "ICMP"
            info = f"ICMP Type: {icmp.type}, Code: {icmp.code} ({ip_src} -> {ip_dst})"
            layers["ICMP"] = {
                "Type": icmp.type,
                "Code": icmp.code,
                "Checksum": hex(icmp.chksum)
            }
            self.protocol_counts["ICMP"] += 1
            
        else:
            if proto not in ["ARP", "DNS"]:
                self.protocol_counts["Other"] += 1

        # Parse Payload / Raw Data
        payload_data = None
        if Raw in packet:
            raw_payload = packet[Raw].load
            payload_len = len(raw_payload)
            
            # Convert raw payload to base64 so JS can easily decode and show hex viewer
            payload_data = base64.b64encode(raw_payload).decode("utf-8")
            
            # Simple HTTP detection in raw payload
            if b"HTTP/" in raw_payload:
                try:
                    payload_str = raw_payload.decode(errors="ignore")
                    first_line = payload_str.split("\r\n")[0]
                    if len(first_line) < 100:
                        info = f"HTTP: {first_line}"
                        proto = "HTTP"
                except Exception:
                    pass
            
            layers["Payload"] = {
                "Length": payload_len,
                "Preview": raw_payload[:64].decode(errors="ignore")
            }
            
            # Data exfiltration check
            if payload_len > 1400:
                self._add_alert("Warning", "Large Data Transfer", f"Source IP {src} transmitted a large payload size of {payload_len} bytes.")

        # Final structured packet packet
        return {
            "id": pkt_id,
            "timestamp": round(now, 3),
            "source": src,
            "destination": dst,
            "protocol": proto,
            "length": pkt_len,
            "info": info,
            "layers": layers,
            "payload": payload_data  # Base64 string
        }

    # ==========================================
    # IDS/Anomaly Detection Functions
    # ==========================================
    def _add_alert(self, severity, category, message):
        """
        Adds a threat detection alert. Prevents flooding of identical active alerts.
        """
        now = time.time()
        
        # Don't add identical alert if logged within last 10 seconds
        for alert in reversed(self.alerts[-5:]):
            if alert["category"] == category and alert["message"] == message:
                if now - alert["timestamp"] < 10.0:
                    return
                    
        self.alerts.append({
            "timestamp": round(now, 3),
            "severity": severity,
            "category": category,
            "message": message
        })

    def _check_port_scan(self, src_ip, dst_port):
        """
        Alerts if an IP requests more than 15 unique ports within a 10-second window.
        """
        now = time.time()
        
        # If cache expired (older than 10 sec), reset
        if now - self.port_scan_timestamps[src_ip] > 10.0:
            self.port_scan_cache[src_ip] = set()
            self.port_scan_timestamps[src_ip] = now
            
        self.port_scan_cache[src_ip].add(dst_port)
        
        if len(self.port_scan_cache[src_ip]) > 15:
            self._add_alert(
                "High",
                "Port Scanning Detected",
                f"Source IP {src_ip} attempted connections to {len(self.port_scan_cache[src_ip])} unique ports within 10s."
            )

    def _check_syn_flood(self, src_ip, flags):
        """
        Alerts if an IP sends more than 50 SYN packets without ACK within 5 seconds.
        """
        if "S" in flags and "A" not in flags:  # SYN only
            now = time.time()
            
            # Reset if interval expired
            if now - self.syn_flood_timestamps[src_ip] > 5.0:
                self.syn_flood_cache[src_ip] = 0
                self.syn_flood_timestamps[src_ip] = now
                
            self.syn_flood_cache[src_ip] += 1
            
            if self.syn_flood_cache[src_ip] > 50:
                self._add_alert(
                    "Critical",
                    "SYN Flood Anomaly",
                    f"Potential SYN flood attack from {src_ip}: {self.syn_flood_cache[src_ip]} SYN-only packets within 5s."
                )

    def _check_arp_spoofing(self, arp):
        """
        Detects if an IP is claimed by multiple MAC addresses (ARP cache poisoning).
        """
        if arp.op == 2:  # Reply
            sender_ip = arp.psrc
            sender_mac = arp.hwsrc
            
            if sender_ip in self.arp_table:
                if self.arp_table[sender_ip] != sender_mac:
                    old_mac = self.arp_table[sender_ip]
                    self._add_alert(
                        "Critical",
                        "ARP Spoofing Detected",
                        f"IP Conflict! Host {sender_ip} reported MAC {sender_mac}, but previously had MAC {old_mac}. Possible ARP cache poisoning."
                    )
            else:
                self.arp_table[sender_ip] = sender_mac

    def _check_dns_anomaly(self, src_ip, domain):
        """
        Checks if the DNS query looks like DNS tunneling (very long domains)
        or accesses suspicious extensions.
        """
        # DNS Tunneling check: unusually long domain name
        if len(domain) > 80:
            self._add_alert(
                "Medium",
                "Suspicious DNS Tunneling",
                f"Client {src_ip} requested an abnormally long domain query ({len(domain)} chars): {domain[:40]}..."
            )
            
        # Suspicious TLD check
        suspicious_tlds = [".top", ".xyz", ".bid", ".loan", ".win", ".download"]
        for tld in suspicious_tlds:
            if domain.endswith(tld) or domain.endswith(tld + "."):
                self._add_alert(
                    "Warning",
                    "Suspicious Domain Requested",
                    f"Client {src_ip} query matches known adware/malware TLD pattern: {domain}"
                )
