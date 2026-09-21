# Apex Packet Sniffer & Network Threat Detector

[![Python Version](https://img.shields.io/badge/python-3.11%2B-blue?logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110%2B-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![Scapy](https://img.shields.io/badge/Scapy-2.5%2B-red?logo=scapy&logoColor=white)](https://scapy.net/)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)](#)

An advanced, real-time desktop packet sniffer, protocol analyzer, and network intrusion detection system (NIDS) designed for network administrators and cybersecurity researchers. This project binds directly to physical or virtual network interface cards (NICs) to capture, parse, and analyze live network traffic.

Built as a native desktop application, it combines a robust **Python backend** utilizing **Scapy** and **FastAPI** with a **stunning, glassmorphic dark-mode web dashboard** wrapped in **PyWebView**.

---

## 📸 Dashboard Preview

* **Live Traffic Stream**: View details of packets (IPv4, IPv6, TCP, UDP, ARP, DNS, ICMP, HTTP) captured in real-time.
* **Intrusion Detection Feed**: Visual alerts for port scanning, TCP SYN floods, ARP cache spoofing, and suspicious DNS requests.
* **Packet Inspector Drawer**: Click any packet to view its structured tree decode alongside a Wireshark-like offset Hex & ASCII raw payload dump.
* **Real-time Analytics**: Dynamic charts mapping data throughput (Bytes/sec) and protocol distribution ratios.

---

## 🛠️ Tech Stack

* **Backend Core**: Python, Scapy (raw packet parsing)
* **Web Server**: FastAPI, Uvicorn, WebSockets (live data streaming)
* **Desktop Wrapper**: PyWebView (native standalone app GUI frame)
* **System Metrics**: Psutil (network card discovery)
* **Frontend UI**: HTML5, Vanilla CSS3 (glassmorphic dark design system), Vanilla JavaScript
* **Visualizations**: Chart.js (live line and doughnut plots), Lucide Icons

---

## 📐 Architecture Flow

```mermaid
graph TD
    UserRun[python main.py] -->|Spawns| GUIWindow[Native Desktop Window (PyWebView)]
    UserRun -->|Launches Background| FastAPI[FastAPI Server]
    GUIWindow -->|Renders UI via| WebView[Embedded Web Engine]
    NIC[Network Interface Card] -->|Raw Traffic| Scapy[Scapy Sniffer Thread]
    Scapy -->|Parsed Packets| Analyzer[Threat & Stats Analyzer]
    Analyzer -->|Real-time Data & Alerts| FastAPI
    FastAPI -->|WebSocket Stream| WebView
```

---

## ⚙️ Installation & Setup

### Prerequisites

1. **Python 3.11** or higher.
2. **Npcap (Required for Windows)**:
   * On Windows, Scapy requires Npcap to capture raw socket headers.
   * Download Npcap from the [Official Npcap Website](https://npcap.com/).
   * **Important**: Check the box **"Install Npcap in WinPcap API-compatible Mode"** during the installation process.

### Step-by-Step Installation

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/YOUR_USERNAME/YOUR_REPO_NAME.git
   cd "Packet Sniffer Python Program"
   ```

2. **Install Dependencies**:
   Install all required libraries from the requirements file:
   ```bash
   pip install -r requirements.txt
   ```

---

## 🚀 Running the Application

Because packet sniffing requires binding to low-level network adapter drivers, the application **must be run with Administrative / root privileges**.

### Windows (PowerShell / Command Prompt)
1. Open PowerShell or CMD as **Administrator** (Right-click -> Run as Administrator).
2. Run the main script:
   ```powershell
   python main.py
   ```

### macOS / Linux (Terminal)
1. Open terminal and execute with `sudo`:
   ```bash
   sudo python main.py
   ```

---

## 🛡️ Threat Intelligence (IDS Detections)

The integrated threat detection engine analyzes packets in real-time to identify anomalies:
* **Port Scanning Detection**: Raises a high-severity alert if an IP attempts connections to more than 15 unique destination ports within a rolling 10-second window.
* **SYN Flood Anomaly**: Flags potential DoS attacks if a source IP initiates more than 50 SYN-only packets without corresponding ACKs within a 5-second interval.
* **ARP Spoofing (Cache Poisoning)**: Monitors IP-to-MAC associations. If an IP address changes its MAC mapping mid-session, a critical warning is logged.
* **DNS Anomaly/Tunneling**: Flags domains exceeding 80 characters (exfiltration check) or queries ending with suspicious TLDs (e.g., `.xyz`, `.top`, `.download`).
* **Large Data Transfers**: Detects raw packet payloads exceeding 1400 bytes, flagging potential bulk data exfiltration.

---

## 📂 Project Structure

```
├── backend/
│   ├── sniffer.py       # Scapy sniffer background thread & adapter manager
│   ├── analyzer.py      # Packet protocol parser & IDS threat engine
│   └── server.py        # FastAPI routing, WebSockets & static asset hosting
├── frontend/
│   ├── index.html       # Semantic dashboard HTML layout
│   ├── style.css        # Premium HSL CSS custom variables & animations
│   └── app.js           # Real-time WebSocket consumer & Chart.js logic
├── main.py              # Application entry point (Server + PyWebView desktop wrapper)
├── requirements.txt     # Project Python dependencies
└── README.md            # Repository documentation
```

---

## 📄 License

This project is licensed under the MIT License. See the `LICENSE` file for details.

*Note: This tool is developed for educational and research purposes. Always obtain authorization before capturing network traffic on networks you do not own or manage.*
