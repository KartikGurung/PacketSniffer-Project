// ==========================================================================
// APEX SNIFFER CLIENT APPLICATION LOGIC
// ==========================================================================

document.addEventListener("DOMContentLoaded", () => {
    // Initialize Lucide Icons
    lucide.createIcons();

    // DOM Elements References
    const interfaceSelect = document.getElementById("interface-select");
    const filterInput = document.getElementById("filter-input");
    const startBtn = document.getElementById("start-btn");
    const stopBtn = document.getElementById("stop-btn");
    const clearBtn = document.getElementById("clear-btn");
    const downloadBtn = document.getElementById("download-btn");
    const connectionBadge = document.getElementById("connection-badge");
    const connectionBadgeDot = connectionBadge.querySelector(".badge-dot");
    const connectionBadgeText = connectionBadge.querySelector(".badge-text");

    // Metrics Cards
    const ppsVal = document.getElementById("stat-pps");
    const totalPacketsVal = document.getElementById("stat-total-packets");
    const bandwidthVal = document.getElementById("stat-bandwidth");
    const alertsVal = document.getElementById("stat-alerts");
    const threatsBadge = document.getElementById("threats-badge");
    const threatsCard = document.getElementById("threats-card");

    // Table & List Streams
    const packetList = document.getElementById("packet-list");
    const packetTableWrapper = document.querySelector(".packet-table-wrapper");
    const searchInput = document.getElementById("search-input");
    const autoscrollCheck = document.getElementById("autoscroll-check");
    const threatList = document.getElementById("threat-list");

    // Packet Inspector Drawer
    const inspectorDrawer = document.getElementById("inspector-drawer");
    const drawerCloseBtn = document.getElementById("drawer-close-btn");
    const inspectorPacketBadge = document.getElementById("inspector-packet-badge");
    const decodedLayersTree = document.getElementById("decoded-layers-tree");
    const hexDumpOutput = document.getElementById("hex-dump-output");
    const tabBtns = document.querySelectorAll(".tab-btn");
    const tabPanes = document.querySelectorAll(".tab-pane");

    // State Management
    let ws = null;
    let interfaces = [];
    let isCapturing = false;
    let packetHistory = []; // Buffered packets (limit to 1000 for performance)
    const MAX_PACKETS = 1000;
    let selectedPacketId = null;
    let searchQuery = "";
    
    // Throughput Chart Data History (20 data points)
    let throughputHistory = Array(20).fill(0);
    let throughputLabels = Array(20).fill("");

    // ==========================================
    // CHART INITIALIZATION
    // ==========================================
    
    // Throughput Chart (Line Chart with smooth gradient fill)
    const ctxBandwidth = document.getElementById("bandwidth-chart").getContext("2d");
    const gradient = ctxBandwidth.createLinearGradient(0, 0, 0, 150);
    gradient.addColorStop(0, 'rgba(59, 130, 246, 0.4)');
    gradient.addColorStop(1, 'rgba(59, 130, 246, 0.0)');

    const bandwidthChart = new Chart(ctxBandwidth, {
        type: 'line',
        data: {
            labels: throughputLabels,
            datasets: [{
                label: 'Throughput',
                data: throughputHistory,
                borderColor: '#3b82f6',
                borderWidth: 2,
                backgroundColor: gradient,
                fill: true,
                tension: 0.4,
                pointRadius: 0,
                pointHoverRadius: 4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false },
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            return ` ${formatBytes(context.parsed.y)}/s`;
                        }
                    }
                }
            },
            scales: {
                x: { display: false, grid: { display: false } },
                y: {
                    grid: { color: 'rgba(255, 255, 255, 0.05)' },
                    ticks: {
                        color: '#94a3b8',
                        font: { size: 9 },
                        callback: function(value) {
                            return formatBytes(value);
                        }
                    }
                }
            }
        }
    });

    // Protocol Distribution Chart (Doughnut Chart)
    const ctxProtocol = document.getElementById("protocol-chart").getContext("2d");
    const protocolChart = new Chart(ctxProtocol, {
        type: 'doughnut',
        data: {
            labels: ['TCP', 'UDP', 'ICMP', 'DNS', 'ARP', 'Other'],
            datasets: [{
                data: [0, 0, 0, 0, 0, 0],
                backgroundColor: [
                    '#3b82f6', // TCP - Blue
                    '#8b5cf6', // UDP - Violet
                    '#f59e0b', // ICMP - Amber
                    '#10b981', // DNS - Emerald
                    '#06b6d4', // ARP - Cyan
                    '#64748b'  // Other - Slate
                ],
                borderWidth: 1,
                borderColor: '#0f172a'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'right',
                    labels: {
                        color: '#94a3b8',
                        boxWidth: 12,
                        font: { size: 10, family: 'Inter' }
                    }
                }
            },
            cutout: '65%'
        }
    });

    // ==========================================
    // UTILITY FUNCTIONS
    // ==========================================

    function formatBytes(bytes, decimals = 2) {
        if (bytes <= 0) return '0 B';
        const k = 1024;
        const dm = decimals < 0 ? 0 : decimals;
        const sizes = ['B', 'KB', 'MB', 'GB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        if (i < 0) return bytes.toFixed(dm) + ' B';
        return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
    }

    function getProtocolTagClass(proto) {
        switch(proto.toUpperCase()) {
            case 'TCP': return 'tag-tcp';
            case 'UDP': return 'tag-udp';
            case 'ICMP': return 'tag-icmp';
            case 'DNS': return 'tag-dns';
            case 'ARP': return 'tag-arp';
            case 'HTTP': return 'tag-http';
            default: return 'tag-other';
        }
    }

    // Wireshark-style HEX and ASCII Dump formatter
    function generateHexDump(base64Payload) {
        if (!base64Payload) return "No payload bytes associated with this packet.";
        
        try {
            // Decode base64 to byte array
            const binaryStr = atob(base64Payload);
            const len = binaryStr.length;
            const bytes = new Uint8Array(len);
            for (let i = 0; i < len; i++) {
                bytes[i] = binaryStr.charCodeAt(i);
            }
            
            let dump = "";
            for (let offset = 0; offset < bytes.length; offset += 16) {
                // Offset block (e.g. 0000)
                let offsetStr = offset.toString(16).padStart(4, '0');
                
                let hexPart = "";
                let asciiPart = "";
                
                for (let i = 0; i < 16; i++) {
                    if (offset + i < bytes.length) {
                        const byte = bytes[offset + i];
                        hexPart += byte.toString(16).padStart(2, '0') + " ";
                        
                        // Extra space at byte index 8 (Wireshark spacing)
                        if (i === 7) hexPart += " ";
                        
                        // Printable ASCII character filter
                        if (byte >= 32 && byte <= 126) {
                            asciiPart += String.fromCharCode(byte);
                        } else {
                            asciiPart += ".";
                        }
                    } else {
                        // Empty space padding for uneven lines
                        hexPart += "   ";
                        if (i === 7) hexPart += " ";
                    }
                }
                
                dump += `${offsetStr}  ${hexPart.padEnd(49)}  |${asciiPart}|\n`;
            }
            return dump;
        } catch (e) {
            console.error("Hex dump error:", e);
            return "Failed to parse payload hex dump.";
        }
    }

    // Toast Notification System
    function showToast(message, type = "error") {
        const container = document.getElementById("toast-container") || createToastContainer();
        const toast = document.createElement("div");
        toast.className = `toast toast-${type}`;
        toast.style.background = type === "error" ? "rgba(239, 68, 68, 0.9)" : "rgba(16, 185, 129, 0.9)";
        toast.style.color = "#ffffff";
        toast.style.padding = "0.75rem 1.25rem";
        toast.style.borderRadius = "8px";
        toast.style.fontSize = "0.8rem";
        toast.style.fontWeight = "600";
        toast.style.boxShadow = "0 10px 25px rgba(0, 0, 0, 0.4)";
        toast.style.backdropFilter = "blur(8px)";
        toast.style.border = type === "error" ? "1px solid rgba(239, 68, 68, 0.4)" : "1px solid rgba(16, 185, 129, 0.4)";
        toast.style.display = "flex";
        toast.style.alignItems = "center";
        toast.style.gap = "0.5rem";
        toast.style.transition = "all 0.3s ease";
        
        const iconName = type === "error" ? "alert-circle" : "check-circle";
        toast.innerHTML = `<i data-lucide="${iconName}" style="width: 16px; height: 16px;"></i> <span>${message}</span>`;
        
        container.appendChild(toast);
        lucide.createIcons();
        
        setTimeout(() => {
            toast.style.opacity = "0";
            toast.style.transform = "translateY(10px)";
            setTimeout(() => toast.remove(), 300);
        }, 4000);
    }
    
    function createToastContainer() {
        const c = document.createElement("div");
        c.id = "toast-container";
        c.style.position = "fixed";
        c.style.bottom = "20px";
        c.style.right = "20px";
        c.style.zIndex = "9999";
        c.style.display = "flex";
        c.style.flexDirection = "column";
        c.style.gap = "10px";
        document.body.appendChild(c);
        return c;
    }

    // ==========================================
    // UI RENDERING FUNCTIONS
    // ==========================================

    // Fetch and populate network interfaces list
    async function fetchInterfaces() {
        try {
            const res = await fetch("/api/interfaces");
            if (!res.ok) throw new Error("API error fetching interfaces.");
            interfaces = await res.ok ? await res.json() : [];
            
            interfaceSelect.innerHTML = "";
            if (interfaces.length === 0) {
                interfaceSelect.innerHTML = '<option value="">No adapters found (Run as Admin)</option>';
                return;
            }
            
            interfaces.forEach(iface => {
                const opt = document.createElement("option");
                opt.value = iface.id;
                // e.g. Wi-Fi (192.168.1.12)
                opt.textContent = `${iface.name} - [${iface.ip}]`;
                interfaceSelect.appendChild(opt);
            });
        } catch (err) {
            console.error(err);
            interfaceSelect.innerHTML = '<option value="">Failed to query adapters</option>';
        }
    }

    // Render Layer-by-layer decoded details in inspector
    function renderDecodedLayers(layers) {
        decodedLayersTree.innerHTML = "";
        
        if (!layers || Object.keys(layers).length === 0) {
            decodedLayersTree.innerHTML = '<div class="empty-message"><p>No structured header fields parsed.</p></div>';
            return;
        }
        
        for (const [layerName, fields] of Object.entries(layers)) {
            const block = document.createElement("div");
            block.className = "layer-block";
            
            const title = document.createElement("div");
            title.className = "layer-title";
            title.textContent = layerName;
            block.appendChild(title);
            
            const fieldsContainer = document.createElement("div");
            fieldsContainer.className = "layer-fields";
            
            for (const [fieldName, fieldVal] of Object.entries(fields)) {
                if (fieldName === "Queries") {
                    // Special case for list query fields (DNS)
                    fieldVal.forEach((q, idx) => {
                        const row = document.createElement("div");
                        row.className = "field-row";
                        row.innerHTML = `<span class="field-name">Query #${idx+1}</span><span class="field-val">${q}</span>`;
                        fieldsContainer.appendChild(row);
                    });
                } else {
                    const row = document.createElement("div");
                    row.className = "field-row";
                    row.innerHTML = `<span class="field-name">${fieldName}</span><span class="field-val">${fieldVal}</span>`;
                    fieldsContainer.appendChild(row);
                }
            }
            
            block.appendChild(fieldsContainer);
            decodedLayersTree.appendChild(block);
        }
    }

    // Open/Inspect packet in drawer
    function inspectPacket(packet) {
        selectedPacketId = packet.id;
        inspectorPacketBadge.textContent = `Packet #${packet.id}`;
        inspectorPacketBadge.className = `proto-tag ${getProtocolTagClass(packet.protocol)}`;
        
        // Render layers tree
        renderDecodedLayers(packet.layers);
        
        // Render hex payload
        hexDumpOutput.textContent = generateHexDump(packet.payload);
        
        // Highlight active row in table
        document.querySelectorAll("#packet-list tr").forEach(row => {
            row.classList.remove("active-row");
            if (parseInt(row.getAttribute("data-id")) === packet.id) {
                row.classList.add("active-row");
            }
        });
        
        // Open drawer
        inspectorDrawer.classList.add("open");
        
        // Refresh icons
        lucide.createIcons();
    }

    // Add packet row to DOM table
    function appendPacketRow(pkt) {
        // Remove empty state row if present
        const emptyRow = packetList.querySelector(".empty-state");
        if (emptyRow) emptyRow.remove();
        
        // Create table row
        const tr = document.createElement("tr");
        tr.setAttribute("data-id", pkt.id);
        
        // Match searching
        if (searchQuery) {
            const query = searchQuery.toLowerCase();
            const matches = pkt.protocol.toLowerCase().includes(query) ||
                            pkt.source.toLowerCase().includes(query) ||
                            pkt.destination.toLowerCase().includes(query) ||
                            pkt.info.toLowerCase().includes(query);
            if (!matches) {
                tr.style.display = "none";
            }
        }
        
        // Format Timestamp (Relative or absolute)
        const date = new Date(pkt.timestamp * 1000);
        const timeStr = date.toTimeString().split(" ")[0] + "." + String(date.getMilliseconds()).padStart(3, '0');
        
        tr.innerHTML = `
            <td>${pkt.id}</td>
            <td style="color: var(--text-secondary)">${timeStr}</td>
            <td class="text-truncate" title="${pkt.source}">${pkt.source}</td>
            <td class="text-truncate" title="${pkt.destination}">${pkt.destination}</td>
            <td><span class="proto-tag ${getProtocolTagClass(pkt.protocol)}">${pkt.protocol}</span></td>
            <td>${pkt.length}</td>
            <td class="text-truncate" title="${pkt.info}">${pkt.info}</td>
        `;
        
        // Highlight if this is the currently selected packet in drawer
        if (selectedPacketId === pkt.id) {
            tr.className = "active-row";
        }
        
        tr.addEventListener("click", () => inspectPacket(pkt));
        packetList.appendChild(tr);
        
        // Clean table DOM list if exceeds max elements
        if (packetList.children.length > MAX_PACKETS) {
            packetList.removeChild(packetList.firstChild);
        }
        
        // Perform auto scroll to bottom
        if (autoscrollCheck.checked) {
            packetTableWrapper.scrollTop = packetTableWrapper.scrollHeight;
        }
    }

    // Render threat logs
    function renderThreatAlerts(alerts) {
        if (!alerts || alerts.length === 0) {
            threatList.innerHTML = `
                <div class="empty-alerts">
                    <i data-lucide="shield-check"></i>
                    <p>No network anomalies detected. System secure.</p>
                </div>
            `;
            alertsVal.textContent = "0";
            threatsBadge.textContent = "0 Alerts";
            threatsCard.classList.remove("active");
            lucide.createIcons();
            return;
        }
        
        threatList.innerHTML = "";
        alertsVal.textContent = alerts.length;
        threatsBadge.textContent = `${alerts.length} Alert${alerts.length > 1 ? 's' : ''}`;
        threatsCard.classList.add("active");
        
        // Reverse array to show newest alerts first
        const reversedAlerts = [...alerts].reverse();
        
        reversedAlerts.forEach(alert => {
            const item = document.createElement("div");
            
            // Map severity to CSS class
            let severityClass = "threat-warning";
            let severityIcon = "info";
            if (alert.severity.toLowerCase() === "critical") {
                severityClass = "threat-critical";
                severityIcon = "alert-octagon";
            } else if (alert.severity.toLowerCase() === "high") {
                severityClass = "threat-high";
                severityIcon = "alert-triangle";
            } else if (alert.severity.toLowerCase() === "warning") {
                severityClass = "threat-warning";
                severityIcon = "shield-alert";
            } else {
                severityClass = "threat-info";
                severityIcon = "info";
            }
            
            item.className = `threat-item ${severityClass}`;
            
            const timeDate = new Date(alert.timestamp * 1000);
            const timeStr = timeDate.toTimeString().split(" ")[0];
            
            item.innerHTML = `
                <div class="threat-item-icon">
                    <i data-lucide="${severityIcon}"></i>
                </div>
                <div class="threat-details">
                    <div class="threat-meta">
                        <span class="threat-category">${alert.category}</span>
                        <span class="threat-time">${timeStr}</span>
                    </div>
                    <span class="threat-msg">${alert.message}</span>
                </div>
            `;
            
            threatList.appendChild(item);
        });
        
        // Refresh icons
        lucide.createIcons();
    }

    // ==========================================
    // WEBSOCKET LOGIC
    // ==========================================

    function connectWebSocket() {
        const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
        const wsUrl = `${protocol}//${window.location.host}/ws`;
        
        console.log(`Connecting to WebSocket: ${wsUrl}`);
        ws = new WebSocket(wsUrl);
        
        ws.onopen = () => {
            console.log("WebSocket connected.");
            connectionBadge.className = "badge badge-connected";
            connectionBadgeText.textContent = "Live";
        };
        
        ws.onmessage = (event) => {
            const msg = JSON.parse(event.data);
            
            if (msg.type === "packets") {
                // Batch packet array ingestion
                msg.data.forEach(pkt => {
                    packetHistory.push(pkt);
                    if (packetHistory.length > MAX_PACKETS) {
                        packetHistory.shift();
                    }
                    appendPacketRow(pkt);
                });
            } else if (msg.type === "stats") {
                // Update numerical values in cards
                ppsVal.textContent = msg.data.packets_sec.toFixed(1);
                totalPacketsVal.textContent = msg.data.total_packets.toLocaleString();
                bandwidthVal.textContent = `${formatBytes(msg.data.bytes_sec)}/s`;
                
                // Push throughput metrics value to line chart
                throughputHistory.push(msg.data.bytes_sec);
                throughputHistory.shift();
                bandwidthChart.update("none"); // Update chart smoothly without redraw animation lag
                
                // Update protocol distribution chart
                const pCounts = msg.data.protocol_counts;
                protocolChart.data.datasets[0].data = [
                    pCounts.TCP || 0,
                    pCounts.UDP || 0,
                    pCounts.ICMP || 0,
                    pCounts.DNS || 0,
                    pCounts.ARP || 0,
                    pCounts.Other || 0
                ];
                protocolChart.update("none");
            } else if (msg.type === "alerts") {
                renderThreatAlerts(msg.data);
            }
        };
        
        ws.onclose = () => {
            console.log("WebSocket closed. Reconnecting in 3 seconds...");
            connectionBadge.className = "badge badge-disconnected";
            connectionBadgeText.textContent = "Offline";
            setTimeout(connectWebSocket, 3000);
        };
        
        ws.onerror = (err) => {
            console.error("WebSocket error observed:", err);
            ws.close();
        };
    }

    // ==========================================
    // REST CONTROL HANDLERS
    // ==========================================

    async function startCapture() {
        const interfaceId = interfaceSelect.value;
        if (!interfaceId) {
            showToast("No active network adapter selected. Please run the sniffer as Administrator to list interfaces.", "error");
            return;
        }
        
        const filterStr = filterInput.value;
        
        try {
            const res = await fetch("/api/start", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    interface_id: interfaceId,
                    filter_str: filterStr
                })
            });
            
            if (res.ok) {
                isCapturing = true;
                startBtn.disabled = true;
                stopBtn.disabled = false;
                interfaceSelect.disabled = true;
                filterInput.disabled = true;
                
                // Clean browser display state
                packetList.innerHTML = "";
                packetHistory = [];
                
                // Reset rolling charts
                throughputHistory = Array(20).fill(0);
                bandwidthChart.data.datasets[0].data = throughputHistory;
                bandwidthChart.update();
            } else {
                const data = await res.json();
                showToast(`Start error: ${data.detail || "Unknown error occurred."}`, "error");
            }
        } catch (e) {
            console.error("Start request failed:", e);
            showToast("Failed to contact the backend service. Ensure FastAPI server is running.", "error");
        }
    }

    async function stopCapture() {
        try {
            const res = await fetch("/api/stop", { method: "POST" });
            if (res.ok) {
                isCapturing = false;
                startBtn.disabled = false;
                stopBtn.disabled = true;
                interfaceSelect.disabled = false;
                filterInput.disabled = false;
            } else {
                showToast("Failed to stop sniff capture.", "error");
            }
        } catch (e) {
            console.error("Stop request failed:", e);
        }
    }

    async function clearLogs() {
        try {
            const res = await fetch("/api/clear", { method: "POST" });
            if (res.ok) {
                // Flush memory structures
                packetHistory = [];
                packetList.innerHTML = `
                    <tr class="empty-state">
                        <td colspan="7">
                            <div class="empty-message">
                                <i data-lucide="radar"></i>
                                <p>No packets captured yet. Choose an interface and click Start Capture.</p>
                            </div>
                        </td>
                    </tr>
                `;
                selectedPacketId = null;
                inspectorDrawer.classList.remove("open");
                
                // Clear alerts
                renderThreatAlerts([]);
                
                // Reset card values
                ppsVal.textContent = "0.0";
                totalPacketsVal.textContent = "0";
                bandwidthVal.textContent = "0 B/s";
                
                // Reset rolling charts
                throughputHistory = Array(20).fill(0);
                bandwidthChart.data.datasets[0].data = throughputHistory;
                bandwidthChart.update();
                
                protocolChart.data.datasets[0].data = [0,0,0,0,0,0];
                protocolChart.update();
                
                lucide.createIcons();
            }
        } catch (e) {
            console.error(e);
        }
    }

    function downloadPcap() {
        // Redirect browser to PCAP API endpoint to trigger attachment download
        window.location.href = "/api/download-pcap";
    }

    // ==========================================
    // SEARCH FILTER LOGIC
    // ==========================================

    searchInput.addEventListener("input", (e) => {
        searchQuery = e.target.value;
        const query = searchQuery.toLowerCase();
        
        const rows = packetList.querySelectorAll("tr");
        if (rows.length === 1 && rows[0].classList.contains("empty-state")) return;
        
        rows.forEach(row => {
            const id = parseInt(row.getAttribute("data-id"));
            const pkt = packetHistory.find(p => p.id === id);
            
            if (pkt) {
                const matches = pkt.protocol.toLowerCase().includes(query) ||
                                pkt.source.toLowerCase().includes(query) ||
                                pkt.destination.toLowerCase().includes(query) ||
                                pkt.info.toLowerCase().includes(query);
                if (matches) {
                    row.style.display = "";
                } else {
                    row.style.display = "none";
                }
            }
        });
    });

    // ==========================================
    // INSPECTOR DRAWER TABS & LIFECYCLE
    // ==========================================

    // Close drawer listener
    drawerCloseBtn.addEventListener("click", () => {
        inspectorDrawer.classList.remove("open");
        document.querySelectorAll("#packet-list tr").forEach(row => {
            row.classList.remove("active-row");
        });
        selectedPacketId = null;
    });

    // Handle tab selection inside inspector
    tabBtns.forEach(btn => {
        btn.addEventListener("click", () => {
            tabBtns.forEach(b => b.classList.remove("active"));
            tabPanes.forEach(p => p.classList.remove("active"));
            
            btn.classList.add("active");
            const tabId = btn.getAttribute("data-tab");
            document.getElementById(tabId).classList.add("active");
        });
    });

    // ==========================================
    // APPLICATION INITIALIZATION
    // ==========================================
    
    // Bind listeners
    startBtn.addEventListener("click", startCapture);
    stopBtn.addEventListener("click", stopCapture);
    clearBtn.addEventListener("click", clearLogs);
    downloadBtn.addEventListener("click", downloadPcap);
    
    // Load adapters and open connection
    fetchInterfaces();
    connectWebSocket();
});
