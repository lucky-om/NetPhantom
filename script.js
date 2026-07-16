/*
   script.js - Simulated Packet Sniffer Preview and UI Animations
   Author: Lucky | Cybersecurity Project
*/

document.addEventListener("DOMContentLoaded", () => {
    initSimulatedSniffer();
    initMobileNav();
    initFaqAccordion();
    initCliTerminal();
});

function initMobileNav() {
    const toggleBtn = document.querySelector(".mobile-nav-toggle");
    const navMenu = document.querySelector(".nav-menu");
    if (!toggleBtn || !navMenu) return;

    toggleBtn.addEventListener("click", () => {
        navMenu.classList.toggle("active");
        if (navMenu.classList.contains("active")) {
            toggleBtn.innerHTML = "✕";
        } else {
            toggleBtn.innerHTML = "☰";
        }
    });

    // Close menu when clicking outside
    document.addEventListener("click", (e) => {
        if (!navMenu.contains(e.target) && !toggleBtn.contains(e.target) && navMenu.classList.contains("active")) {
            navMenu.classList.remove("active");
            toggleBtn.innerHTML = "☰";
        }
    });
}

function initFaqAccordion() {
    const faqItems = document.querySelectorAll(".faq-item");
    faqItems.forEach(item => {
        const question = item.querySelector(".faq-question");
        if (!question) return;

        question.addEventListener("click", () => {
            // Close other items
            faqItems.forEach(otherItem => {
                if (otherItem !== item) {
                    otherItem.classList.remove("active");
                }
            });
            item.classList.toggle("active");
        });
    });
}

function initCliTerminal() {
    const cliInput = document.getElementById("cli-shell-input");
    const cliFeedback = document.getElementById("cli-feedback");
    if (!cliInput || !cliFeedback) return;

    cliInput.addEventListener("keydown", (e) => {
        if (e.key === "Enter") {
            const val = cliInput.value.trim().toLowerCase();
            cliFeedback.style.display = "block";
            
            if (val === "netphantom") {
                cliFeedback.style.color = "var(--success)";
                cliFeedback.innerHTML = "SYSTEM: Initializing interface hooks...<br>SYSTEM: Launching NetPhantom UI v3.0... Done.";
                
                // Add a cool temporary highlight to the simulator window
                const previewWindow = document.querySelector(".preview-window");
                if (previewWindow) {
                    previewWindow.style.borderColor = "var(--border-active)";
                    setTimeout(() => {
                        previewWindow.style.borderColor = "var(--border-ghost)";
                    }, 1200);
                }
            } else if (val === "help") {
                cliFeedback.style.color = "var(--primary)";
                cliFeedback.innerHTML = "Available commands: 'netphantom' (runs the sniffer), 'help' (lists commands), 'clear'.";
            } else if (val === "clear") {
                cliFeedback.style.display = "none";
                cliFeedback.innerHTML = "";
                cliInput.value = "";
            } else {
                cliFeedback.style.color = "var(--error)";
                cliFeedback.innerHTML = `'${cliInput.value}' is not recognized as an internal or external command.<br>Type 'netphantom' to launch.`;
            }
            cliInput.value = "";
        }
    });
}

function initSimulatedSniffer() {
    const previewContainer = document.querySelector(".window-content");
    if (!previewContainer) return;

    // Create the simulated layout inside .window-content (using style.css classes)
    previewContainer.innerHTML = `
        <div class="sim-toolbar">
            <span style="color:var(--text-dim);">Interface:</span>
            <span style="background:var(--surface); color:var(--text-primary); padding:2px 8px; border-radius:4px; font-weight:bold;">Wi-Fi</span>
            <span style="color:var(--text-dim); margin-left:8px;">Filter:</span>
            <span style="background:var(--surface); color:var(--text-secondary); padding:2px 8px; border-radius:4px; font-family:monospace;">none</span>
            <div style="margin-left:auto; display:flex; gap:8px;">
                <span style="background:var(--text-primary); color:var(--bg-base); font-weight:bold; padding:2px 8px; border-radius:4px;">● CAPTURING</span>
                <span id="sim-counter" style="color:var(--text-primary); font-family:var(--font-mono);">0 packets</span>
            </div>
        </div>
        <div class="sim-main">
            <!-- Left: Packet List Table -->
            <div class="sim-list-container">
                <div class="sim-table-hdr">
                    <div>No.</div>
                    <div>Time</div>
                    <div>Source</div>
                    <div>Destination</div>
                    <div>Protocol</div>
                    <div>Info</div>
                </div>
                <div id="sim-packet-list" class="sim-packet-list">
                    <!-- Rows will be injected here -->
                </div>
            </div>
            <!-- Right: Live Stats & Small Graph -->
            <div class="sim-sidebar">
                <div style="color:var(--text-dim); font-size:0.65rem; font-weight:bold; text-transform:uppercase;">Distribution</div>
                <div style="display:flex; flex-direction:column; gap:6px;">
                    <div>TCP: <span id="sim-stat-tcp" style="color:var(--text-primary); font-weight:bold;">0</span></div>
                    <div>UDP: <span id="sim-stat-udp" style="color:var(--text-secondary); font-weight:bold;">0</span></div>
                    <div>DNS: <span id="sim-stat-dns" style="color:var(--accent); font-weight:bold;">0</span></div>
                    <div>TLS: <span id="sim-stat-tls" style="color:var(--text-dim); font-weight:bold;">0</span></div>
                </div>
                <div style="border-top:1px solid var(--border-ghost); padding-top:8px;">
                    <div style="color:var(--text-dim); font-size:0.65rem; font-weight:bold; text-transform:uppercase; margin-bottom:4px;">Threat Alerts</div>
                    <div id="sim-stat-alerts" style="color:var(--error); font-weight:bold; font-family:var(--font-mono);">No Threats</div>
                </div>
            </div>
        </div>
    `;

    const packetList = document.getElementById("sim-packet-list");
    const counterEl = document.getElementById("sim-counter");
    const statTcp = document.getElementById("sim-stat-tcp");
    const statUdp = document.getElementById("sim-stat-udp");
    const statDns = document.getElementById("sim-stat-dns");
    const statTls = document.getElementById("sim-stat-tls");
    const statAlerts = document.getElementById("sim-stat-alerts");

    let count = 0;
    let tcpCount = 0;
    let udpCount = 0;
    let dnsCount = 0;
    let tlsCount = 0;
    let maxPackets = Math.floor(Math.random() * 6) + 10; // Random cap between 10 and 15

    const templates = [
        { proto: "DNS", src: "192.168.1.15", dst: "8.8.8.8", info: "Standard query 0x1aef A google.com" },
        { proto: "DNS", src: "8.8.8.8", dst: "192.168.1.15", info: "Standard query response 0x1aef A 142.250.190.46" },
        { proto: "TCP", src: "192.168.1.15", dst: "142.250.190.46", info: "49281 → 443 [SYN] Seq=0 Win=64240 Len=0" },
        { proto: "TCP", src: "142.250.190.46", dst: "192.168.1.15", info: "443 → 49281 [SYN, ACK] Seq=0 Ack=1 Win=64240 Len=0" },
        { proto: "TCP", src: "192.168.1.15", dst: "142.250.190.46", info: "49281 → 443 [ACK] Seq=1 Ack=1 Win=64240 Len=0" },
        { proto: "TLS", src: "192.168.1.15", dst: "142.250.190.46", info: "Client Hello [SNI: google.com]" },
        { proto: "TLS", src: "142.250.190.46", dst: "192.168.1.15", info: "Server Hello, Certificate, Server Key Exchange" },
        { proto: "HTTPS", src: "192.168.1.15", dst: "142.250.190.46", info: "Application Data (Encrypted)" },
        { proto: "UDP", src: "192.168.1.15", dst: "192.168.1.255", info: "Discovery Broadcast (SSDP)" }
    ];

    function addSimulatedRow() {
        if (count >= maxPackets) {
            // Buffer Reset & Auto-Restart Loop
            packetList.innerHTML = `<div style="color:var(--text-dim); padding:16px; font-family:var(--font-mono); font-size:0.75rem;">SYSTEM: Clearing cache buffers... Restarting adapter listener...</div>`;
            count = 0;
            tcpCount = 0;
            udpCount = 0;
            dnsCount = 0;
            tlsCount = 0;
            statTcp.innerText = 0;
            statUdp.innerText = 0;
            statDns.innerText = 0;
            statTls.innerText = 0;
            statAlerts.innerText = "No Threats";
            counterEl.innerText = "0 packets";
            
            maxPackets = Math.floor(Math.random() * 6) + 10; // Get next limit (10 to 15)
            setTimeout(addSimulatedRow, 1400);
            return;
        }

        count++;
        const item = templates[Math.floor(Math.random() * templates.length)];
        
        // Update counters
        if (item.proto === "TCP" || item.proto === "HTTPS") {
            tcpCount++;
            statTcp.innerText = tcpCount;
        } else if (item.proto === "UDP") {
            udpCount++;
            statUdp.innerText = udpCount;
        } else if (item.proto === "DNS") {
            dnsCount++;
            statDns.innerText = dnsCount;
        } else if (item.proto === "TLS") {
            tlsCount++;
            statTls.innerText = tlsCount;
        }

        counterEl.innerText = `${count} packets`;

        const timeStr = new Date().toLocaleTimeString();
        const row = document.createElement("div");

        // Check for simulated port scan threat
        if (count > 0 && count % 7 === 0) {
            statAlerts.innerHTML = `<span style="color:var(--error);">⚠ PORT SCAN</span><br><span style="color:var(--text-dim); font-size:0.6rem;">192.168.1.200 -> .15</span>`;
            
            row.className = "sim-table-row threat";
            row.innerHTML = `
                <div>${count}</div>
                <div>${timeStr}</div>
                <div>192.168.1.200</div>
                <div>192.168.1.15</div>
                <div>TCP</div>
                <div style="font-weight:bold;">⚠ Port Scan Probe: Port ${Math.floor(Math.random()*8000+80)}</div>
            `;
        } else {
            row.className = `sim-table-row ${item.proto.toLowerCase()}`;
            row.innerHTML = `
                <div>${count}</div>
                <div>${timeStr}</div>
                <div>${item.src}</div>
                <div>${item.dst}</div>
                <div>${item.proto}</div>
                <div>${item.info}</div>
            `;
        }

        packetList.appendChild(row);

        // Auto Scroll to bottom
        packetList.scrollTop = packetList.scrollHeight;

        // Randomize next interval
        setTimeout(addSimulatedRow, Math.random() * 400 + 200);
    }

    // Start simulation
    addSimulatedRow();
}
