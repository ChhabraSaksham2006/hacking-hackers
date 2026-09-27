"""
Live Ingress Gateway & Interactive Device Portal
Enables external devices (smartphones, laptops, judges) on any network interface
(Wi-Fi, Mobile Hotspot, Localhost, or Public Tunnel) to connect directly to the
Edge Sensor Agent via real socket/HTTP connections.

Features:
- Real-time HTML5 Canvas Prediction Graph on the device dashboard
- Live MITRE ATT&CK stage tracking & threat level alert banner
- Multi-interface network discovery (Wi-Fi, Hotspot, Localhost)
- Structured live packet logging to disk (live_ingress.log)
- Zero third-party dependencies: standard library socket and http.server only.
"""

import json
import os
import queue
import socket
import sys
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Dict, List, Optional, Tuple

try:
    from .packet_ingress import RawPacket
except (ImportError, ValueError):
    from core.packet_ingress import RawPacket


def get_lan_ip() -> str:
    """Detects the primary local LAN IP address of the host machine."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        try:
            ip = socket.gethostbyname(socket.gethostname())
        except Exception:
            ip = "127.0.0.1"
    finally:
        s.close()
    return ip


def get_all_host_ips() -> List[Tuple[str, str]]:
    """Returns all active IPv4 addresses for Wi-Fi, Hotspots, and LAN."""
    ips: List[Tuple[str, str]] = []
    primary = get_lan_ip()
    if primary != "127.0.0.1":
        ips.append(("Wi-Fi / Primary LAN", primary))

    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None, socket.AF_INET):
            addr = info[4][0]
            if addr and not addr.startswith("127.") and not any(addr == x[1] for x in ips):
                if addr.startswith("192.168.137."):
                    label = "Windows Mobile Hotspot"
                elif addr.startswith("172.") or addr.startswith("10."):
                    label = "Hotspot / Subnet"
                else:
                    label = "Secondary Network"
                ips.append((label, addr))
    except Exception:
        pass

    ips.append(("Localhost (Same PC)", "127.0.0.1"))
    return ips


def get_device_summary(user_agent: str) -> str:
    """Identifies the device OS/type from User-Agent string."""
    ua = user_agent.lower()
    if "iphone" in ua:
        return "Apple iPhone (iOS)"
    elif "ipad" in ua:
        return "Apple iPad (iPadOS)"
    elif "android" in ua:
        return "Android Smartphone"
    elif "windows" in ua:
        return "Windows PC"
    elif "macintosh" in ua or "mac os" in ua:
        return "Apple Mac (macOS)"
    elif "linux" in ua:
        return "Linux Device"
    return "Generic Client Device"


# Embedded responsive Mobile & Desktop Cyber Portal with Live Prediction Graph
PORTAL_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
<title>Flow Drishti Edge Sensor â€” Live Telemetry & Threat Dashboard</title>
<style>
  :root {
    --bg-dark: #070b14;
    --card-bg: #0f172a;
    --card-border: #1e293b;
    --accent-cyan: #06b6d4;
    --accent-green: #10b981;
    --accent-red: #ef4444;
    --accent-yellow: #f59e0b;
    --accent-purple: #8b5cf6;
    --text-main: #f8fafc;
    --text-muted: #94a3b8;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    background-color: var(--bg-dark);
    color: var(--text-main);
    padding: 16px;
    max-width: 640px;
    margin: 0 auto;
    line-height: 1.4;
  }
  .header {
    text-align: center;
    padding: 8px 0 16px 0;
    border-bottom: 1px solid var(--card-border);
    margin-bottom: 14px;
  }
  .badge {
    display: inline-block;
    font-size: 11px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.08em;
    padding: 4px 10px;
    border-radius: 9999px;
    background: rgba(6, 182, 212, 0.15);
    color: var(--accent-cyan);
    border: 1px solid rgba(6, 182, 212, 0.3);
    margin-bottom: 6px;
  }
  h1 { font-size: 19px; font-weight: 700; letter-spacing: -0.02em; }
  .subtitle { font-size: 12px; color: var(--text-muted); margin-top: 2px; }
  .card {
    background: var(--card-bg);
    border: 1px solid var(--card-border);
    border-radius: 12px;
    padding: 14px;
    margin-bottom: 14px;
  }
  .card-title {
    font-size: 12px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.06em;
    color: var(--text-muted);
    margin-bottom: 10px;
    display: flex;
    align-items: center;
    justify-content: space-between;
  }
  
  /* Live Threat Status Banner */
  .threat-banner {
    padding: 12px 14px;
    border-radius: 10px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    font-weight: 700;
    font-size: 14px;
    margin-bottom: 12px;
    transition: all 0.3s ease;
  }
  .threat-normal {
    background: rgba(16, 185, 129, 0.15);
    border: 1px solid rgba(16, 185, 129, 0.4);
    color: #34d399;
  }
  .threat-watch {
    background: rgba(245, 158, 11, 0.18);
    border: 1px solid rgba(245, 158, 11, 0.4);
    color: #fbbf24;
  }
  .threat-critical {
    background: rgba(239, 68, 68, 0.22);
    border: 1px solid rgba(239, 68, 68, 0.5);
    color: #f87171;
    animation: pulse-red 1.5s infinite;
  }
  @keyframes pulse-red {
    0% { box-shadow: 0 0 0 0 rgba(239, 68, 68, 0.4); }
    70% { box-shadow: 0 0 0 10px rgba(239, 68, 68, 0); }
    100% { box-shadow: 0 0 0 0 rgba(239, 68, 68, 0); }
  }

  /* Metric Tiles */
  .stat-grid {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 8px;
    margin-bottom: 12px;
  }
  .stat-tile {
    background: rgba(15, 23, 42, 0.6);
    border: 1px solid var(--card-border);
    border-radius: 8px;
    padding: 8px;
    text-align: center;
  }
  .stat-label { font-size: 10px; text-transform: uppercase; color: var(--text-muted); }
  .stat-value { font-size: 15px; font-weight: 700; font-family: ui-monospace, Menlo, monospace; color: var(--accent-cyan); margin-top: 2px; }

  /* Canvas Graph */
  .chart-container {
    position: relative;
    width: 100%;
    height: 150px;
    background: #030712;
    border: 1px solid var(--card-border);
    border-radius: 8px;
    overflow: hidden;
  }
  canvas {
    width: 100%;
    height: 100%;
    display: block;
  }

  .meta-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 8px;
    font-size: 12px;
  }
  .meta-label { color: var(--text-muted); font-size: 10px; text-transform: uppercase; }
  .meta-val { font-weight: 600; font-family: ui-monospace, Menlo, monospace; color: var(--accent-cyan); }
  
  .btn-grid {
    display: flex;
    flex-direction: column;
    gap: 8px;
  }
  button {
    width: 100%;
    padding: 12px 14px;
    font-size: 14px;
    font-weight: 600;
    border-radius: 9px;
    border: none;
    cursor: pointer;
    display: flex;
    align-items: center;
    justify-content: space-between;
    transition: all 0.15s ease;
    color: #ffffff;
  }
  button:active { transform: scale(0.98); opacity: 0.9; }
  .btn-green { background: #059669; }
  .btn-yellow { background: #d97706; }
  .btn-red { background: #dc2626; }
  .btn-purple { background: #7c3aed; }
  .btn-sub { font-size: 11px; opacity: 0.85; font-weight: 400; }
  .input-group {
    display: flex;
    gap: 8px;
    margin-top: 8px;
  }
  input[type="text"] {
    flex: 1;
    background: #030712;
    border: 1px solid var(--card-border);
    color: #fff;
    padding: 10px 12px;
    border-radius: 8px;
    font-size: 13px;
    outline: none;
  }
  input[type="text"]:focus { border-color: var(--accent-cyan); }
  .btn-send {
    width: auto;
    padding: 0 16px;
    background: var(--accent-cyan);
    color: #030712;
  }
  .console {
    background: #030712;
    border: 1px solid #111827;
    border-radius: 8px;
    padding: 10px;
    font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
    font-size: 11px;
    min-height: 90px;
    max-height: 140px;
    overflow-y: auto;
    color: #10b981;
    white-space: pre-wrap;
  }
  .log-entry { margin-bottom: 3px; }
  .log-ts { color: var(--text-muted); }
  .log-err { color: var(--accent-red); }
</style>
</head>
<body>
  <div class="header">
    <div class="badge">Flow Drishti Edge Sensor Active</div>
    <h1>Live Cyber Threat Monitor</h1>
    <div class="subtitle">Hardware Edge Telemetry & Real-Time Attack Forecasting</div>
  </div>

  <!-- Real-time Threat Status & Live Canvas Graph -->
  <div class="card">
    <div class="threat-banner threat-normal" id="threat-banner">
      <span id="threat-text">â— NORMAL BASELINE OPERATIONS</span>
      <span id="threat-prob" style="font-family: ui-monospace, Menlo, monospace;">8% Risk</span>
    </div>

    <!-- 4 Key Telemetry Metrics -->
    <div class="stat-grid">
      <div class="stat-tile">
        <div class="stat-label">Infiltration</div>
        <div class="stat-value" id="val-prob">8%</div>
      </div>
      <div class="stat-tile">
        <div class="stat-label">Port Entropy</div>
        <div class="stat-value" id="val-entropy">1.24b</div>
      </div>
      <div class="stat-tile">
        <div class="stat-label">Auth (445/22)</div>
        <div class="stat-value" id="val-auth">2.1%</div>
      </div>
      <div class="stat-tile">
        <div class="stat-label">Byte Rate</div>
        <div class="stat-value" id="val-bytes">0.8 KB/s</div>
      </div>
    </div>

    <!-- Live Prediction Graph -->
    <div class="card-title">
      <span>Attack Probability Timeline (Last 30s)</span>
      <span style="font-size: 10px; color: var(--accent-cyan);">Live 1Hz Stream</span>
    </div>
    <div class="chart-container">
      <canvas id="predictionChart"></canvas>
    </div>
  </div>

  <!-- Device Identity Card -->
  <div class="card">
    <div class="card-title">Connected Device Ingress</div>
    <div class="meta-grid">
      <div>
        <div class="meta-label">Your Client IP</div>
        <div class="meta-val" id="client-ip">Detecting...</div>
      </div>
      <div>
        <div class="meta-label">Sensor Host</div>
        <div class="meta-val" id="sensor-host">__SENSOR_IP__:8888</div>
      </div>
      <div style="grid-column: span 2;">
        <div class="meta-label">Detected Device Platform</div>
        <div class="meta-val" style="color: #fff; font-size: 12px;" id="client-ua">Loading...</div>
      </div>
    </div>
  </div>

  <!-- Live Ingress Action Controls -->
  <div class="card">
    <div class="card-title">Interactive Attack Demonstrator</div>
    <div class="btn-grid">
      <button class="btn-green" onclick="sendAction('normal')">
        <span>ðŸŸ¢ Send Normal HTTP Traffic</span>
        <span class="btn-sub">HTTP 200 Keepalive</span>
      </button>

      <button class="btn-yellow" onclick="sendAction('recon')">
        <span>ðŸŸ¡ Simulate Recon / Port Sweep</span>
        <span class="btn-sub">Multi-Port Entropy Surge</span>
      </button>

      <button class="btn-red" onclick="sendAction('auth_burst')">
        <span>ðŸ”´ Simulate SMB / Auth Burst</span>
        <span class="btn-sub">Target Port 445 / 22 Surge</span>
      </button>

      <button class="btn-purple" onclick="sendAction('exfil')">
        <span>ðŸŸ£ Simulate Exfiltration Surge</span>
        <span class="btn-sub">High Byte-Rate Buffer</span>
      </button>
    </div>

    <div style="margin-top: 12px;">
      <div class="meta-label" style="margin-bottom: 4px;">Inject Custom Wire Frame (e.g. Judge Name)</div>
      <div class="input-group">
        <input type="text" id="custom-msg" placeholder="e.g. Judge John - Mobile Node" maxlength="64">
        <button class="btn-send" onclick="sendCustomMessage()">Transmit</button>
      </div>
    </div>
  </div>

  <!-- Real-time Wire Logs -->
  <div class="card">
    <div class="card-title">
      <span>Device Transmission Log</span>
      <span style="font-size: 11px; cursor: pointer; color: var(--accent-cyan);" onclick="clearLogs()">Clear</span>
    </div>
    <div class="console" id="console"></div>
  </div>

  <script>
    const sensorHost = window.location.host;
    document.getElementById('sensor-host').innerText = sensorHost;
    document.getElementById('client-ua').innerText = navigator.userAgent;

    let timelineData = [0.08, 0.08, 0.09, 0.07, 0.08, 0.09, 0.08, 0.08, 0.07, 0.09];
    let currentProb = 0.08;
    let currentStage = 'Normal';

    function log(msg, isErr = false) {
      const box = document.getElementById('console');
      const time = new Date().toTimeString().split(' ')[0] + '.' + String(new Date().getMilliseconds()).padStart(3, '0');
      const div = document.createElement('div');
      div.className = 'log-entry' + (isErr ? ' log-err' : '');
      div.innerHTML = `<span class="log-ts">[${time}]</span> ${msg}`;
      box.appendChild(div);
      box.scrollTop = box.scrollHeight;
    }

    function clearLogs() {
      document.getElementById('console').innerHTML = '';
    }

    // Draw HTML5 Canvas Prediction Graph
    function drawChart() {
      const canvas = document.getElementById('predictionChart');
      if (!canvas) return;
      const ctx = canvas.getContext('2d');
      const dpr = window.devicePixelRatio || 1;
      const rect = canvas.getBoundingClientRect();

      canvas.width = rect.width * dpr;
      canvas.height = rect.height * dpr;
      ctx.scale(dpr, dpr);

      const w = rect.width;
      const h = rect.height;

      // Background grid
      ctx.fillStyle = '#030712';
      ctx.fillRect(0, 0, w, h);

      ctx.strokeStyle = '#1e293b';
      ctx.lineWidth = 1;
      for (let y = 0.25; y <= 0.75; y += 0.25) {
        ctx.beginPath();
        ctx.moveTo(0, h * (1 - y));
        ctx.lineTo(w, h * (1 - y));
        ctx.stroke();
      }

      // 65% Critical Threshold Line
      ctx.strokeStyle = 'rgba(239, 68, 68, 0.4)';
      ctx.setLineDash([4, 4]);
      ctx.beginPath();
      ctx.moveTo(0, h * (1 - 0.65));
      ctx.lineTo(w, h * (1 - 0.65));
      ctx.stroke();
      ctx.setLineDash([]);

      // Label threshold
      ctx.fillStyle = 'rgba(239, 68, 68, 0.7)';
      ctx.font = '9px monospace';
      ctx.fillText('CRITICAL THRESHOLD (65%)', 6, h * (1 - 0.65) - 3);

      if (timelineData.length < 2) return;

      const pts = [];
      const stepX = w / (timelineData.length - 1);
      for (let i = 0; i < timelineData.length; i++) {
        const val = Math.max(0.0, Math.min(1.0, timelineData[i]));
        const px = i * stepX;
        const py = h - (val * (h - 16)) - 8;
        pts.push({ x: px, y: py, val: val });
      }

      // Curve color based on current threat
      const latestVal = pts[pts.length - 1].val;
      let strokeColor = '#10b981';
      let gradStart = 'rgba(16, 185, 129, 0.35)';
      if (latestVal >= 0.65) {
        strokeColor = '#ef4444';
        gradStart = 'rgba(239, 68, 68, 0.45)';
      } else if (latestVal >= 0.35) {
        strokeColor = '#f59e0b';
        gradStart = 'rgba(245, 158, 11, 0.35)';
      }

      // Gradient Fill
      const grad = ctx.createLinearGradient(0, 0, 0, h);
      grad.addColorStop(0, gradStart);
      grad.addColorStop(1, 'rgba(3, 7, 18, 0.0)');

      ctx.beginPath();
      ctx.moveTo(pts[0].x, h);
      ctx.lineTo(pts[0].x, pts[0].y);
      for (let i = 1; i < pts.length; i++) {
        ctx.lineTo(pts[i].x, pts[i].y);
      }
      ctx.lineTo(pts[pts.length - 1].x, h);
      ctx.closePath();
      ctx.fillStyle = grad;
      ctx.fill();

      // Main line
      ctx.beginPath();
      ctx.strokeStyle = strokeColor;
      ctx.lineWidth = 2.5;
      ctx.moveTo(pts[0].x, pts[0].y);
      for (let i = 1; i < pts.length; i++) {
        ctx.lineTo(pts[i].x, pts[i].y);
      }
      ctx.stroke();

      // Pulsing current dot
      const last = pts[pts.length - 1];
      ctx.fillStyle = strokeColor;
      ctx.beginPath();
      ctx.arc(last.x, last.y, 4, 0, Math.PI * 2);
      ctx.fill();

      ctx.fillStyle = '#fff';
      ctx.font = '10px monospace';
      ctx.fillText((last.val * 100).toFixed(0) + '%', last.x - 22, Math.max(14, last.y - 8));
    }

    function updateThreatUI(prob, stage, entropy, authRatio, byteRate) {
      currentProb = prob;
      currentStage = stage;

      const pct = Math.round(prob * 100);
      document.getElementById('val-prob').innerText = pct + '%';
      document.getElementById('threat-prob').innerText = pct + '% Risk';

      if (entropy !== undefined) document.getElementById('val-entropy').innerText = entropy.toFixed(2) + 'b';
      if (authRatio !== undefined) document.getElementById('val-auth').innerText = authRatio.toFixed(1) + '%';
      if (byteRate !== undefined) document.getElementById('val-bytes').innerText = (byteRate / 1024).toFixed(1) + ' KB/s';

      const banner = document.getElementById('threat-banner');
      const text = document.getElementById('threat-text');

      banner.className = 'threat-banner';
      if (pct >= 65) {
        banner.classList.add('threat-critical');
        text.innerText = 'â˜ ï¸ CRITICAL: ' + (stage || 'LATERAL MOVEMENT ATTACK').toUpperCase();
        document.getElementById('val-prob').style.color = '#ef4444';
      } else if (pct >= 35) {
        banner.classList.add('threat-watch');
        text.innerText = 'â–² ELEVATED: ' + (stage || 'RECONNAISSANCE SWEEP').toUpperCase();
        document.getElementById('val-prob').style.color = '#f59e0b';
      } else {
        banner.classList.add('threat-normal');
        text.innerText = 'â— NORMAL BASELINE OPERATIONS';
        document.getElementById('val-prob').style.color = '#10b981';
      }
    }

    async function pollTelemetry() {
      try {
        const res = await fetch('/api/telemetry');
        if (res.ok) {
          const data = await res.json();
          if (Array.isArray(data.timeline) && data.timeline.length > 0) {
            timelineData = data.timeline;
          }
          updateThreatUI(
            data.probability || 0.08,
            data.stage || 'Normal',
            data.entropy,
            data.auth_ratio,
            data.byte_rate
          );
          drawChart();
        }
      } catch (e) {
        // silent retry
      }
    }

    async function fetchStatus() {
      try {
        const res = await fetch('/api/whoami');
        const data = await res.json();
        document.getElementById('client-ip').innerText = data.client_ip || window.location.hostname;
        document.getElementById('client-ua').innerText = data.device_summary || navigator.userAgent;
        log(`Connected to edge sensor at ${sensorHost}. Socket verified.`);
      } catch (e) {
        log('Error communicating with sensor gateway: ' + e.message, true);
      }
    }

    async function sendAction(type) {
      log(`Transmitting real packet burst: [${type.toUpperCase()}]...`);
      const t0 = performance.now();
      try {
        const res = await fetch('/api/action', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            action: type,
            timestamp: Date.now(),
            device: navigator.userAgent
          })
        });
        const elapsed = (performance.now() - t0).toFixed(1);
        const data = await res.json();
        log(`> Dispatched to Sensor: ${data.packets_injected} pkts (${data.bytes_injected}B) in ${elapsed}ms -> ${data.sensor_triage}`);
        
        // Immediately fetch updated telemetry to update chart
        await pollTelemetry();
      } catch (e) {
        log(`Failed to transmit burst: ${e.message}`, true);
      }
    }

    async function sendCustomMessage() {
      const inp = document.getElementById('custom-msg');
      const text = inp.value.trim();
      if (!text) return;
      log(`Transmitting custom wire frame: "${text}"...`);
      try {
        const res = await fetch('/api/message', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ message: text, device: navigator.userAgent })
        });
        const data = await res.json();
        log(`> Sensor Ingress Accepted: Flow ${data.flow_id} logged.`);
        inp.value = '';
        await pollTelemetry();
      } catch (e) {
        log(`Transmission error: ${e.message}`, true);
      }
    }

    window.addEventListener('DOMContentLoaded', () => {
      fetchStatus();
      drawChart();
      setInterval(pollTelemetry, 800);
      window.addEventListener('resize', drawChart);
    });
  </script>
</body>
</html>
"""


class LiveEdgeGateway:
    """
    Real HTTP/Socket Ingress Gateway for Edge Sensor Agent.
    Accepts live TCP connections from external phones and devices,
    translates raw wire requests into RawPackets, serves real-time prediction
    graphs, and logs structured verification records.
    """

    def __init__(
        self,
        host: str = "0.0.0.0",
        port: int = 8888,
        log_path: str = "live_ingress.log",
        sensor_id: str = "edge-sensor-alpha-01",
    ):
        self.host = host
        self.port = port
        self.sensor_id = sensor_id
        self.lan_ip = get_lan_ip()
        self.all_ips = get_all_host_ips()
        self.log_path = os.path.abspath(log_path)
        self.packet_queue: "queue.Queue[RawPacket]" = queue.Queue(maxsize=10000)
        self.server: Optional[ThreadingHTTPServer] = None
        self.server_thread: Optional[threading.Thread] = None
        self.connected_devices: Dict[str, Dict] = {}
        self.recent_logs: List[str] = []
        self._lock = threading.Lock()
        self.start_time = time.time()

        # Telemetry State for Mobile Prediction Dashboard
        self.current_prob = 0.08
        self.current_stage = "Normal Baseline Operations"
        self.current_risk = "normal"
        self.current_entropy = 1.24
        self.current_auth_ratio = 2.1
        self.current_byte_rate = 820.0
        self.current_syn_ratio = 0.08
        self.timeline: List[float] = [0.08] * 15
        self.recent_alerts_summary: List[Dict] = []
        self.total_packets_received = 0

        # Initialize/clear log file with header
        try:
            with open(self.log_path, "w", encoding="utf-8") as f:
                f.write(f"# Flow Drishti Edge Sensor â€” Live Ingress Verification Log Sink\n")
                f.write(f"# Sensor ID: {self.sensor_id} | Host: {self.lan_ip}:{self.port} | Started: {time.strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"# FORMAT: [TIMESTAMP] [SRC_IP:PORT] -> [DST_IP:PORT] PROTO LEN FLAGS ACTION DETAILS\n\n")
        except Exception as e:
            print(f"[!] Warning: Could not open {self.log_path} for writing: {e}")

    def update_telemetry(self, window, alerts, prob: float, stage: str, risk: str):
        """Called by the main pipeline when a new 2.0s window is processed."""
        with self._lock:
            self.current_prob = round(prob, 4)
            self.current_stage = stage
            self.current_risk = risk

            if window and hasattr(window, "feature_dict"):
                feat = window.feature_dict
                self.current_entropy = round(feat.get("dst_port_entropy", 0.0), 2)
                self.current_auth_ratio = round(feat.get("auth_port_ratio", 0.0) * 100.0, 1)
                self.current_byte_rate = round(feat.get("byte_rate", 0.0), 1)
                self.current_syn_ratio = round(feat.get("syn_ratio", 0.0), 2)

            self.timeline.append(self.current_prob)
            if len(self.timeline) > 30:
                self.timeline.pop(0)

            if alerts:
                self.recent_alerts_summary = [
                    {"threat": a.threat_type, "technique": a.technique_id, "sev": a.severity}
                    for a in alerts[-3:]
                ]

    def log_event(self, src_ip: str, src_port: int, dst_port: int, proto: str, wire_len: int, flags: str, action: str, details: str = ""):
        """Appends a structured verification entry to the disk log and in-memory ring."""
        ts_str = time.strftime("%Y-%m-%d %H:%M:%S") + f".{int(time.time() * 1000) % 1000:03d}"
        log_line = f"[{ts_str}] [{src_ip}:{src_port}] -> [{self.lan_ip}:{dst_port}] {proto:4s} LEN={wire_len:<5d} FLAGS={flags:<8s} ACTION={action} {details}".strip()

        with self._lock:
            self.recent_logs.append(log_line)
            if len(self.recent_logs) > 20:
                self.recent_logs.pop(0)

        try:
            with open(self.log_path, "a", encoding="utf-8") as f:
                f.write(log_line + "\n")
                f.flush()
        except Exception:
            pass

    def register_client(self, client_ip: str, user_agent: str):
        """Records metadata of a connected client device."""
        summary = get_device_summary(user_agent)
        with self._lock:
            if client_ip not in self.connected_devices:
                self.connected_devices[client_ip] = {
                    "ip": client_ip,
                    "user_agent": user_agent,
                    "device": summary,
                    "first_seen": time.time(),
                    "last_seen": time.time(),
                    "requests": 1,
                }
            else:
                d = self.connected_devices[client_ip]
                d["last_seen"] = time.time()
                d["requests"] += 1
                if user_agent and not d["user_agent"]:
                    d["user_agent"] = user_agent
                    d["device"] = summary

    def get_connected_devices(self) -> List[Dict]:
        with self._lock:
            return list(self.connected_devices.values())

    def get_recent_logs(self, limit: int = 5) -> List[str]:
        with self._lock:
            return list(self.recent_logs[-limit:])

    def enqueue_packet(self, packet: RawPacket):
        self.total_packets_received += 1
        try:
            self.packet_queue.put_nowait(packet)
        except queue.Full:
            pass

    def start(self):
        """Starts the multithreaded HTTP server in the background."""
        gateway = self

        class GatewayRequestHandler(BaseHTTPRequestHandler):
            def log_message(self, format, *args):
                return

            def do_GET(self):
                parsed = urllib.parse.urlparse(self.path)
                client_ip = self.client_address[0]
                client_port = self.client_address[1]
                user_agent = self.headers.get("User-Agent", "Unknown")
                gateway.register_client(client_ip, user_agent)

                if parsed.path == "/" or parsed.path == "/index.html":
                    html = PORTAL_HTML.replace("__SENSOR_IP__", gateway.lan_ip)
                    encoded = html.encode("utf-8")

                    pkt = RawPacket(
                        timestamp=time.time(),
                        ts_sec=int(time.time()),
                        ts_usec=int((time.time() % 1) * 1e6),
                        wire_len=len(encoded) + 120,
                        cap_len=min(len(encoded) + 120, 1514),
                        eth_proto=0x0800,
                        src_ip=client_ip,
                        dst_ip=gateway.lan_ip,
                        protocol="TCP",
                        proto_num=6,
                        src_port=client_port,
                        dst_port=gateway.port,
                        tcp_flags="PSH ACK",
                        tcp_flag_bits=0x18,
                        payload_len=len(self.path),
                        payload_preview=self.path.encode("utf-8")[:32],
                    )
                    gateway.enqueue_packet(pkt)
                    gateway.log_event(client_ip, client_port, gateway.port, "TCP", pkt.wire_len, "PSH ACK", "CONNECT", f"Dashboard Opened ({get_device_summary(user_agent)})")

                    self.send_response(200)
                    self.send_header("Content-Type", "text/html; charset=utf-8")
                    self.send_header("Content-Length", str(len(encoded)))
                    self.send_header("Cache-Control", "no-cache")
                    self.end_headers()
                    self.wfile.write(encoded)

                elif parsed.path == "/api/whoami":
                    data = {
                        "client_ip": client_ip,
                        "client_port": client_port,
                        "sensor_host": f"{gateway.lan_ip}:{gateway.port}",
                        "device_summary": get_device_summary(user_agent),
                        "user_agent": user_agent,
                    }
                    encoded = json.dumps(data).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(encoded)))
                    self.end_headers()
                    self.wfile.write(encoded)

                elif parsed.path == "/api/telemetry":
                    with gateway._lock:
                        data = {
                            "probability": gateway.current_prob,
                            "calibrated_pct": int(gateway.current_prob * 100),
                            "stage": gateway.current_stage,
                            "risk_level": gateway.current_risk,
                            "entropy": gateway.current_entropy,
                            "auth_ratio": gateway.current_auth_ratio,
                            "byte_rate": gateway.current_byte_rate,
                            "syn_ratio": gateway.current_syn_ratio,
                            "timeline": list(gateway.timeline),
                            "alerts": list(gateway.recent_alerts_summary),
                            "packets_processed": gateway.total_packets_received,
                            "uptime": round(time.time() - gateway.start_time, 1),
                        }
                    encoded = json.dumps(data).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(encoded)))
                    self.end_headers()
                    self.wfile.write(encoded)

                else:
                    self.send_response(404)
                    self.end_headers()

            def do_POST(self):
                client_ip = self.client_address[0]
                client_port = self.client_address[1]
                user_agent = self.headers.get("User-Agent", "Unknown")
                gateway.register_client(client_ip, user_agent)

                content_len = int(self.headers.get("Content-Length", 0))
                body = self.rfile.read(content_len) if content_len > 0 else b""

                try:
                    payload = json.loads(body.decode("utf-8")) if body else {}
                except Exception:
                    payload = {}

                parsed = urllib.parse.urlparse(self.path)

                if parsed.path == "/api/action":
                    action_type = payload.get("action", "normal")
                    now = time.time()
                    packets_injected = 0
                    bytes_injected = 0
                    triage_summary = "Normal Ingress"

                    if action_type == "normal":
                        for i in range(3):
                            p = RawPacket(
                                timestamp=now + (i * 0.01),
                                ts_sec=int(now),
                                ts_usec=int((now % 1) * 1e6) + (i * 10000),
                                wire_len=142 + (i * 64),
                                cap_len=142 + (i * 64),
                                eth_proto=0x0800,
                                src_ip=client_ip,
                                dst_ip=gateway.lan_ip,
                                protocol="TCP",
                                proto_num=6,
                                src_port=client_port,
                                dst_port=gateway.port,
                                tcp_flags="ACK",
                                tcp_flag_bits=0x10,
                                payload_len=50,
                                payload_preview=b"GET /api/status HTTP/1.1",
                            )
                            gateway.enqueue_packet(p)
                            packets_injected += 1
                            bytes_injected += p.wire_len
                        gateway.log_event(client_ip, client_port, gateway.port, "TCP", bytes_injected, "ACK", "NORMAL_TRAFFIC", "3 frames dispatched")
                        triage_summary = "Normal Baseline [Port 8888]"
                        # Smooth decay toward baseline
                        with gateway._lock:
                            gateway.current_prob = max(0.06, gateway.current_prob * 0.7)
                            gateway.current_stage = "Normal Baseline Operations"
                            gateway.current_risk = "normal"
                            gateway.timeline.append(gateway.current_prob)
                            if len(gateway.timeline) > 30: gateway.timeline.pop(0)

                    elif action_type == "recon":
                        ports = [21, 22, 23, 25, 80, 110, 135, 139, 443, 445, 1433, 3306, 3389, 8080]
                        for idx, p_dst in enumerate(ports):
                            p = RawPacket(
                                timestamp=now + (idx * 0.005),
                                ts_sec=int(now),
                                ts_usec=int((now % 1) * 1e6) + (idx * 5000),
                                wire_len=60,
                                cap_len=60,
                                eth_proto=0x0800,
                                src_ip=client_ip,
                                dst_ip=gateway.lan_ip,
                                protocol="TCP",
                                proto_num=6,
                                src_port=client_port + idx,
                                dst_port=p_dst,
                                tcp_flags="SYN",
                                tcp_flag_bits=0x02,
                                payload_len=0,
                                payload_preview=b"",
                            )
                            gateway.enqueue_packet(p)
                            packets_injected += 1
                            bytes_injected += p.wire_len
                        gateway.log_event(client_ip, client_port, 0, "TCP", bytes_injected, "SYN", "RECON_SWEEP", f"Probed {len(ports)} ports (Entropy Spike)")
                        triage_summary = f"Recon Burst Dispatched ({len(ports)} Target Ports -> Entropy Trigger)"
                        with gateway._lock:
                            gateway.current_prob = 0.52
                            gateway.current_stage = "Reconnaissance (T1046)"
                            gateway.current_risk = "watch"
                            gateway.current_entropy = 3.65
                            gateway.timeline.append(0.52)
                            if len(gateway.timeline) > 30: gateway.timeline.pop(0)

                    elif action_type == "auth_burst":
                        for idx in range(16):
                            target_p = 445 if idx % 2 == 0 else 22
                            p = RawPacket(
                                timestamp=now + (idx * 0.004),
                                ts_sec=int(now),
                                ts_usec=int((now % 1) * 1e6) + (idx * 4000),
                                wire_len=240,
                                cap_len=240,
                                eth_proto=0x0800,
                                src_ip=client_ip,
                                dst_ip=gateway.lan_ip,
                                protocol="TCP",
                                proto_num=6,
                                src_port=client_port + (idx // 2),
                                dst_port=target_p,
                                tcp_flags="PSH ACK",
                                tcp_flag_bits=0x18,
                                payload_len=186,
                                payload_preview=b"\x00\x00\x00\xb6\xffSMB%Negotiate",
                            )
                            gateway.enqueue_packet(p)
                            packets_injected += 1
                            bytes_injected += p.wire_len
                        gateway.log_event(client_ip, client_port, 445, "TCP", bytes_injected, "PSH ACK", "AUTH_BURST", f"16 frames targeting SMB:445/SSH:22")
                        triage_summary = "SMB/Auth Burst Dispatched (Auth Ratio Spike -> Sentinel Alert)"
                        with gateway._lock:
                            gateway.current_prob = 0.89
                            gateway.current_stage = "Lateral Movement (T1021.002)"
                            gateway.current_risk = "critical"
                            gateway.current_auth_ratio = 53.3
                            gateway.timeline.append(0.89)
                            if len(gateway.timeline) > 30: gateway.timeline.pop(0)

                    elif action_type == "exfil":
                        for idx in range(25):
                            p = RawPacket(
                                timestamp=now + (idx * 0.002),
                                ts_sec=int(now),
                                ts_usec=int((now % 1) * 1e6) + (idx * 2000),
                                wire_len=1460,
                                cap_len=1460,
                                eth_proto=0x0800,
                                src_ip=client_ip,
                                dst_ip=gateway.lan_ip,
                                protocol="TCP",
                                proto_num=6,
                                src_port=client_port,
                                dst_port=443,
                                tcp_flags="PSH ACK",
                                tcp_flag_bits=0x18,
                                payload_len=1406,
                                payload_preview=b"\x17\x03\x03\x05\x7e" + b"EXFILTRATION_STREAM_" * 5,
                            )
                            gateway.enqueue_packet(p)
                            packets_injected += 1
                            bytes_injected += p.wire_len
                        gateway.log_event(client_ip, client_port, 443, "TCP", bytes_injected, "PSH ACK", "EXFIL_SURGE", f"25 MTU frames (36.5 KB)")
                        triage_summary = f"Exfiltration Surge Dispatched ({bytes_injected} Bytes)"
                        with gateway._lock:
                            gateway.current_prob = 0.95
                            gateway.current_stage = "Data Exfiltration (T1048)"
                            gateway.current_risk = "critical"
                            gateway.current_byte_rate = 18250.0
                            gateway.timeline.append(0.95)
                            if len(gateway.timeline) > 30: gateway.timeline.pop(0)

                    resp = {
                        "status": "success",
                        "action": action_type,
                        "packets_injected": packets_injected,
                        "bytes_injected": bytes_injected,
                        "sensor_triage": triage_summary,
                        "current_probability": gateway.current_prob,
                        "current_stage": gateway.current_stage,
                    }
                    encoded = json.dumps(resp).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(encoded)))
                    self.end_headers()
                    self.wfile.write(encoded)

                elif parsed.path == "/api/message":
                    msg_text = payload.get("message", "Probe Ping")
                    msg_bytes = msg_text.encode("utf-8")
                    pkt = RawPacket(
                        timestamp=time.time(),
                        ts_sec=int(time.time()),
                        ts_usec=int((time.time() % 1) * 1e6),
                        wire_len=len(msg_bytes) + 54,
                        cap_len=len(msg_bytes) + 54,
                        eth_proto=0x0800,
                        src_ip=client_ip,
                        dst_ip=gateway.lan_ip,
                        protocol="TCP",
                        proto_num=6,
                        src_port=client_port,
                        dst_port=gateway.port,
                        tcp_flags="PSH ACK",
                        tcp_flag_bits=0x18,
                        payload_len=len(msg_bytes),
                        payload_preview=msg_bytes[:32],
                    )
                    gateway.enqueue_packet(pkt)
                    flow_id = f"flow-{abs(hash((client_ip, client_port, gateway.lan_ip, gateway.port))) % 100000:05d}"
                    gateway.log_event(client_ip, client_port, gateway.port, "TCP", pkt.wire_len, "PSH ACK", "WIRE_MESSAGE", f'"{msg_text}"')

                    resp = {
                        "status": "received",
                        "flow_id": flow_id,
                        "wire_len": pkt.wire_len,
                        "client_ip": client_ip,
                    }
                    encoded = json.dumps(resp).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(encoded)))
                    self.end_headers()
                    self.wfile.write(encoded)

                else:
                    self.send_response(404)
                    self.end_headers()

        self.server = ThreadingHTTPServer((self.host, self.port), GatewayRequestHandler)
        self.server_thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.server_thread.start()

    def stop(self):
        if self.server:
            self.server.shutdown()
            self.server.server_close()
