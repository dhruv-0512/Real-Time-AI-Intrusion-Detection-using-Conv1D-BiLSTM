"""
dashboard.py - SOC-grade live web dashboard for the BiLSTM IDS.

Reads ids_alerts.jsonl (written by realtime_ids.py / pcap_replay.py) and
serves a live-updating dashboard with:
  - System health panel (IDS status, latency, model info)
  - Severity-coded alert feed with source/dest IPs & protocol
  - Threat distribution doughnut chart
  - Classification breakdown progress bars
  - Attack timeline (alerts bucketed by minute)
  - Deduplicated alert grouping view
  - Packet statistics
  - Model metadata panel

Design: Cyber-Sentinel Aesthetic (glassmorphism dark theme)

USAGE
    python dashboard.py                     # uses logs/ids_alerts.jsonl
    python dashboard.py --alerts path.jsonl # point at a different file
    python dashboard.py --port 8000

Then open http://localhost:5000 in a browser.
"""

import argparse
import json
import os
import threading
import time
from collections import deque, defaultdict

from flask import Flask, jsonify, render_template_string

app = Flask(__name__)

STATE = {
    "alert_file": os.path.join("logs", "ids_alerts.jsonl") if os.path.exists(os.path.join("logs", "ids_alerts.jsonl")) else "ids_alerts.jsonl",
    "alerts": deque(maxlen=500),
    "last_size": 0,
    "start_time": time.time(),
}
LOCK = threading.Lock()


def tail_loop():
    """Background thread: poll the alert file for new lines."""
    while True:
        try:
            path = STATE["alert_file"]
            if os.path.exists(path):
                size = os.path.getsize(path)
                if size < STATE["last_size"]:
                    STATE["last_size"] = 0
                    with LOCK:
                        STATE["alerts"].clear()
                if size > STATE["last_size"]:
                    with open(path, "r", encoding="utf-8") as f:
                        f.seek(STATE["last_size"])
                        new_data = f.read()
                    STATE["last_size"] = size
                    with LOCK:
                        for line in new_data.splitlines():
                            line = line.strip()
                            if not line:
                                continue
                            try:
                                STATE["alerts"].append(json.loads(line))
                            except json.JSONDecodeError:
                                pass
        except Exception:
            pass
        time.sleep(1.0)


@app.route("/api/alerts")
def api_alerts():
    with LOCK:
        alerts = list(STATE["alerts"])

    # Counts & percentages
    counts = defaultdict(int)
    severity_counts = defaultdict(int)
    for a in alerts:
        counts[a.get("label", "UNKNOWN")] += 1
        severity_counts[a.get("severity", "INFO")] += 1

    total = len(alerts)
    pcts = {k: round(v / total * 100, 1) if total > 0 else 0 for k, v in counts.items()}

    # Timeline: bucket alerts by minute
    timeline = defaultdict(lambda: {"total": 0, "threats": 0})
    for a in alerts:
        ts = a.get("ts", "")
        if ts:
            minute_key = ts[:16]  # "2026-07-28T20:41"
            timeline[minute_key]["total"] += 1
            if a.get("label", "NORMAL") != "NORMAL":
                timeline[minute_key]["threats"] += 1
    sorted_timeline = sorted(timeline.items())[-30:]  # last 30 minutes

    # Deduplication summary: group by (label, src_ip)
    dedup_groups = defaultdict(lambda: {"count": 0, "first_seen": "", "last_seen": "", "max_conf": 0, "dst_ip": ""})
    for a in alerts:
        if a.get("label", "NORMAL") == "NORMAL":
            continue
        key = f"{a.get('label', '')}|{a.get('src_ip', '')}"
        g = dedup_groups[key]
        g["count"] += 1
        g["label"] = a.get("label", "")
        g["src_ip"] = a.get("src_ip", "")
        g["dst_ip"] = a.get("dst_ip", "")
        g["severity"] = a.get("severity", "MEDIUM")
        g["max_conf"] = max(g["max_conf"], a.get("confidence", 0))
        ts = a.get("ts", "")
        if not g["first_seen"] or ts < g["first_seen"]:
            g["first_seen"] = ts
        if not g["last_seen"] or ts > g["last_seen"]:
            g["last_seen"] = ts

    dedup_list = sorted(dedup_groups.values(), key=lambda x: x["count"], reverse=True)[:20]

    # Protocol breakdown
    proto_counts = defaultdict(int)
    for a in alerts:
        proto_counts[a.get("protocol", "TCP")] += 1

    uptime = time.time() - STATE["start_time"]

    return jsonify({
        "alerts": alerts[-100:][::-1],
        "total": total,
        "counts": dict(counts),
        "percentages": pcts,
        "severity_counts": dict(severity_counts),
        "timeline": [{"minute": m, "total": d["total"], "threats": d["threats"]} for m, d in sorted_timeline],
        "dedup_groups": dedup_list,
        "proto_counts": dict(proto_counts),
        "uptime_sec": round(uptime),
    })


PAGE = r"""
<!DOCTYPE html>
<html class="dark" lang="en"><head>
<meta charset="utf-8"/>
<meta content="width=device-width, initial-scale=1.0" name="viewport"/>
<title>BiLSTM IDS - SOC Dashboard</title>
<script src="https://cdn.tailwindcss.com?plugins=forms,container-queries"></script>
<link href="https://fonts.googleapis.com/css2?family=Material+Symbols+Outlined:wght,FILL@100..700,0..1&display=swap" rel="stylesheet"/>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet"/>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js"></script>
<script>
    tailwind.config = {
        darkMode: "class",
        theme: {
            extend: {
                colors: {
                    "background": "#0b0f14", "surface": "#121820", "surface-dim": "#0f150f",
                    "surface-container": "#1b211a", "surface-container-high": "#262c24",
                    "outline-variant": "#3f4a3d", "on-surface": "#dee4d9",
                    "on-surface-variant": "#becaba", "primary": "#b3ffb3",
                    "primary-container": "#7ee787", "brand-border": "#1f2b38",
                    "brand-text-primary": "#d8e1e8", "brand-text-secondary": "#6b7785",
                    "threat-red": "#ff7b72", "threat-yellow": "#f2cc60",
                    "threat-green": "#7ee787", "threat-purple": "#dbb8ff", "threat-cyan": "#38bdf8"
                },
                spacing: { xs: "4px", lg: "24px", sm: "8px", "container-max": "1440px", gutter: "20px", md: "16px", xl: "32px" },
                fontFamily: { "body-md": ["Inter"], "label-md": ["Inter"], "headline-sm": ["Inter"], "mono-sm": ["monospace"], "headline-md": ["Inter"], "headline-lg": ["Inter"] },
                fontSize: {
                    "body-md": ["14px", {"lineHeight": "20px", "fontWeight": "400"}],
                    "label-md": ["12px", {"lineHeight": "16px", "letterSpacing": "0.05em", "fontWeight": "600"}],
                    "headline-sm": ["20px", {"lineHeight": "28px", "fontWeight": "600"}],
                    "mono-sm": ["13px", {"lineHeight": "18px", "fontWeight": "400"}],
                    "headline-md": ["24px", {"lineHeight": "32px", "letterSpacing": "-0.01em", "fontWeight": "600"}],
                    "headline-lg": ["32px", {"lineHeight": "40px", "letterSpacing": "-0.02em", "fontWeight": "700"}]
                }
            }
        }
    }
</script>
<style>
    body { background: #0b0f14; color: #d8e1e8; }
    .glass-card { background: #121820; border: 1px solid #1f2b38; border-radius: 0.5rem; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1); transition: all 0.3s ease; overflow: hidden; }
    .glass-card:hover { border-color: rgba(126,231,135,0.3); box-shadow: inset 0 2px 4px 0 rgba(255,255,255,0.05); }
    @keyframes pulse-dot { 0%,100%{opacity:1;transform:scale(1)} 50%{opacity:.5;transform:scale(.8)} }
    .animate-pulse-dot { animation: pulse-dot 2s cubic-bezier(0.4,0,0.6,1) infinite; }
    ::-webkit-scrollbar{width:6px;height:6px} ::-webkit-scrollbar-track{background:#0b0f14} ::-webkit-scrollbar-thumb{background:#1f2b38;border-radius:3px}
    .sev-CRITICAL{background:rgba(255,123,114,0.2);color:#ff7b72;border-left:2px solid #ff7b72}
    .sev-HIGH{background:rgba(255,123,114,0.15);color:#ff7b72;border-left:2px solid #ff7b72}
    .sev-MEDIUM{background:rgba(242,204,96,0.15);color:#f2cc60;border-left:2px solid #f2cc60}
    .sev-LOW{background:rgba(255,255,255,0.08);color:#d8e1e8;border-left:2px solid #6b7785}
    .sev-INFO{background:rgba(126,231,135,0.12);color:#7ee787;border-left:2px solid #7ee787}
</style>
</head>
<body class="font-body-md antialiased min-h-screen flex flex-col">

<!-- Top Navbar -->
<header class="bg-[#121820]/90 backdrop-blur-md fixed top-0 left-0 w-full z-50 flex justify-between items-center px-lg h-14 border-b border-[#1f2b38]">
  <div class="font-headline-md text-headline-md font-bold text-primary flex items-center gap-2">
    <span class="material-symbols-outlined text-primary-container text-2xl" style="font-variation-settings:'FILL' 1">security</span>
    BiLSTM IDS
  </div>
  <div class="flex items-center gap-2 font-label-md text-label-md text-primary-container bg-primary-container/10 px-3 py-1 rounded-full border border-primary-container/20">
    <span class="w-2 h-2 rounded-full bg-primary-container animate-pulse-dot shadow-[0_0_8px_rgba(126,231,135,0.8)]"></span>
    MONITORING ACTIVE
  </div>
  <div class="flex items-center gap-3 text-on-surface-variant font-mono-sm text-mono-sm">
    <span>Alerts: <span class="text-on-surface font-semibold" id="navTotal">0</span></span>
    <div class="h-4 w-px bg-outline-variant"></div>
    <span id="clock">--:--:--</span>
  </div>
</header>

<main class="flex-1 mt-14 p-lg max-w-container-max mx-auto w-full flex flex-col gap-lg">

  <!-- ROW 1: System Health + Stats -->
  <div class="grid grid-cols-1 lg:grid-cols-12 gap-gutter">
    <!-- IDS Health Panel -->
    <div class="glass-card p-md lg:col-span-3">
      <h2 class="font-label-md text-label-md text-brand-text-secondary uppercase tracking-wider mb-3 flex items-center gap-2">
        <span class="material-symbols-outlined text-sm">monitor_heart</span> SYSTEM STATUS
      </h2>
      <div class="space-y-3 text-sm">
        <div class="flex justify-between"><span class="text-brand-text-secondary">Status</span><span class="text-threat-green font-semibold flex items-center gap-1"><span class="w-1.5 h-1.5 rounded-full bg-threat-green"></span>Running</span></div>
        <div class="flex justify-between"><span class="text-brand-text-secondary">Uptime</span><span id="uptime" class="font-mono-sm">0m 0s</span></div>
        <div class="flex justify-between"><span class="text-brand-text-secondary">Model</span><span class="font-mono-sm text-primary-container">BiLSTM NSL-KDD</span></div>
        <div class="flex justify-between"><span class="text-brand-text-secondary">Architecture</span><span class="font-mono-sm">Conv1D+BiLSTM×2</span></div>
        <div class="flex justify-between"><span class="text-brand-text-secondary">Classes</span><span class="font-mono-sm">5</span></div>
        <div class="flex justify-between"><span class="text-brand-text-secondary">Features</span><span class="font-mono-sm">122</span></div>
        <div class="flex justify-between"><span class="text-brand-text-secondary">Dataset</span><span class="font-mono-sm">NSL-KDD</span></div>
      </div>
    </div>
    <!-- Stats Cards -->
    <div class="lg:col-span-9 grid grid-cols-2 lg:grid-cols-4 gap-gutter">
      <div class="glass-card p-md">
        <div class="font-label-md text-label-md text-brand-text-secondary uppercase tracking-wider mb-1">Total Alerts</div>
        <div class="text-3xl font-bold text-white" id="statTotal">0</div>
      </div>
      <div class="glass-card p-md">
        <div class="font-label-md text-label-md text-brand-text-secondary uppercase tracking-wider mb-1">Threats</div>
        <div class="text-3xl font-bold text-threat-red" id="statThreats">0</div>
      </div>
      <div class="glass-card p-md">
        <div class="font-label-md text-label-md text-brand-text-secondary uppercase tracking-wider mb-1 flex items-center gap-1">
          <span class="material-symbols-outlined text-threat-red text-sm">error</span> CRITICAL/HIGH
        </div>
        <div class="text-3xl font-bold text-threat-red" id="statCritical">0</div>
      </div>
      <div class="glass-card p-md">
        <div class="font-label-md text-label-md text-brand-text-secondary uppercase tracking-wider mb-1">Accuracy</div>
        <div class="text-3xl font-bold text-primary-container">99.16%</div>
      </div>
      <!-- Severity mini-cards -->
      <div class="glass-card p-md"><div class="text-xs text-brand-text-secondary uppercase mb-1">Critical</div><div class="text-xl font-bold text-threat-red" id="sevCritical">0</div></div>
      <div class="glass-card p-md"><div class="text-xs text-brand-text-secondary uppercase mb-1">High</div><div class="text-xl font-bold text-threat-red" id="sevHigh">0</div></div>
      <div class="glass-card p-md"><div class="text-xs text-brand-text-secondary uppercase mb-1">Medium</div><div class="text-xl font-bold text-threat-yellow" id="sevMedium">0</div></div>
      <div class="glass-card p-md"><div class="text-xs text-brand-text-secondary uppercase mb-1">Low/Info</div><div class="text-xl font-bold text-threat-green" id="sevLow">0</div></div>
    </div>
  </div>

  <!-- ROW 2: Alert Feed + Distribution -->
  <div class="grid grid-cols-1 lg:grid-cols-12 gap-gutter">
    <!-- Live Alert Feed -->
    <div class="glass-card lg:col-span-8 flex flex-col h-[400px]">
      <div class="p-md border-b border-brand-border flex justify-between items-center">
        <h2 class="font-headline-sm text-headline-sm font-semibold flex items-center gap-2">
          <span class="material-symbols-outlined">table_rows</span> Live Alert Feed
        </h2>
        <span class="text-brand-text-secondary text-xs" id="alertCount">0 alerts</span>
      </div>
      <div class="flex-1 overflow-auto">
        <table class="w-full text-left font-mono-sm text-mono-sm whitespace-nowrap">
          <thead class="sticky top-0 bg-[#121820] z-10 font-label-md text-label-md text-brand-text-secondary border-b border-brand-border">
            <tr>
              <th class="px-3 py-2">Time</th>
              <th class="px-3 py-2">Severity</th>
              <th class="px-3 py-2">Attack</th>
              <th class="px-3 py-2">Source IP</th>
              <th class="px-3 py-2">Dest IP</th>
              <th class="px-3 py-2">Proto</th>
              <th class="px-3 py-2">Confidence</th>
            </tr>
          </thead>
          <tbody id="alertBody" class="divide-y divide-brand-border/50">
            <tr><td colspan="7" class="px-3 py-6 text-center text-brand-text-secondary">Waiting for alerts...</td></tr>
          </tbody>
        </table>
      </div>
    </div>
    <!-- Right Column -->
    <div class="lg:col-span-4 flex flex-col gap-gutter">
      <!-- Threat Distribution Donut -->
      <div class="glass-card p-md flex-1 min-h-[180px]">
        <h2 class="font-label-md text-label-md text-brand-text-secondary uppercase tracking-wider mb-3">Threat Distribution</h2>
        <canvas id="donutChart" height="160"></canvas>
      </div>
      <!-- Classification Breakdown -->
      <div class="glass-card p-md">
        <h2 class="font-label-md text-label-md text-brand-text-secondary uppercase tracking-wider mb-3">Classification Breakdown</h2>
        <div class="space-y-3" id="breakdownBars"><div class="text-sm text-brand-text-secondary">Waiting...</div></div>
      </div>
    </div>
  </div>

  <!-- ROW 3: Attack Timeline -->
  <div class="glass-card p-md">
    <h2 class="font-headline-sm text-headline-sm font-semibold mb-3 flex items-center gap-2">
      <span class="material-symbols-outlined">timeline</span> Attack Timeline
    </h2>
    <canvas id="timelineChart" height="80"></canvas>
  </div>

  <!-- ROW 4: Deduplicated Alerts + Protocol Stats -->
  <div class="grid grid-cols-1 lg:grid-cols-12 gap-gutter">
    <!-- Deduplicated Alert Groups -->
    <div class="glass-card lg:col-span-8 p-md">
      <h2 class="font-headline-sm text-headline-sm font-semibold mb-3 flex items-center gap-2">
        <span class="material-symbols-outlined">stacks</span> Deduplicated Alert Groups
      </h2>
      <div class="overflow-auto max-h-[250px]">
        <table class="w-full text-left font-mono-sm text-mono-sm whitespace-nowrap">
          <thead class="sticky top-0 bg-[#121820] font-label-md text-label-md text-brand-text-secondary border-b border-brand-border">
            <tr><th class="px-3 py-2">Attack</th><th class="px-3 py-2">Severity</th><th class="px-3 py-2">Source</th><th class="px-3 py-2">Dest</th><th class="px-3 py-2">Occurrences</th><th class="px-3 py-2">First Seen</th><th class="px-3 py-2">Last Seen</th><th class="px-3 py-2">Max Conf</th></tr>
          </thead>
          <tbody id="dedupBody" class="divide-y divide-brand-border/50"><tr><td colspan="8" class="px-3 py-4 text-center text-brand-text-secondary">No grouped alerts yet</td></tr></tbody>
        </table>
      </div>
    </div>
    <!-- Protocol & Network Stats -->
    <div class="lg:col-span-4 flex flex-col gap-gutter">
      <div class="glass-card p-md">
        <h2 class="font-label-md text-label-md text-brand-text-secondary uppercase tracking-wider mb-3">Network Activity</h2>
        <div class="space-y-2 text-sm" id="protoStats"><div class="text-brand-text-secondary">Waiting...</div></div>
      </div>
      <div class="glass-card p-md">
        <h2 class="font-label-md text-label-md text-brand-text-secondary uppercase tracking-wider mb-3">Model Metadata</h2>
        <div class="space-y-2 text-xs font-mono-sm">
          <div class="flex justify-between"><span class="text-brand-text-secondary">Architecture</span><span>Conv1D -> MaxPool -> BN -> BiLSTM×2 -> Dense(5)</span></div>
          <div class="flex justify-between"><span class="text-brand-text-secondary">Dataset</span><span>NSL-KDD (125,973 train / 22,544 test)</span></div>
          <div class="flex justify-between"><span class="text-brand-text-secondary">Input Shape</span><span>(122, 1)</span></div>
          <div class="flex justify-between"><span class="text-brand-text-secondary">Output</span><span>Normal | DoS | Probe | R2L | U2R</span></div>
          <div class="flex justify-between"><span class="text-brand-text-secondary">Accuracy</span><span class="text-threat-green">99.16%</span></div>
          <div class="flex justify-between"><span class="text-brand-text-secondary">FPR</span><span class="text-threat-yellow">0.83%</span></div>
        </div>
      </div>
    </div>
  </div>

</main>

<script>
const COLORS = {NORMAL:'#7ee787',DOS:'#ff7b72',PROBE:'#f2cc60',R2L:'#dbb8ff',U2R:'#38bdf8'};
const SEV_CLS = {CRITICAL:'sev-CRITICAL',HIGH:'sev-HIGH',MEDIUM:'sev-MEDIUM',LOW:'sev-LOW',INFO:'sev-INFO'};

function updateClock(){ document.getElementById('clock').textContent = new Date().toLocaleTimeString(); }
setInterval(updateClock,1000); updateClock();

function fmtUptime(s){const m=Math.floor(s/60),h=Math.floor(m/60);return h>0?`${h}h ${m%60}m`:`${m}m ${Math.floor(s%60)}s`}

function badge(label){const c=COLORS[label]||'#d8e1e8';return `<span style="display:inline-flex;align-items:center;padding:1px 6px;border-radius:3px;font-size:11px;font-weight:600;background:${c}22;color:${c};border-left:2px solid ${c}">${label}</span>`}
function sevBadge(sev){const cls=SEV_CLS[sev]||'sev-LOW';return `<span class="${cls}" style="display:inline-flex;padding:1px 6px;border-radius:3px;font-size:10px;font-weight:600">${sev}</span>`}

// Charts
const donutCtx = document.getElementById('donutChart').getContext('2d');
const donutChart = new Chart(donutCtx, {
  type:'doughnut', data:{labels:[],datasets:[{data:[],backgroundColor:Object.values(COLORS),borderWidth:0}]},
  options:{responsive:true,maintainAspectRatio:false,cutout:'65%',plugins:{legend:{labels:{color:'#6b7785',font:{size:11}},position:'bottom'}}}
});

const tlCtx = document.getElementById('timelineChart').getContext('2d');
const tlChart = new Chart(tlCtx, {
  type:'bar', data:{labels:[],datasets:[
    {label:'Total',data:[],backgroundColor:'rgba(126,231,135,0.3)',borderColor:'#7ee787',borderWidth:1},
    {label:'Threats',data:[],backgroundColor:'rgba(255,123,114,0.5)',borderColor:'#ff7b72',borderWidth:1}
  ]},
  options:{responsive:true,maintainAspectRatio:false,scales:{x:{ticks:{color:'#6b7785',font:{size:10}},grid:{color:'#1f2b3844'}},y:{ticks:{color:'#6b7785',font:{size:10}},grid:{color:'#1f2b3844'},beginAtZero:true}},plugins:{legend:{labels:{color:'#6b7785',font:{size:11}}}}}
});

async function poll(){
  try{
    const res=await fetch('/api/alerts');
    const d=await res.json();

    document.getElementById('navTotal').textContent=d.total.toLocaleString();
    document.getElementById('statTotal').textContent=d.total.toLocaleString();
    const threats=d.total-(d.counts.NORMAL||0);
    document.getElementById('statThreats').textContent=threats.toLocaleString();
    document.getElementById('statCritical').textContent=((d.severity_counts.CRITICAL||0)+(d.severity_counts.HIGH||0)).toLocaleString();
    document.getElementById('sevCritical').textContent=(d.severity_counts.CRITICAL||0).toLocaleString();
    document.getElementById('sevHigh').textContent=(d.severity_counts.HIGH||0).toLocaleString();
    document.getElementById('sevMedium').textContent=(d.severity_counts.MEDIUM||0).toLocaleString();
    document.getElementById('sevLow').textContent=((d.severity_counts.LOW||0)+(d.severity_counts.INFO||0)).toLocaleString();
    document.getElementById('uptime').textContent=fmtUptime(d.uptime_sec);
    document.getElementById('alertCount').textContent=d.alerts.length+' recent';

    // Alert table
    const body=document.getElementById('alertBody');
    if(d.alerts.length===0){body.innerHTML='<tr><td colspan="7" class="px-3 py-6 text-center text-brand-text-secondary">Waiting for alerts...</td></tr>';}
    else{body.innerHTML=d.alerts.map(a=>{
      const ts=a.ts||a.timestamp||'';let t='';try{t=new Date(ts).toLocaleTimeString()}catch(e){t=ts}
      const sev=a.severity||'INFO';const conf=(a.confidence*100).toFixed(1);
      return `<tr class="hover:bg-white/[0.02] transition-colors">
        <td class="px-3 py-2 text-brand-text-secondary">${t}</td>
        <td class="px-3 py-2">${sevBadge(sev)}</td>
        <td class="px-3 py-2">${badge(a.label)}</td>
        <td class="px-3 py-2">${a.src_ip||'-'}</td>
        <td class="px-3 py-2">${a.dst_ip||'-'}</td>
        <td class="px-3 py-2 text-brand-text-secondary">${a.protocol||'-'}</td>
        <td class="px-3 py-2"><div style="display:flex;align-items:center;gap:6px"><div style="width:48px;height:4px;background:#0f150f;border-radius:9px;overflow:hidden"><div style="height:100%;background:${COLORS[a.label]||'#d8e1e8'};width:${conf}%"></div></div>${conf}%</div></td>
      </tr>`}).join('')}

    // Donut
    const order=['NORMAL','DOS','PROBE','R2L','U2R'];
    donutChart.data.labels=order.filter(k=>d.counts[k]);
    donutChart.data.datasets[0].data=order.filter(k=>d.counts[k]).map(k=>d.counts[k]);
    donutChart.data.datasets[0].backgroundColor=order.filter(k=>d.counts[k]).map(k=>COLORS[k]);
    donutChart.update('none');

    // Breakdown
    document.getElementById('breakdownBars').innerHTML=order.map(k=>{
      const p=d.percentages[k]||0;return `<div><div style="display:flex;justify-content:space-between;margin-bottom:2px"><span style="color:#d8e1e8;font-size:13px">${k}</span><span style="color:#6b7785;font-family:monospace;font-size:12px">${p}%</span></div><div style="width:100%;height:5px;background:#0f150f;border-radius:9px;overflow:hidden"><div style="background:${COLORS[k]};height:100%;border-radius:9px;width:${p}%;transition:width .5s ease"></div></div></div>`
    }).join('');

    // Timeline
    tlChart.data.labels=d.timeline.map(t=>t.minute.substring(11));
    tlChart.data.datasets[0].data=d.timeline.map(t=>t.total);
    tlChart.data.datasets[1].data=d.timeline.map(t=>t.threats);
    tlChart.update('none');

    // Dedup groups
    const db=document.getElementById('dedupBody');
    if(d.dedup_groups.length===0){db.innerHTML='<tr><td colspan="8" class="px-3 py-4 text-center text-brand-text-secondary">No grouped alerts yet</td></tr>';}
    else{db.innerHTML=d.dedup_groups.map(g=>{
      let fs='',ls='';try{fs=new Date(g.first_seen).toLocaleTimeString();ls=new Date(g.last_seen).toLocaleTimeString()}catch(e){}
      return `<tr class="hover:bg-white/[0.02]">
        <td class="px-3 py-2">${badge(g.label)}</td>
        <td class="px-3 py-2">${sevBadge(g.severity)}</td>
        <td class="px-3 py-2">${g.src_ip||'-'}</td>
        <td class="px-3 py-2">${g.dst_ip||'-'}</td>
        <td class="px-3 py-2 font-semibold text-threat-red">${g.count}</td>
        <td class="px-3 py-2 text-brand-text-secondary">${fs}</td>
        <td class="px-3 py-2 text-brand-text-secondary">${ls}</td>
        <td class="px-3 py-2">${(g.max_conf*100).toFixed(1)}%</td>
      </tr>`}).join('')}

    // Proto stats
    const totalProto=Object.values(d.proto_counts).reduce((a,b)=>a+b,0)||1;
    document.getElementById('protoStats').innerHTML=Object.entries(d.proto_counts).sort((a,b)=>b[1]-a[1]).map(([k,v])=>{
      const p=(v/totalProto*100).toFixed(1);
      return `<div><div style="display:flex;justify-content:space-between;font-size:13px"><span>${k}</span><span style="color:#6b7785">${v} (${p}%)</span></div><div style="width:100%;height:4px;background:#0f150f;border-radius:9px;overflow:hidden;margin-top:2px"><div style="background:#7ee787;height:100%;width:${p}%"></div></div></div>`
    }).join('')||'<div class="text-brand-text-secondary">No data</div>';

  }catch(e){console.error(e)}
}
poll(); setInterval(poll,1500);
</script>
</body></html>
"""


@app.route("/")
def index():
    return render_template_string(PAGE, alert_file=STATE["alert_file"])


def main():
    ap = argparse.ArgumentParser(description="SOC Dashboard for BiLSTM IDS alerts")
    alert_default = os.path.join("logs", "ids_alerts.jsonl")
    ap.add_argument("--alerts", default=alert_default, help="Path to ids_alerts.jsonl")
    ap.add_argument("--port", type=int, default=5000)
    ap.add_argument("--host", default="127.0.0.1")
    args = ap.parse_args()

    STATE["alert_file"] = args.alerts
    STATE["last_size"] = 0

    t = threading.Thread(target=tail_loop, daemon=True)
    t.start()

    print(f"[dashboard] Tailing {args.alerts}")
    print(f"[dashboard] Open http://{args.host}:{args.port} in your browser")
    app.run(host=args.host, port=args.port, debug=False)


if __name__ == "__main__":
    main()
