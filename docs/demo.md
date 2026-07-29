# Quickstart & Demo Guide

This guide demonstrates how to set up, run, and evaluate the **BiLSTM Real-Time Intrusion Detection System**.

---

## 1. Prerequisites Checklist

- **Python**: Version 3.8+
- **Wireshark / tshark**: Installed and present in system PATH (`C:\Program Files\Wireshark\tshark.exe` on Windows).
- **Dependencies**: Installed via `pip install -r requirements.txt`.

---

## 2. Running Live Detection Mode

To capture and analyze live packets from your network interface:

```bash
# List available network interfaces
python realtime_ids.py --list-ifaces

# Launch IDS on specific interface index (e.g., interface 4)
python realtime_ids.py --iface 4
```

Terminal output will stream live classification results with color-coded threat badges (`[NORMAL]`, `[DOS]`, `[PROBE]`, `[R2L]`, `[U2R]`).

---

## 3. Running PCAP Replay Mode

To evaluate the system against sample packet captures without live traffic generation:

```bash
# Replay standard packet capture
python pcap_replay.py --pcap normal_traffic.pcap --delay 0.02
```

---

## 4. Launching the Web Dashboard

To visualize live alerts and attack distributions in real time:

```bash
# Start Flask web server
python dashboard.py --port 5000
```

Open `http://localhost:5000` in any web browser to view:
- **Live Alert Feed**: Real-time tabular stream of detected threats and packet metadata.
- **Threat Distribution Chart**: Dynamic chart displaying attack vector proportions.
- **Session Metrics**: Total processed packets, alert rates, and confidence scores.

---

## 5. Model Conversion & Compatibility Tools

If running into Keras 3 / TensorFlow 2.x version mismatch issues:

```bash
# Fix model format compatibility
python fix_model_compatibility.py

# Rebuild feature schema pkl if needed
python fix_columns_pkl.py
```
