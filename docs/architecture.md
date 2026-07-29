# System Architecture & Technical Design

The **Real-Time Intrusion Detection System (BiLSTM IDS)** is engineered for live network traffic analysis, feature engineering, and deep learning prediction.

---

## 1. System Pipeline Overview

```
                          ┌───────────────────────────┐
                          │   Live Network Interface  │
                          └─────────────┬─────────────┘
                                        │
                                        ▼
                          ┌───────────────────────────┐
                          │     tshark Packet Sniffer │
                          └─────────────┬─────────────┘
                                        │
                                        ▼
                          ┌───────────────────────────┐
                          │   Feature Preprocessing   │
                          │   & Alignment (122-dim)   │
                          └─────────────┬─────────────┘
                                        │
                                        ▼
                          ┌───────────────────────────┐
                          │    BiLSTM Deep Learning   │
                          │      Inference Engine     │
                          └─────────────┬─────────────┘
                                        │
                         ┌──────────────┴──────────────┐
                         ▼                             ▼
              ┌────────────────────┐        ┌────────────────────┐
              │ Live CLI Output    │        │ JSONL Alert Log    │
              │ & Stats Dashboard  │        │ (ids_alerts.jsonl) │
              └────────────────────┘        └─────────┬──────────┘
                                                      │
                                                      ▼
                                            ┌────────────────────┐
                                            │ Web Dashboard      │
                                            │ (Flask + Chart.js) │
                                            └────────────────────┘
```

---

## 2. Core Components

### A. Live Packet Capture (`tshark`)
- Uses `tshark` (Wireshark CLI) to capture unbuffered packet header fields (`frame.len`, `ip.proto`, `tcp.flags`, `ip.src`, `ip.dst`, `tcp.srcport`, `tcp.dstport`, `ip.ttl`).
- Supports both live interface streaming and pre-recorded `.pcap` replay.

### B. Feature Preprocessing Pipeline (`FeatureBuilder`)
- Maps raw network attributes into the **122-feature NSL-KDD schema** defined in `columns.pkl`.
- Calculates rolling window metrics (same-host connection counts, error rates `serror_rate`, `rerror_rate`, service diversity).
- Applies binary/one-hot encoding for protocol types, services (70 classes), and TCP flags (11 states).

### C. Neural Network Inference (`fixed_model.keras` / `bilstm_ids.h5`)
- Accepts sequence tensors of shape `(batch_size, sequence_length, 122)`.
- 1D Convolution layer extracts spatial feature patterns across packets.
- Dual Bidirectional LSTM (BiLSTM) layers capture forward and backward sequence dependencies.
- Dense Softmax head outputs class probabilities across 5 categories: `NORMAL`, `DOS`, `PROBE`, `R2L`, and `U2R`.

### D. Alert System & Live Dashboard (`dashboard.py`)
- Real-time event streaming via `ids_alerts.jsonl`.
- Flask dashboard provides real-time traffic statistics, distribution charts, and alert logs.
