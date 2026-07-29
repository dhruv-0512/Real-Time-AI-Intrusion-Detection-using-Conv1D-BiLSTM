<div align="center">

# Real-Time Intrusion Detection System

**BiLSTM-powered network threat detection.**

[![Python 3.8+](https://img.shields.io/badge/Python-3.8%2B-3776AB?logo=python&logoColor=white)](https://python.org)
[![TensorFlow](https://img.shields.io/badge/TensorFlow-2.12%2B-FF6F00?logo=tensorflow&logoColor=white)](https://tensorflow.org)
[![Flask](https://img.shields.io/badge/Flask-Dashboard-000000?logo=flask&logoColor=white)](https://flask.palletsprojects.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

*An end-to-end intrusion detection prototype using Conv1D + BiLSTM to classify network traffic across 5 threat categories in real time.*

</div>

---

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [Project Lineage](#2-project-lineage)
3. [Key Features](#3-key-features)
4. [System Architecture](#4-system-architecture)
5. [Repository Structure](#5-repository-structure)
6. [Technology Stack](#6-technology-stack)
7. [Installation](#7-installation)
8. [Usage (Live Mode)](#8-usage-live-mode)
9. [Usage (PCAP Replay)](#9-usage-pcap-replay)
10. [Dashboard](#10-dashboard)
11. [Results](#11-results)
12. [Limitations](#12-limitations)
13. [Future Work](#13-future-work)
14. [Contributors](#14-contributors)
15. [License](#15-license)

---

## 1. Project Overview

Modern networks generate millions of packets per hour, requiring automated analysis to filter noise and identify threats. This project bridges the gap between academic machine learning research and real-world security operations. 

It is an AI-powered intrusion detection system utilizing a **Conv1D + BiLSTM** deep learning model. The system captures live network traffic, extracts features, performs classification, and surfaces actionable alerts for security analysis.

## 2. Project Lineage

This repository extends an original academic project. The base model architecture and training dataset curation were developed collaboratively.

This repository primarily contains my individual contributions and engineering extensions, including:
- Real-time inference integration via live packet sniffing
- Flask web dashboard implementation
- PCAP replay support for offline testing
- Alert enrichment and visualization
- Alert deduplication and temporal confirmation pipelines
- Deployment improvements and TensorFlow/Keras compatibility fixes

## 3. Key Features

- **Real-Time Detection**: Live packet capture and classification via `tshark` with severity output.
- **BiLSTM Architecture**: 1D-CNN + dual Bidirectional LSTM layers to process temporal attack patterns.
- **5-Class Classification**: Detects DoS, Probe, R2L, U2R attacks, and Normal traffic.
- **Severity Scoring**: Prioritization levels (CRITICAL / HIGH / MEDIUM / LOW / INFO).
- **Temporal Confirmation**: Requires classification patterns to persist across multiple predictions to trigger an alert, reducing false positives.
- **Alert Deduplication**: Groups repeated alerts from the same source into single events with occurrence counts.
- **Enriched Alerts**: Includes source IP, destination IP, protocol, ports, severity, and confidence.
- **Demo Mode**: Reproducible demonstrations using pre-recorded packet captures.

## 4. System Architecture

```text
Network Traffic
|
v
TShark Packet Capture
|
v
Feature Extraction
|
v
122-D NSL-KDD Feature Vector
|
v
Conv1D + BiLSTM
|
v
Prediction
|
v
Temporal Confirmation
|
v
Severity Classification
|
v
Alert Logging
|
v
Flask Dashboard
```

## 5. Repository Structure

```text
Real-Time-AI-Intrusion-Detection-using-Conv1D-BiLSTM/
|-- realtime_ids.py               # Main real-time live IDS engine
|-- dashboard.py                  # Flask SOC web dashboard
|-- pcap_replay.py                # Replay packets from .pcap files
|-- convert_model.py              # Model format converter utility
|-- fix_model_compatibility.py    # TF/Keras version compatibility fixer
|-- fix_columns_pkl.py            # Rebuild columns.pkl for NumPy compat
|
|-- models/                       # Trained model artifacts (.keras, .h5, .pkl)
|-- data/                         # Sample packet capture files (.pcap)
|-- docs/                         # Extended markdown documentation
|-- screenshots/                  # UI and architecture visuals
|-- logs/                         # Runtime generated outputs
```

## 6. Technology Stack

| Layer | Technology |
|---|---|
| Core | Python 3.8+ |
| Deep Learning | TensorFlow, Keras |
| Data Processing | NumPy, Pandas, Joblib |
| Network Capture | tshark (Wireshark) |
| Web Interface | Flask, Tailwind CSS, Chart.js |

## 7. Installation

1. **Clone the Repository**
   ```bash
   git clone https://github.com/dhruv-0512/Real-Time-AI-Intrusion-Detection-using-Conv1D-BiLSTM.git
   cd Real-Time-AI-Intrusion-Detection-using-Conv1D-BiLSTM
   ```

2. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Verify tshark**
   Ensure Wireshark/tshark is installed and in your system PATH.
   ```bash
   tshark --version
   ```

## 8. Usage (Live Mode)

Run the IDS on live network traffic.

```bash
# List available network interfaces
python realtime_ids.py --list-ifaces

# Start IDS on a specific interface
python realtime_ids.py --iface 4
```

The engine captures packets, extracts features, applies temporal confirmation, and writes enriched JSONL alerts to `logs/ids_alerts.jsonl`.

## 9. Usage (PCAP Replay)

Test the system against pre-recorded packet captures without live traffic.

```bash
# Replay via Demo Mode on the main engine
python realtime_ids.py --demo data/normal_traffic.pcap

# Replay using the dedicated script
python pcap_replay.py --pcap data/normal_traffic.pcap
```

## 10. Dashboard

The Flask dashboard provides a visualization of detected threats reading from the generated JSONL log.

```bash
python dashboard.py
```
Open `http://localhost:5000` in your browser.

**Features:**
- System Health & Uptime Status
- Live Enriched Alert Feed
- Deduplicated Alert Grouping View
- Attack Timeline Chart
- Threat Distribution Doughnut

*[Placeholder: screenshots/dashboard.png]*
*[Placeholder: screenshots/dashboard.gif]*
*[Placeholder: screenshots/alerts.png]*
*[Placeholder: screenshots/architecture.png]*

## 11. Results

The following evaluation metrics correspond exclusively to the NSL-KDD benchmark dataset test set, and may not necessarily reflect performance on real-world enterprise traffic:

- **Overall Accuracy**: 99.16%
- **Misclassification Rate**: 0.84%
- **False Positive Rate**: 0.83%
- **DoS Detection Rate**: 99.84%
- **Probe Detection Rate**: 98.98%

## 12. Limitations

- **Dataset Age**: The model is trained on NSL-KDD. While academically rigorous, it does not fully encompass modern enterprise traffic patterns.
- **U2R Detection**: User-to-Root detection accuracy is limited by the sparse number of training examples (52) in the source dataset.
- **Throughput**: Python's GIL and subprocess overhead with `tshark` constrain analysis to moderate bandwidth links. High-speed gigabit line-rate processing would necessitate a C/Rust packet hook rewrite.

## 13. Future Work

- **Dataset Upgrades**: Retraining the model on modern datasets such as CICIDS2017 or UNSW-NB15.
- **Advanced Architectures**: Experimenting with Attention-based architectures and transformers for sequence modeling.
- **Deployment**: Containerization using Docker for isolated, reproducible deployments.
- **Streaming pipelines**: Integrating Kafka streaming for robust, distributed packet ingestion.
- **SIEM Integration**: Implementing native webhook and API support for Splunk, Elastic, and other enterprise SIEM platforms.

## 14. Contributors

The original model development and initial dataset feature engineering were completed as part of a collaborative academic project. 

This repository focuses on my individual engineering extensions, real-time inference integration, and system implementation work.

## 15. License

This project is licensed under the [MIT License](LICENSE).
