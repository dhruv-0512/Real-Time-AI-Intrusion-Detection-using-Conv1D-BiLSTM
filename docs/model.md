# BiLSTM Intrusion Detection Model Architecture & Performance

This document describes the deep learning model architecture, training background, NSL-KDD dataset feature mapping, and performance metrics.

---

## 1. Model Architecture

The neural network utilizes a hybrid **1D-CNN + Bidirectional LSTM** architecture for sequence-based classification of packet flows.

| Layer Type | Configuration / Units | Details |
|---|---|---|
| **Input Layer** | `(30, 122)` | Window of 30 contiguous packet feature vectors |
| **Conv1D** | 64 Filters, Kernel Size 3, ReLU | Extracts short-term local pattern correlations |
| **MaxPooling1D** | Pool Size 2 | Downsamples feature maps |
| **Batch Normalization** | Default | Stabilizes gradient distributions |
| **BiLSTM Layer 1** | 64 Units (Bidirectional) | Forward and backward temporal sequence learning |
| **BiLSTM Layer 2** | 32 Units (Bidirectional) | Higher-level sequential dependency extraction |
| **Dense** | 32 Units, ReLU | Fully connected feature consolidation |
| **Output Layer** | 5 Units, Softmax | Multi-class probability distribution |

---

## 2. Target Classes

1. **NORMAL**: Benign network traffic (HTTP, DNS, SSH, SSL/TLS sessions).
2. **DoS (Denial of Service)**: Flooding attacks designed to crash or overload services (Neptune, Smurf, Teardrop, Pod).
3. **Probe (Reconnaissance)**: Port scanning and network probing (Nmap, Portsweep, Ipsweep, Satan).
4. **R2L (Remote to Local)**: Unauthorized access attempts from a remote machine (Guess_passwd, FTP_write, Imap, Warezmaster).
5. **U2R (User to Root)**: Privilege escalation attacks attempting to gain root access (Buffer_overflow, Rootkit, Loadmodule).

---

## 3. Training & Evaluation Metrics

Evaluated on the benchmark **NSL-KDD dataset** (125,973 training records, 22,544 test records):

- **Overall Accuracy**: 99.16%
- **Misclassification Rate**: 0.84%
- **False Positive Rate**: 0.83%
- **DoS Detection Accuracy**: 99.84%
- **Probe Detection Accuracy**: 98.98%
- **R2L Detection Accuracy**: 91.73%
- **U2R Detection Accuracy**: 36.84% (limited training sample size)

---

## 4. Preprocessing Schema (`columns.pkl`)

The model relies on `columns.pkl` containing 122 normalized column identifiers:
- **0–18**: Numeric flow statistics (`duration`, `src_bytes`, `dst_bytes`, error flags, login indicators)
- **19–37**: Windowed connection metrics (`count`, `srv_count`, `serror_rate`, `rerror_rate`, host counts)
- **38–40**: One-hot protocol flags (`protocol_type_tcp`, `protocol_type_udp`, `protocol_type_icmp`)
- **41–110**: One-hot service classifications (70 distinct services)
- **111–121**: One-hot TCP flag combinations (`SF`, `S0`, `REJ`, `RSTO`, `RSTR`, etc.)
