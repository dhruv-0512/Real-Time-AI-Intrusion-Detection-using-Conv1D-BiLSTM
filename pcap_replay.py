"""
pcap_replay.py - Replay pre-recorded network capture files (PCAP) through the BiLSTM IDS.

Parses packets from a .pcap file using tshark (or scapy as fallback), converts them into
122-feature NSL-KDD vectors via FeatureBuilder, feeds them to the BiLSTM model,
and outputs predictions to the console, ids_log.txt, and ids_alerts.jsonl.

USAGE:
    python pcap_replay.py
    python pcap_replay.py --pcap normal_traffic.pcap
    python pcap_replay.py --pcap custom_traffic.pcap --model fixed_model.keras --delay 0.05
"""

import argparse
import os
import subprocess
import sys
import time
from datetime import datetime

import joblib
import numpy as np

# Optional colorama
try:
    from colorama import init as colorama_init, Fore, Style
    colorama_init(autoreset=True)
    _HAS_COLOR = True
except ImportError:
    _HAS_COLOR = False
    class _Stub:
        def __getattr__(self, _): return ""
    Fore = Style = _Stub()

# Import helper functionality from realtime_ids if available
try:
    from realtime_ids import (
        FeatureBuilder, TSHARK_FIELDS,
        parse_tshark_line, LABELS, LABEL_COLOR, write_alert, setup_logging
    )
except ImportError:
    # Fallback definition if realtime_ids import fails
    LABELS = ["DOS", "NORMAL", "PROBE", "R2L", "U2R"]
    LABEL_COLOR = {
        "NORMAL": Fore.GREEN,
        "DOS": Fore.RED,
        "PROBE": Fore.YELLOW,
        "R2L": Fore.MAGENTA,
        "U2R": Fore.CYAN,
    }


def compute_severity(label: str, confidence: float) -> str:
    if label == "NORMAL":
        return "INFO"
    if confidence > 0.85:
        return "CRITICAL" if label in ("U2R", "R2L") else "HIGH"
    if confidence > 0.60:
        return "MEDIUM"
    return "LOW"


def parse_args():
    parser = argparse.ArgumentParser(description="BiLSTM IDS - PCAP Replay Mode")
    pcap_default = os.path.join("data", "normal_traffic.pcap") if os.path.exists(os.path.join("data", "normal_traffic.pcap")) else "normal_traffic.pcap"
    model_default = os.path.join("models", "fixed_model.keras") if os.path.exists(os.path.join("models", "fixed_model.keras")) else (os.path.join("models", "bilstm_ids.h5") if os.path.exists(os.path.join("models", "bilstm_ids.h5")) else "fixed_model.keras")
    columns_default = os.path.join("models", "columns.pkl") if os.path.exists(os.path.join("models", "columns.pkl")) else "columns.pkl"
    alert_default = os.path.join("logs", "ids_alerts.jsonl")
    log_default = os.path.join("logs", "ids_log.txt")

    parser.add_argument("--pcap", type=str, default=pcap_default, help="Path to PCAP file")
    parser.add_argument("--model", type=str, default=model_default, help="Path to Keras model (.keras or .h5)")
    parser.add_argument("--columns", type=str, default=columns_default, help="Path to columns.pkl schema")
    parser.add_argument("--alert-file", type=str, default=alert_default, help="Alert log destination")
    parser.add_argument("--log-file", type=str, default=log_default, help="Runtime log file destination")
    parser.add_argument("--tshark-path", type=str, default=r"C:\Program Files\Wireshark\tshark.exe", help="Path to tshark executable")
    parser.add_argument("--delay", type=float, default=0.01, help="Delay between replayed packets in seconds")
    return parser.parse_args()


def main():
    args = parse_args()
    logger = setup_logging(args.log_file)

    print(Fore.CYAN + r"""
  +==========================================================+
  |    BiLSTM Intrusion Detection System - PCAP Replay      |
  |    Replaying packet capture & evaluating threats        |
  +==========================================================+
""" + Style.RESET_ALL)

    if not os.path.exists(args.pcap):
        logger.error(f"PCAP file not found: {args.pcap}")
        sys.exit(1)

    import tensorflow as tf

    logger.info(f"Loading model: {args.model}")
    model_path = args.model if os.path.exists(args.model) else os.path.join("models", "bilstm_ids.h5")
    try:
        model = tf.keras.models.load_model(model_path)
        logger.info(f"Model loaded successfully from {model_path}")
    except Exception as e:
        logger.critical(f"Failed to load model {model_path}: {e}")
        sys.exit(1)

    logger.info(f"Loading columns schema: {args.columns}")
    try:
        columns = joblib.load(args.columns)
        builder = FeatureBuilder(columns)
        logger.info(f"Loaded schema with {len(columns)} features")
    except Exception as e:
        logger.critical(f"Failed to load columns {args.columns}: {e}")
        sys.exit(1)

    # Build tshark command to read PCAP file
    tshark_bin = args.tshark_path if os.path.exists(args.tshark_path) else "tshark"
    cmd = [tshark_bin, "-r", args.pcap, "-T", "fields", "-E", "separator=|", "-E", "occurrence=f", "-E", "quote=n"]
    for f in TSHARK_FIELDS:
        cmd += ["-e", f]

    logger.info(f"Reading packets from: {args.pcap}")
    
    packet_count = 0
    buffer = []
    
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        for line in proc.stdout:
            line = line.strip()
            if not line:
                continue

            raw = parse_tshark_line(line)
            vec = builder.packet_to_vector(raw)
            buffer.append(vec)
            packet_count += 1

            WINDOW_SIZE = 122
            SLIDE = 30
            if len(buffer) >= WINDOW_SIZE:
                window = np.stack(buffer[-WINDOW_SIZE:], axis=0)
                window = window.mean(axis=1)
                x = window.reshape(1, WINDOW_SIZE, 1)
                preds = model.predict(x, verbose=0)[0]
                idx = np.argmax(preds)
                label = LABELS[idx]
                conf = float(preds[idx])

                color = LABEL_COLOR.get(label, "")
                badge = f"[{label:6s}]"
                conf_s = f"{conf*100:5.1f}%"
                severity = compute_severity(label, conf)
                print(f"  Replay Pkt #{packet_count:>5}: [{severity:8s}] {color}{badge}{Style.RESET_ALL} conf={conf_s}")

                # Log alert payload
                payload = {
                    "ts": datetime.now().isoformat(),
                    "label": label,
                    "severity": severity,
                    "confidence": round(conf, 4),
                    "src_ip": raw.get("src_ip", "0.0.0.0"),
                    "dst_ip": raw.get("dst_ip", "0.0.0.0"),
                    "protocol": raw.get("ip_proto", "6"),
                    "src_port": raw.get("src_port", "0"),
                    "dst_port": raw.get("dst_port", "0"),
                    "pkt_count": packet_count,
                    "confirmed": True,
                    "occurrences": 1,
                }
                write_alert(args.alert_file, payload)
                
                buffer = buffer[SLIDE:]  # slide window

            if args.delay > 0:
                time.sleep(args.delay)

        proc.wait()

        # Handle remaining buffer or small PCAP files < 122 packets
        if len(buffer) > 0:
            WINDOW_SIZE = 122
            padded_buffer = buffer[:]
            while len(padded_buffer) < WINDOW_SIZE:
                padded_buffer.append(padded_buffer[-1] if padded_buffer else np.zeros(122))
            window = np.stack(padded_buffer[-WINDOW_SIZE:], axis=0)
            window = window.mean(axis=1)
            x = window.reshape(1, WINDOW_SIZE, 1)
            preds = model.predict(x, verbose=0)[0]
            idx = np.argmax(preds)
            label = LABELS[idx]
            conf = float(preds[idx])
            color = LABEL_COLOR.get(label, "")
            badge = f"[{label:6s}]"
            conf_s = f"{conf*100:5.1f}%"
            severity = compute_severity(label, conf)
            print(f"  Replay Final Batch ({packet_count} pkts): [{severity:8s}] {color}{badge}{Style.RESET_ALL} conf={conf_s}")
            payload = {
                "ts": datetime.now().isoformat(),
                "label": label,
                "severity": severity,
                "confidence": round(conf, 4),
                "src_ip": last_raw.get("src_ip", "0.0.0.0") if 'last_raw' in locals() else "0.0.0.0",
                "dst_ip": last_raw.get("dst_ip", "0.0.0.0") if 'last_raw' in locals() else "0.0.0.0",
                "protocol": last_raw.get("ip_proto", "6") if 'last_raw' in locals() else "6",
                "src_port": last_raw.get("src_port", "0") if 'last_raw' in locals() else "0",
                "dst_port": last_raw.get("dst_port", "0") if 'last_raw' in locals() else "0",
                "pkt_count": packet_count,
                "confirmed": True,
                "occurrences": 1,
            }
            write_alert(args.alert_file, payload)
        logger.info(f"PCAP Replay completed. Processed {packet_count} packets.")

    except Exception as e:
        logger.error(f"Error during PCAP replay: {e}")

if __name__ == "__main__":
    main()
