import sys
import os
import random
from datetime import datetime

# Ensure project root is importable
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

try:
    from scapy.all import sniff
    SCAPY_AVAILABLE = True
except Exception:
    SCAPY_AVAILABLE = False

from utils.attack_predictor import predict_attack


def process_packet(packet):
    # If this was a scapy packet, len(packet) will be packet length; when simulated packet is passed
    # we may pass an int or dict. Handle both.
    if isinstance(packet, dict):
        data = packet
    else:
        data = {
            "protocol": "TCP",
            "port": getattr(packet, 'dport', 80),
            "packet_size": len(packet),
            "request_rate": 100,
            "failed_logins": 0,
            "malware_signature": "none",
            "traffic_type": "suspicious",
            "attack_type": "Port Scan",
            "dataset_source": "live"
        }

    result = predict_attack(data)

    if result.get("error"):
        print("Prediction error:", result["error"])
        return

    if result.get("prediction") == 1:
        print("\n🚨 ALERT: Attack detected")
        print("Details:", result.get("processed"))
        print("Risk:", result.get("ai_analysis", {}).get("risk_level"))
    else:
        print("✅ NORMAL")


def start_monitor(simulate=False, count=10):
    print("📡 Monitoring network traffic...")
    if simulate or not SCAPY_AVAILABLE:
        print("Running in simulated mode (no scapy).")
        for _ in range(count):
            # create a fake packet dict
            req_rate = random.randint(1, 5000)
            pkt = {
                "protocol": random.choice(["TCP", "UDP"]),
                "port": random.choice([22, 80, 443, 8080]),
                "packet_size": random.randint(64, 1500),
                "request_rate": req_rate,
                "failed_logins": random.randint(0, 5),
                "malware_signature": "none",
                "traffic_type": "suspicious" if req_rate > 1000 else "normal",
                "attack_type": "DDoS" if req_rate > 3000 else "none",
                "dataset_source": "simulated"
            }
            process_packet(pkt)
    else:
        sniff(prn=process_packet, count=count)


if __name__ == "__main__":
    # If scapy is unavailable, run simulated mode automatically
    start_monitor(simulate=not SCAPY_AVAILABLE, count=10)
