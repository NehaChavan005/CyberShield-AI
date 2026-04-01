import os
import random
import sys


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
    if isinstance(packet, dict):
        data = packet
    else:
        data = {
            "protocol": "TCP",
            "port": getattr(packet, "dport", 80),
            "packet_size": len(packet),
            "request_rate": 100,
            "failed_logins": 0,
            "malware_signature": "none",
            "traffic_type": "suspicious",
            "attack_type": "Port Scan",
            "dataset_source": "live",
            "source_ip": getattr(packet, "src", None),
            "destination_ip": getattr(packet, "dst", None),
        }

    result = predict_attack(data, auto_remediate=True)

    if result.get("error"):
        print("Prediction error:", result["error"])
        return

    if result.get("prediction") == 1:
        print("\nALERT: Attack detected")
        print("Details:", result.get("processed"))
        print("Risk:", result.get("ai_analysis", {}).get("risk_level"))
        if result.get("incident_response"):
            print("Response:", result["incident_response"]["summary"])
    else:
        print("NORMAL")


def start_monitor(simulate=False, count=10):
    print("Monitoring network traffic...")
    if simulate or not SCAPY_AVAILABLE:
        print("Running in simulated mode (no scapy).")
        for _ in range(count):
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
                "dataset_source": "simulated",
                "source_ip": f"45.23.12.{random.randint(10, 250)}",
                "destination_ip": "10.0.0.5",
            }
            process_packet(pkt)
    else:
        sniff(prn=process_packet, count=count)


if __name__ == "__main__":
    start_monitor(simulate=not SCAPY_AVAILABLE, count=10)
