import random
from datetime import datetime

from scapy.all import sniff

from utils.attack_predictor import predict_attack


def extract_features(packet):
    try:
        if packet.haslayer("TCP"):
            protocol = "TCP"
        elif packet.haslayer("UDP"):
            protocol = "UDP"
        else:
            protocol = "TCP"

        port = packet.dport if hasattr(packet, "dport") else 0
        packet_size = len(packet)
        request_rate = random.randint(1, 5000)
        failed_logins = random.randint(0, 5)
        traffic_type = "malicious" if request_rate > 1000 else "normal"

        attack_type = "none"
        if request_rate > 3000:
            attack_type = "dos"
        elif failed_logins > 3:
            attack_type = "bruteforce"

        source_ip = packet.src if hasattr(packet, "src") else "192.168.1.1"
        destination_ip = packet.dst if hasattr(packet, "dst") else "10.0.0.1"
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        return {
            "protocol": protocol,
            "port": port,
            "packet_size": packet_size,
            "request_rate": request_rate,
            "failed_logins": failed_logins,
            "traffic_type": traffic_type,
            "attack_type": attack_type,
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "timestamp": timestamp,
        }
    except Exception as exc:
        print("Feature extraction error:", exc)
        return None


def process_packet(packet):
    features = extract_features(packet)
    if not features:
        return

    try:
        result = predict_attack(features, auto_remediate=True)

        if result.get("error"):
            print("Prediction error:", result.get("error"))
            return

        if result.get("prediction") == 1:
            print("\nATTACK DETECTED")
            print("Traffic Data:", result.get("processed") or features)
            if result.get("incident_response"):
                print("Response:", result["incident_response"]["summary"])
        else:
            print("Normal traffic")
    except Exception as exc:
        print("Prediction error:", exc)


def start_monitoring():
    print("Starting Live Network Monitoring...\n")
    sniff(prn=process_packet, store=False)


if __name__ == "__main__":
    start_monitoring()
