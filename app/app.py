import sys
import os
# Ensure project root is on sys.path so `from utils` works when running via streamlit
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import streamlit as st
import pandas as pd
from utils.attack_predictor import predict_attack

st.title("🔐 CyberShield-AI: Cyber Attack Detection Demo")

st.write("Upload traffic samples or enter values manually to detect if traffic is normal or an attack.")

# Input form
protocol = st.selectbox("Protocol", ["TCP", "UDP", "HTTP", "HTTPS", "DNS", "ARP"])
port = st.number_input("Port", min_value=0, max_value=65535, value=80)
packet_size = st.number_input("Packet Size (bytes)", min_value=1, max_value=5000, value=512)
request_rate = st.number_input("Request Rate (req/s)", min_value=0, max_value=10000, value=10)
failed_logins = st.number_input("Failed Logins", min_value=0, max_value=1000, value=0)

if st.button("Detect Attack"):
    sample = {
        "protocol": protocol,
        "port": port,
        "packet_size": packet_size,
        "request_rate": request_rate,
        "failed_logins": failed_logins,
    }

    result = predict_attack(sample)

    if result.get("error"):
        st.error(f"Prediction error: {result['error']}")
    else:
        if result.get("prediction") == 1:
            st.error("⚠️ Attack Detected!")
        else:
            st.success("✅ Normal Traffic")
