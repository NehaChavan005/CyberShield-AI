import streamlit as st
import pandas as pd
import joblib

# Load trained model
MODEL_PATH = "../model/cybershield_model.pkl"
clf = joblib.load(MODEL_PATH)

st.title("🔐 CyberShield-AI: Cyber Attack Detection Demo")

st.write("Upload traffic samples or enter values manually to detect if traffic is normal or an attack.")

# Input form
protocol = st.selectbox("Protocol", ["TCP", "UDP", "HTTP", "HTTPS", "DNS", "ARP"])
port = st.number_input("Port", min_value=0, max_value=65535, value=80)
packet_size = st.number_input("Packet Size (bytes)", min_value=1, max_value=5000, value=512)
request_rate = st.number_input("Request Rate (req/s)", min_value=0, max_value=10000, value=10)
failed_logins = st.number_input("Failed Logins", min_value=0, max_value=1000, value=0)

if st.button("Detect Attack"):
    # Build sample dataframe
    sample = pd.DataFrame([{
        "protocol": protocol,
        "port": port,
        "packet_size": packet_size,
        "request_rate": request_rate,
        "failed_logins": failed_logins
    }])

    prediction = clf.predict(sample)[0]
    if prediction == 1:
        st.error("⚠️ Attack Detected!")
    else:
        st.success("✅ Normal Traffic")
