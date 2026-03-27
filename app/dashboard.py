import streamlit as st
from utils.attack_predictor import predict_attack

st.title("🛡 CyberShield AI Threat Monitoring")

st.header("Simulate Network Traffic")

protocol = st.selectbox("Protocol", ["TCP","UDP","HTTP","HTTPS","DNS"])
port = st.number_input("Port", value=80)
packet_size = st.slider("Packet Size", 100,1500,500)
request_rate = st.slider("Request Rate",1,5000,100)
failed_logins = st.slider("Failed Logins",0,50,0)

traffic_type = st.selectbox("Traffic Type",["normal","suspicious"])
attack_type = st.selectbox("Attack Type",[
    "none","DDoS","Brute Force","SQL Injection","XSS","Port Scan"
])

if st.button("Analyze Traffic"):

    sample = {
        "protocol": protocol,
        "port": port,
        "packet_size": packet_size,
        "request_rate": request_rate,
        "failed_logins": failed_logins,
        "malware_signature": "none",
        "traffic_type": traffic_type,
        "attack_type": attack_type
    }

    result = predict_attack(sample)

    if result["prediction"] == 1:
        st.error("🚨 Cyber Attack Detected")
    else:
        st.success("✅ Normal Traffic")

    st.subheader("📊 Risk Level")
    st.write(result["ai_analysis"]["risk_level"])

    st.subheader("🤖 AI Explanation")
    st.write(result["ai_analysis"]["explanation"])

    st.subheader("🛡 Recommended Remediation")
    st.write(result["ai_analysis"]["remediation"])

    st.subheader("📄 AI Security Report")
    st.write(result["llm_security_report"])