import os
import sys
import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
import pydeck as pdk
from streamlit_autorefresh import st_autorefresh

# Project path fix
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

# Import existing modules
from auth.streamlit_auth import logout_button, require_login
from utils.attack_predictor import predict_attack

# ------------------ PAGE CONFIG ------------------
st.set_page_config(page_title="CyberShield Dashboard", layout="wide")

# Auto refresh
st_autorefresh(interval=5000, key="refresh")

# ------------------ STYLING ------------------
st.markdown("""
<style>
body {
    background-color: #0d1117;
    color: white;
}
.glass {
    background: rgba(255,255,255,0.08);
    border-radius: 12px;
    padding: 16px;
    backdrop-filter: blur(6px);
}
</style>
""", unsafe_allow_html=True)

# ------------------ AUTH ------------------
user = require_login()

st.title("🛡️ CyberShield AI Threat Monitoring")
st.caption(f"Signed in as {user.get('username', 'unknown')}")
logout_button()

# ------------------ TOP METRICS ------------------
col1, col2, col3 = st.columns(3)

col1.metric("⚠️ Threat Level", "HIGH")
col2.metric("🧠 Active Attacks", np.random.randint(5, 30))
col3.metric("🔒 System Status", "SECURE")

# ------------------ ATTACK TIMELINE ------------------
st.subheader("📊 Attack Timeline")

time = pd.date_range(start='now', periods=50, freq='min')
attacks = np.random.randint(5, 25, size=50)

df = pd.DataFrame({"Time": time, "Attacks": attacks})

fig = px.line(df, x="Time", y="Attacks",
              template="plotly_dark",
              title="Real-Time Attack Activity")

st.plotly_chart(fig, use_container_width=True)

# ------------------ SIMULATION INPUT ------------------
st.header("Simulate Network Traffic")

protocol = st.selectbox("Protocol", ["TCP", "UDP", "HTTP", "HTTPS", "DNS"])
port = st.number_input("Port", value=80)
packet_size = st.slider("Packet Size", 100, 1500, 500)
request_rate = st.slider("Request Rate", 1, 5000, 100)
failed_logins = st.slider("Failed Logins", 0, 50, 0)

traffic_type = st.selectbox("Traffic Type", ["normal", "suspicious"])
attack_type = st.selectbox(
    "Attack Type",
    ["none", "DDoS", "Brute Force", "SQL Injection", "XSS", "Port Scan"],
)

# ------------------ ANALYSIS ------------------
if st.button("Analyze Traffic"):

    sample = {
        "protocol": protocol,
        "port": port,
        "packet_size": packet_size,
        "request_rate": request_rate,
        "failed_logins": failed_logins,
        "malware_signature": "none",
        "traffic_type": traffic_type,
        "attack_type": attack_type,
    }

    result = predict_attack(sample)

    if result.get("error"):
        st.error(f"Prediction failed: {result['error']}")
    else:
        colA, colB = st.columns(2)

        # -------- RESULT STATUS --------
        with colA:
            if result.get("prediction") == 1:
                st.error("🚨 Cyber attack detected")
            else:
                st.success("✅ Normal traffic")

        # -------- RISK GAUGE --------
        with colB:
            risk_value = np.random.randint(1, 10)

            gauge = go.Figure(go.Indicator(
                mode="gauge+number",
                value=risk_value,
                title={'text': "Risk Score"},
                gauge={
                    'axis': {'range': [0, 10]},
                    'bar': {'color': "red"},
                    'steps': [
                        {'range': [0, 3], 'color': "green"},
                        {'range': [3, 7], 'color': "yellow"},
                        {'range': [7, 10], 'color': "red"},
                    ],
                }
            ))

            st.plotly_chart(gauge, use_container_width=True)

        # -------- AI OUTPUT PANEL --------
        st.markdown('<div class="glass">', unsafe_allow_html=True)

        st.subheader("Risk Level")
        st.write(result.get("ai_analysis", {}).get("risk_level"))

        st.subheader("Detected Attack Type")
        st.write(result.get("processed", {}).get("attack_type", "unknown"))

        st.subheader("AI Explanation")
        st.write(result.get("ai_analysis", {}).get("explanation"))

        st.subheader("Recommended Remediation")
        st.write(result.get("ai_analysis", {}).get("remediation"))

        st.subheader("Detailed Security Report")
        st.code(result.get("llm_security_report", ""))

        st.markdown("</div>", unsafe_allow_html=True)

# ------------------ MAP + ALERTS ------------------
colX, colY = st.columns(2)

# -------- GEO MAP --------
with colX:
    st.subheader("🌍 Attack Locations")

    map_data = pd.DataFrame({
        'lat': [28.6, 40.7, 51.5, 35.6],
        'lon': [77.2, -74.0, -0.1, 139.6],
        'size': [200, 300, 150, 400]
    })

    layer = pdk.Layer(
        "ScatterplotLayer",
        data=map_data,
        get_position='[lon, lat]',
        get_radius='size',
        get_fill_color='[255, 0, 0, 160]',
    )

    view_state = pdk.ViewState(latitude=20, longitude=0, zoom=1)

    st.pydeck_chart(pdk.Deck(layers=[layer], initial_view_state=view_state))

# -------- ALERTS --------
with colY:
    st.subheader("🚨 Live Alerts")

    alerts = [
        "SQL Injection detected",
        "DDoS attack detected",
        "Brute force blocked",
        "Malware upload attempt"
    ]

    for alert in alerts:
        st.error(alert)

# ------------------ PIE CHART ------------------
st.subheader("📊 Attack Distribution")

attack_types = ["DDoS", "SQL Injection", "Malware", "Phishing"]
values = np.random.randint(10, 50, size=4)

pie = px.pie(names=attack_types, values=values, template="plotly_dark")
st.plotly_chart(pie, use_container_width=True)