import os
import sys

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import streamlit as st
import pandas as pd

from auth.streamlit_auth import auth_page, logout_button, open_signup_page
from utils.attack_predictor import predict_attack
from utils.threat_intelligence import add_to_blacklist, enrich_threat_intelligence, load_blacklist_db


st.set_page_config(
    page_title="CyberShield-AI",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(
    """
    <style>
  @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=Orbitron:wght@500;700&display=swap');

  .stApp {
    background:
      radial-gradient(circle at top left, rgba(0, 255, 255, 0.14), transparent 28%),
      radial-gradient(circle at top right, rgba(0, 255, 159, 0.10), transparent 24%),
      radial-gradient(circle at bottom center, rgba(0, 180, 255, 0.12), transparent 34%),
      linear-gradient(140deg, #05070b 0%, #09111f 44%, #04141d 100%);
    color: #ffffff;
    font-family: 'Inter', sans-serif;
  }
  h1, h2, h3, .auth-title {
    font-family: 'Orbitron', 'Inter', sans-serif;
    letter-spacing: 0.04em;
  }
  section[data-testid="stSidebar"] {
    background: rgba(6, 16, 26, 0.82);
    border-right: 1px solid rgba(255,255,255,0.10);
    backdrop-filter: blur(18px);
    -webkit-backdrop-filter: blur(18px);
  }
  section[data-testid="stSidebar"] * {
    color: #ffffff;
  }
  .stTextInput input, .stNumberInput input, .stTextArea textarea, .stSelectbox div[data-baseweb="select"] > div {
    background: rgba(255,255,255,0.06);
    border: 1px solid rgba(255,255,255,0.10);
    border-radius: 14px;
    color: #ffffff;
    backdrop-filter: blur(12px);
  }
  .stButton > button {
    background: linear-gradient(135deg, rgba(0,255,255,0.20), rgba(0,255,159,0.18));
    color: #ffffff;
    border: 1px solid rgba(0,255,255,0.28);
    border-radius: 14px;
    box-shadow: 0 0 18px rgba(0,255,255,0.14);
    transition: all 0.2s ease;
  }
  .stButton > button:hover {
    border-color: rgba(0,255,159,0.60);
    box-shadow: 0 0 24px rgba(0,255,159,0.22);
    transform: translateY(-1px);
  }
  div[data-testid="stMetric"] {
    background: rgba(255,255,255,0.06);
    border: 1px solid rgba(255,255,255,0.10);
    border-radius: 18px;
    padding: 14px;
    backdrop-filter: blur(14px);
    box-shadow: 0 0 20px rgba(0,255,255,0.08);
  }
  .glass {
    background: rgba(255,255,255,0.08);
    border-radius: 18px;
    padding: 20px;
    box-shadow: 0 0 24px rgba(0,255,255,0.10), 0 16px 40px rgba(0,0,0,0.28);
    backdrop-filter: blur(16px);
    -webkit-backdrop-filter: blur(16px);
    border: 1px solid rgba(255,255,255,0.10);
  }
  .hero {
    padding: 24px;
    border-radius: 22px;
    background: rgba(255,255,255,0.06);
    border: 1px solid rgba(255,255,255,0.10);
    margin-bottom: 20px;
    backdrop-filter: blur(18px);
    -webkit-backdrop-filter: blur(18px);
    box-shadow: 0 0 30px rgba(0,255,255,0.10);
  }
  .metric-card {
    padding: 16px;
    border-radius: 16px;
    background: rgba(255,255,255,0.06);
    border: 1px solid rgba(255,255,255,0.10);
    color: #ffffff;
    backdrop-filter: blur(14px);
  }
  .panel-critical {
    box-shadow: 0 0 26px rgba(255,77,77,0.22), 0 16px 40px rgba(0,0,0,0.28);
    border: 1px solid rgba(255,77,77,0.34);
  }
  .panel-normal {
    box-shadow: 0 0 26px rgba(0,255,159,0.18), 0 16px 40px rgba(0,0,0,0.28);
    border: 1px solid rgba(0,255,159,0.28);
  }
  .auth-shell {
    max-width: 520px;
    margin: 4vh auto 0 auto;
    text-align: center;
  }
  .auth-title {
    font-size: 2rem;
    color: #ffffff;
    margin-bottom: 1rem;
    text-shadow: 0 0 18px rgba(0,255,255,0.22);
  }
  .auth-card {
    background: rgba(255,255,255,0.08);
    border: 1px solid rgba(255,255,255,0.10);
    border-radius: 20px;
    padding: 24px;
    backdrop-filter: blur(18px);
    -webkit-backdrop-filter: blur(18px);
    box-shadow: 0 0 24px rgba(0,255,255,0.12), 0 16px 40px rgba(0,0,0,0.28);
  }
  .auth-card-title {
    font-size: 1.1rem;
    color: #00ffff;
    margin-bottom: 0.75rem;
    font-weight: 700;
  }
  .page-heading {
    margin-bottom: 14px;
  }
  .ti-status-clean {
    color: #00ff9f;
    font-weight: 700;
  }
  .ti-status-bad {
    color: #ff4d4d;
    font-weight: 700;
  }
    </style>
    """,
    unsafe_allow_html=True,
)


def infer_indicator_type(value: str) -> str:
    candidate = str(value or "").strip()
    if not candidate:
        return "ip"
    if candidate.count(".") == 3 and all(part.isdigit() for part in candidate.split(".")):
        return "ip"
    if len(candidate) in {32, 40, 64} and all(ch in "0123456789abcdefABCDEF" for ch in candidate):
        return "hash"
    if "." in candidate and "/" not in candidate and " " not in candidate:
        return "domain"
    return "domain"


def render_public_auth() -> None:
    return None


def render_overview(user: dict) -> None:
    blacklist_db = load_blacklist_db()
    st.markdown(
        f"""
        <div class="hero">
          <h1>Security Operations Dashboard</h1>
          <p>Welcome back, <strong>{user.get('full_name') or user.get('username')}</strong>.</p>
        </div>
        """,
        unsafe_allow_html=True,
    )
    cols = st.columns(4)
    cols[0].metric("Blacklisted IPs", len(blacklist_db.get("ips", {})))
    cols[1].metric("Blacklisted Domains", len(blacklist_db.get("domains", {})))
    cols[2].metric("Blacklisted Hashes", len(blacklist_db.get("hashes", {})))
    cols[3].metric("History Entries", len(blacklist_db.get("history", [])))


def render_simulation_page(user: dict) -> None:
    st.markdown('<div class="page-heading"><h1>Simulate Network Traffic</h1></div>', unsafe_allow_html=True)
    st.caption(f"Signed in as {user.get('username', 'unknown')}")

    col1, col2 = st.columns([1.2, 1], gap="large")
    with col1:
        st.markdown('<div class="glass">', unsafe_allow_html=True)
        protocol = st.selectbox("Protocol", ["TCP", "UDP", "HTTP", "HTTPS", "DNS"], key="sim_protocol")
        port = st.number_input("Port", value=80, key="sim_port")
        packet_size = st.slider("Packet Size", 100, 1500, 500, key="sim_packet")
        request_rate = st.slider("Request Rate", 1, 5000, 100, key="sim_rate")
        failed_logins = st.slider("Failed Logins", 0, 50, 0, key="sim_failed")
        source_ip = st.text_input("Source IP", value="45.23.12.11", key="sim_source_ip")
        destination_ip = st.text_input("Destination IP", value="10.0.0.25", key="sim_dest_ip")
        suspicious_pid = st.text_input("Suspicious PID", value="", key="sim_pid")
        suspicious_process_name = st.text_input("Suspicious Process Name", value="", key="sim_process")
        malware_signature = st.text_input("Malware Signature / Domain", value="none", key="sim_signature")
        auto_remediate = st.checkbox("Enable automated incident response", value=False, key="sim_auto")
        st.markdown('</div>', unsafe_allow_html=True)

    with col2:
        st.markdown('<div class="glass">', unsafe_allow_html=True)
        traffic_type = st.selectbox("Traffic Type", ["normal", "suspicious"], key="sim_traffic")
        attack_type = st.selectbox(
            "Attack Type",
            ["none", "DDoS", "Brute Force", "SQL Injection", "XSS", "Port Scan"],
            key="sim_attack",
        )
        st.info("To see firewall and process actions, enable automated incident response and provide a valid source IP plus a real suspicious PID or process name.")
        st.markdown('</div>', unsafe_allow_html=True)

    if st.button("Analyze Traffic", type="primary", use_container_width=True):
        sample = {
            "protocol": protocol,
            "port": port,
            "packet_size": packet_size,
            "request_rate": request_rate,
            "failed_logins": failed_logins,
            "malware_signature": malware_signature,
            "traffic_type": traffic_type,
            "attack_type": attack_type,
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "suspicious_pid": int(suspicious_pid) if suspicious_pid.strip().isdigit() else None,
            "suspicious_process_name": suspicious_process_name.strip() or None,
        }

        result = predict_attack(sample, auto_remediate=auto_remediate)
        st.session_state["latest_simulation_result"] = result

    result = st.session_state.get("latest_simulation_result")
    if not result:
        return

    if result.get("error"):
        st.error(f"Prediction failed: {result['error']}")
        return

    if result.get("prediction") == 1:
        st.error("Cyber attack detected")
    elif result.get("ai_analysis", {}).get("policy_override"):
        st.warning("High-risk traffic detected by policy override")
    else:
        st.success("Normal traffic")

    analysis_class = "panel-critical" if str(result.get("ai_analysis", {}).get("risk_level", "")).upper() in {"CRITICAL", "HIGH"} else "panel-normal"
    st.markdown(f'<div class="glass {analysis_class}">', unsafe_allow_html=True)
    st.subheader("Analysis Summary")
    st.write(f"Risk Level: {result.get('ai_analysis', {}).get('risk_level')}")
    st.write(f"Attack Type: {result.get('ai_analysis', {}).get('attack_type', 'unknown')}")
    st.write(result.get("ai_analysis", {}).get("explanation"))
    st.write(f"Recommended remediation: {result.get('ai_analysis', {}).get('remediation')}")

    threat_intel = result.get("threat_intelligence") or {}
    st.subheader("Threat Intelligence")
    st.write(f"Highest intel score: {threat_intel.get('highest_score', 0)}")
    st.write(f"Blacklist match: {'Yes' if threat_intel.get('blacklist_match') else 'No'}")
    for indicator in threat_intel.get("indicators", []):
        st.markdown(
            f"- `{indicator.get('type')}` `{indicator.get('value')}` | severity `{indicator.get('severity')}` | score `{indicator.get('score')}`"
        )

    if result.get("blacklist_updates"):
        st.subheader("Blacklist Updates")
        for entry in result["blacklist_updates"]:
            st.write(f"Added `{entry.get('value')}` to the blacklist from `{entry.get('source')}`.")

    if result.get("incident_response"):
        st.subheader("Automated Response")
        st.write(result["incident_response"]["summary"])
        for index, action in enumerate(result["incident_response"].get("actions", []), start=1):
            st.markdown(
                f"**{index}. {action.get('type')}**: {'SUCCESS' if action.get('success') else 'FAILED'}"
            )
            st.caption(action.get("details"))
            for command in action.get("commands", []):
                st.code(
                    "\n".join(
                        [
                            f"Command: {command.get('command')}",
                            f"Return code: {command.get('returncode')}",
                            f"Stdout: {command.get('stdout')}",
                            f"Stderr: {command.get('stderr')}",
                        ]
                    )
                )

    st.subheader("Detailed Security Report")
    st.code(result.get("llm_security_report", ""))
    st.markdown("</div>", unsafe_allow_html=True)


def render_threat_intelligence_page(user: dict) -> None:
    st.markdown('<div class="page-heading"><h1>Threat Intelligence</h1></div>', unsafe_allow_html=True)
    st.caption(f"Signed in as {user.get('username', 'unknown')}")

    st.markdown('<div class="glass">', unsafe_allow_html=True)
    st.markdown("### Indicator Lookup")
    lookup_col, add_col = st.columns([1.3, 1], gap="large")
    with lookup_col:
        indicator_value = st.text_input(
            "Indicator Value",
            value=st.session_state.get("ti_lookup_value", ""),
            placeholder="IP, domain, or file hash",
        )
        if st.button("Lookup Indicator", type="primary", use_container_width=True):
            indicator_type = infer_indicator_type(indicator_value)
            payload = {"source_ip": indicator_value} if indicator_type == "ip" else {"malware_signature": indicator_value}
            st.session_state["ti_lookup_value"] = indicator_value
            st.session_state["ti_lookup_result"] = enrich_threat_intelligence(payload)
            st.session_state["ti_lookup_type"] = indicator_type

        lookup_result = st.session_state.get("ti_lookup_result")
        if lookup_result:
            st.write(f"Highest intel score: {lookup_result.get('highest_score', 0)}")
            status_class = "ti-status-bad" if lookup_result.get('blacklist_match') else "ti-status-clean"
            status_text = "Yes" if lookup_result.get('blacklist_match') else "No"
            st.markdown(f'Blacklist match: <span class="{status_class}">{status_text}</span>', unsafe_allow_html=True)
            for indicator in lookup_result.get("indicators", []):
                indicator_class = "panel-critical" if str(indicator.get("severity", "")).lower() in {"critical", "high"} else "panel-normal"
                st.markdown(f'<div class="glass {indicator_class}">', unsafe_allow_html=True)
                st.markdown(
                    f"- `{indicator.get('type')}` `{indicator.get('value')}` | severity `{indicator.get('severity')}` | score `{indicator.get('score')}`"
                )
                if indicator.get("abuseipdb"):
                    st.caption(f"AbuseIPDB: {indicator.get('abuseipdb')}")
                if indicator.get("virustotal"):
                    st.caption(f"VirusTotal: {indicator.get('virustotal')}")
                st.markdown("</div>", unsafe_allow_html=True)

    with add_col:
        st.markdown("### History")
        manual_type = st.selectbox("Indicator Type", ["ip", "domain", "hash"])
        manual_value = st.text_input("Indicator", value="")
        manual_reason = st.text_input("Reason", value="Analyst-confirmed malicious indicator")
        if st.button("Add To Blacklist", use_container_width=True):
            if manual_value.strip():
                entry = add_to_blacklist(
                    manual_type,
                    manual_value.strip(),
                    source="dashboard_manual",
                    reason=manual_reason.strip() or "Analyst-confirmed malicious indicator",
                    metadata={"created_by": user.get("username")},
                )
                st.success(f"Added {entry.get('value')} to the blacklist database.")
            else:
                st.warning("Enter an indicator value before adding it to the blacklist.")
    st.markdown('</div>', unsafe_allow_html=True)

    blacklist_db = load_blacklist_db()
    st.markdown('<div class="glass">', unsafe_allow_html=True)
    st.markdown("### Searchable Blacklist History")
    search = st.text_input("Search history", placeholder="Search by IP, domain, hash, source, or reason")
    history = list(reversed(blacklist_db.get("history", [])))
    if search.strip():
        term = search.strip().lower()
        history = [
            item for item in history
            if term in str(item.get("value", "")).lower()
            or term in str(item.get("source", "")).lower()
            or term in str(item.get("reason", "")).lower()
            or term in str(item.get("type", "")).lower()
        ]

    if history:
        history_df = pd.DataFrame(history)
        display_cols = [col for col in ["type", "value", "source", "reason", "listed_at"] if col in history_df.columns]
        st.dataframe(history_df[display_cols], use_container_width=True, hide_index=True)
    else:
        st.info("No blacklist history matches the current filter.")
    st.markdown('</div>', unsafe_allow_html=True)

    st.markdown('<div class="glass">', unsafe_allow_html=True)
    st.markdown("### History")
    for idx, item in enumerate(history[:20]):
        cols = st.columns([1.6, 1.2, 0.8])
        cols[0].write(f"`{item.get('type')}` `{item.get('value')}`")
        cols[1].caption(item.get("reason"))
        if cols[2].button("Lookup", key=f"history_lookup_{idx}", use_container_width=True):
            indicator_type = item.get("type")
            indicator_value = item.get("value")
            payload = {"source_ip": indicator_value} if indicator_type == "ip" else {"malware_signature": indicator_value}
            st.session_state["ti_lookup_value"] = indicator_value
            st.session_state["ti_lookup_result"] = enrich_threat_intelligence(payload)
            st.session_state["ti_lookup_type"] = indicator_type
            st.rerun()
    st.markdown('</div>', unsafe_allow_html=True)


user = auth_page()

if not user:
    render_public_auth()
    st.stop()

with st.sidebar:
    st.markdown(f"### {user.get('full_name') or user.get('username')}")
    st.caption(f"@{user.get('username')}")
    page = st.radio(
        "Navigate",
        ["Overview", "Simulate Network Traffic", "Threat Intelligence"],
    )
    logout_button()

if page == "Overview":
    render_overview(user)
elif page == "Simulate Network Traffic":
    render_simulation_page(user)
else:
    render_threat_intelligence_page(user)
