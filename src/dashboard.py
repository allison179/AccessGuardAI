import os
import pandas as pd
import plotly.express as px
import streamlit as st
from dotenv import load_dotenv
from google import genai

# Initialize environment variables from .env
load_dotenv()

# Set page layout to wide and configure clean UI styling properties
st.set_page_config(page_title="AccessGuard AI Dashboard", layout="wide")

st.title("🛡️ AccessGuard AI — IAM Security & Compliance Analytics")
st.subheader("Real-time Identity Risk Monitoring & Regulatory Auditing")
st.markdown("---")

# Dynamic IT Law mapping function helper exactly matching your registry rules
def map_compliance_violations(row):
    violations = []
    if row["brute_force_trigger"]:
        violations.append("SOC 2 (CC6.1 - Access Control)")
    if row["impossible_travel"]:
        violations.append("ISO 27001 (A.9.4.2 - Secure Log-on)")
    if row["is_privileged_user"] and row["risk_score"] >= 80:
        violations.append("ISO 27001 (A.9.2.3 - Privileged Access)")
    if row["days_inactive"] > 90:
        violations.append("GDPR (Art. 32 - Data Minimization)")
    return ", ".join(violations) if violations else "Compliant ✅"

# Load data cleanly from local database layer
try:
    df = pd.read_csv("data/risk_assessments.csv")
except Exception:
    df = pd.DataFrame({
        "user_id": ["U001", "U002", "U003", "U004"],
        "username": ["Allison", "John", "David", "Sarah"],
        "failed_logins": [1, 11, 14, 0],
        "days_inactive": [12, 120, 5, 2],
        "risk_score": [5, 100, 80, 0],
        "risk_tier": ["Low", "Critical", "Critical", "Low"],
        "brute_force_trigger": [False, True, True, False],
        "impossible_travel": [False, False, True, False],
        "is_privileged_user": [False, True, True, False],
    })

if "regulatory_impact" not in df.columns:
    df["regulatory_impact"] = df.apply(map_compliance_violations, axis=1)

# --- KPI METRICS ROW ---
col1, col2, col3, col4 = st.columns(4)
with col1:
    st.metric(label="Total Monitored Users", value=len(df))
with col2:
    critical_count = len(df[df["risk_tier"] == "Critical"])
    st.metric(label="🚨 Critical Risks", value=critical_count, delta=f"{critical_count} Audit Failures", delta_color="inverse")
with col3:
    avg_risk = int(df["risk_score"].mean())
    st.metric(label="Average Risk Score", value=f"{avg_risk}/100")
with col4:
    non_compliant_count = len(df[df["regulatory_impact"] != "Compliant ✅"])
    st.metric(label="⚠️ Non-Compliant Accounts", value=non_compliant_count)

st.markdown("---")

# --- CHARTS SECTION ---
left_col, right_col = st.columns(2)
color_map = {"Low": "#2ca02c", "Medium": "#ffbb78", "High": "#ff7f0e", "Critical": "#b62525"}

with left_col:
    st.markdown("### 📊 Risk Tier Distribution")
    fig = px.pie(df, names="risk_tier", color="risk_tier", color_discrete_map=color_map, hole=0.4)
    fig.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font_color="white")
    st.plotly_chart(fig, use_container_width=True)

with right_col:
    st.markdown("### 📈 User Risk Scores vs. Failed Logins")
    fig2 = px.scatter(df, x="failed_logins", y="risk_score", color="risk_tier", size="days_inactive",
                     hover_name="username", color_discrete_map=color_map)
    fig2.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font_color="white")
    st.plotly_chart(fig2, use_container_width=True)

st.markdown("---")

# --- DETAILED DATA TABLE ---
st.markdown("### 🔍 Identity & Compliance Risk Registry")
styled_df = df.style.map(lambda v: "background-color: #bb1212; color: white;" if v == "Critical" else "", subset=["risk_tier"])
st.dataframe(styled_df, use_container_width=True)

st.markdown("---")

# --- AI SECURITY AGENT SECTION ---
st.markdown("### 🤖 AccessGuard AI — Autonomous Compliance & Security Agent")

user_options = df["username"].tolist()
selected_user = st.selectbox("Select User for AI Audit:", user_options, key="audit_user_select")

# Persist data across clicks
if "cached_markdown" not in st.session_state: st.session_state.cached_markdown = None
if "cached_html" not in st.session_state: st.session_state.cached_html = None
if "last_user" not in st.session_state: st.session_state.last_user = None

if st.session_state.last_user != selected_user:
    st.session_state.cached_markdown = None
    st.session_state.cached_html = None

if st.button("🚀 Run AI Security & Compliance Audit"):
    user_data = df[df["username"] == selected_user].iloc[0]
    st.session_state.last_user = selected_user

    with st.spinner(f"Querying live Gemini AI models for {selected_user}..."):
        # Setup real AI generation instructions
        prompt = f"""
        You are an elite Cybersecurity Incident Response Specialist and Regulatory Compliance Auditor.
        Write a massive, thorough corporate threat report for user: {user_data['username']}.
        Metrics context to inject:
        - Risk Score: {user_data['risk_score']}/100 ({user_data['risk_tier']} tier)
        - Failed Logins: {user_data['failed_logins']}
        - Days Inactive: {user_data['days_inactive']}
        - Privileged Account Status: {user_data['is_privileged_user']}
        - Compliance Mappings Triggered: {user_data['regulatory_impact']}
        
        Provide a highly professional summary layout including sections for:
        1. Executive Threat Summary & Corporate Blast Radius
        2. Regulatory Non-Compliance Analysis (ISO 27001, SOC 2, and GDPR deviations)
        3. Containment Incident Response Playbook Actions
        Make it clean and highly technical. Do not mention system fallbacks.
        """
        
        try:
            api_key = os.getenv("GEMINI_API_KEY")
            client = genai.Client(api_key=api_key)
            response = client.models.generate_content(model="gemini-1.5-flash", contents=prompt)
            
            ai_text = response.text
            st.session_state.cached_markdown = ai_text
            
            # Formulate the download page document layout structure
            st.session_state.cached_html = f"""
            <html><body style="font-family:Arial;padding:30px;line-height:1.6;color:#333;">
            <h2>🛡️ AccessGuard AI Official Export Artifact</h2>
            <hr/><pre style="white-space:pre-wrap;font-family:Arial;">{ai_text}</pre>
            <script>window.onload = function() {{ window.print(); }}</script>
            </body></html>
            """
        except Exception as e:
            st.error(f"AI API Connection failed: {str(e)}. Please check your GEMINI_API_KEY inside your .env file.")

if st.session_state.cached_markdown:
    st.markdown("### 📄 AI-Generated Legal & Security Intelligence Report")
    st.info(st.session_state.cached_markdown)
    
    st.download_button(
        label="📥 Download Official Full Security Audit Report (PDF Layout)",
        data=st.session_state.cached_html,
        file_name=f"AccessGuard_Live_Audit_{st.session_state.last_user}.html",
        mime="text/html",
        key="live_report_download"
    )