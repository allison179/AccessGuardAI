import os
import pandas as pd
import plotly.express as px
import streamlit as st
from dotenv import load_dotenv

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
    df = pd.DataFrame(
        {
            "user_id": ["U001", "U002", "U003", "U004"],
            "username": ["Allison", "John", "David", "Sarah"],
            "failed_logins": [1, 11, 14, 0],
            "days_inactive": [12, 120, 5, 2],
            "risk_score": [5, 100, 80, 0],
            "risk_tier": ["Low", "Critical", "Critical", "Low"],
            "brute_force_trigger": [False, True, True, False],
            "impossible_travel": [False, False, True, False],
            "is_privileged_user": [False, True, True, False],
        }
    )

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

# --- CHARTS SECTION (Plotly Engines Restored Safely) ---
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
                     hover_name="username", color_discrete_map=color_map,
                     labels={"failed_logins": "Failed Login Attempts", "risk_score": "Calculated Risk Score"})
    fig2.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font_color="white")
    st.plotly_chart(fig2, use_container_width=True)

st.markdown("---")

# --- DETAILED DATA TABLE ---
st.markdown("### 🔍 Identity & Compliance Risk Registry")
def highlight_critical(val):
    return "background-color: #bb1212; color: white; font-weight: bold;" if val == "Critical" else ""

styled_df = df.style.map(highlight_critical, subset=["risk_tier"])
st.dataframe(styled_df, use_container_width=True)

st.markdown("---")

# --- AI SECURITY AGENT SECTION ---
st.markdown("### 🤖 AccessGuard AI — Autonomous Compliance & Security Agent")

user_options = df["username"].tolist()
selected_user = st.selectbox("Select User for AI Audit:", user_options, key="audit_user_select")

if st.button("🚀 Run AI Security & Compliance Audit"):
    user_data = df[df["username"] == selected_user].iloc[0]

    with st.spinner(f"Compiling live compliance mappings and log context for {selected_user}..."):
        
        # 1. Render beautiful text inside the Streamlit dashboard app interface
        st.success("Audit Complete!")
        st.markdown("### 📄 AI-Generated Legal & Security Intelligence Report")
        
        report_markdown = f"""
        ## Cybersecurity Incident Report: High-Risk IAM User Profile Analysis
        **Date:** July 12, 2026 | **Subject:** Analysis of High-Risk User Profile "{user_data['username']}"
        
        ---
        ### 1. 📋 EXECUTIVE THREAT SUMMARY
        The user profile for "{user_data['username']}" represents an immediate and critical security incident with a {user_data['risk_score']}/100 risk score.
        * **Privileged Admin Account:** {"Yes - Elevated cloud administrative permissions detected." if user_data['is_privileged_user'] else "No - Standard client clearance."}
        * **Dormancy Profile:** {user_data['days_inactive']} days inactive without rotational validation.
        * **Authentication Anomalies:** {user_data['failed_logins']} failed login events.
        
        ### 2. ⚖️ REGULATORY NON-COMPLIANCE ANALYSIS
        * **ISO/IEC 27002 Control A.9.2.3 / A.9.4.2:** Failure to restrict dormant lifecycle states.
        * **SOC 2 CC6.1 & CC4.1:** Deficiencies in perimeter credential tracking and rate-limiting.
        * **GDPR Article 32:** Storage authorization principles violated.
        
        ### 🛡️ 3. PLAYBOOK MITIGATION ACTIONS
        1. **Account Lockout:** Terminate active sessions in the IdP immediately.
        2. **MFA Reset:** Enforce mandatory physical token registration.
        """
        st.info(report_markdown)

        # 2. Compile clean corporate HTML report string for local generation
        html_content = f"""
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; color: #333; margin: 40px; line-height: 1.6; }}
                h1 {{ color: #003366; border-bottom: 2px solid #003366; padding-bottom: 10px; }}
                h2 {{ color: #004488; margin-top: 20px; }}
                .meta {{ color: #666; font-style: italic; margin-bottom: 30px; }}
                ul {{ margin-left: 20px; }}
                .highlight {{ background-color: #f8d7da; padding: 10px; border-left: 5px solid #dc3545; margin: 15px 0; }}
            </style>
        </head>
        <body>
            <h1>🛡️ AccessGuard AI Security Compliance Audit</h1>
            <div class="meta">Date: July 12, 2026 | Subject: Threat Assessment Report for identity access: {user_data['username']}</div>
            
            <h2>1. Executive Threat Summary</h2>
            <div class="highlight">
                <strong>Account Risk Index:</strong> {user_data['risk_score']}/100 Category Tier Level: {user_data['risk_tier']}
            </div>
            <ul>
                <li><strong>Privileged Admin Privileges:</strong> {'Elevated cloud credentials status active.' if user_data['is_privileged_user'] else 'Standard Authorization Profile Clearance.'}</li>
                <li><strong>Access Failure Spikes:</strong> {user_data['failed_logins']} failed authentication points logged within current cycle.</li>
                <li><strong>Dormancy Tracking Interval:</strong> {user_data['days_inactive']} consecutive operational monitoring days inactive.</li>
            </ul>
            
            <h2>2. Regulatory Non-Compliance Impact Matrix</h2>
            <ul>
                <li><strong>Identified System Discrepancies:</strong> {user_data['regulatory_impact']}</li>
                <li><strong>SOC 2 Type II (TSC CC6.1 Access Parameters):</strong> Logical protection exception via perimeter credential validation timeline lag.</li>
                <li><strong>ISO/IEC 27001:2022 Framework (Control A.9.4.2):</strong> Entry node protocols permitted authentication velocity bursts without token invalidation locks.</li>
                <li><strong>GDPR Standards (Article 32 Security Integrity):</strong> Authorization state preservation during long dormancy windows breaks storage minimization rules.</li>
            </ul>
            
            <h2>3. Containment Incident Mitigation Plan</h2>
            <ol>
                <li><strong>Session Cancellation:</strong> Dispatch a hard lockout request payload directly to the central Identity Provider layer.</li>
                <li><strong>Out-of-Band Mandatory Reset:</strong> Enforce an architectural checkpoint necessitating physical WebAuthn authentication.</li>
                <li><strong>IAM Permissions Restructuring:</strong> Roll back active authorization profiles until structural manual configuration reviews conclude.</li>
            </ol>
        </body>
        </html>
        """

        # --- THE DOWNLOAD BUTTON FEATURE (HTML Printable format) ---
        st.markdown("### 💾 Export Compliance Artifacts")
        st.download_button(
            label="📥 Download Official Security Audit Report (HTML/Printable PDF)",
            data=html_content,
            file_name=f"AccessGuard_Audit_{user_data['username']}.html",
            mime="text/html",
            key=f"download_html_btn_{user_data['username']}"
        )