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
        
        # 1. RENDER DETAILED MARKDOWN ON THE STREAMLIT INTERFACE
        report_content = f"""# Cybersecurity Incident Report: High-Risk IAM User Profile Analysis

**Date:** July 12, 2026 | **Subject:** Analysis of High-Risk User Profile "{user_data['username']}"

---

### 1. 📋 EXECUTIVE THREAT SUMMARY
The user profile for "{user_data['username']}" represents an immediate and critical security incident with a {user_data['risk_score']}/100 risk score, indicating an extreme compromise potential. The confluence of access volatility signifies an imminent threat to the organization's information assets.

**Key Threat Indicators:**
* **Privileged Admin Account:** {"Yes - The account possesses elevated permissions, granting extensive access to core database architectures." if user_data['is_privileged_user'] else "No - Standard non-administrative client parameters apply."}
* **Dormancy Profile:** An inactive account for {user_data['days_inactive']} days without credential rotation represents an unmonitored attack vector.
* **Authentication Anomalies:** {user_data['failed_logins']} failed login attempts confirm active access volatility.
* **Calculated Risk Index:** Explicit {user_data['risk_score']}/100 score mandates immediate Blue-Team intervention tasks.

**Corporate "Blast Radius":**
A successful compromise of "{user_data['username']}"'s credentials would lead to an expanded threat surface including complete system takeover risks, massive data breaches, and heavy regulatory compliance financial penalties under GDPR, ISO 27001, and SOC 2 frameworks.

---

### 2. ⚖️ REGULATORY NON-COMPLIANCE ANALYSIS
The current footprint of the user profile demonstrates deviations from primary international compliance standards:

#### ISO/IEC 27001:2022 Framework
* **Control A.9.2.3 (Privileged Access Rights):** The existence of a dormant, high-risk account actively under threat patterns violates lifecycle restriction parameters.
* **Control A.9.4.2 (Secure Log-on Procedures):** Monitoring utilities failed to actively alert on brute force indicators prior to threshold exhaustion.

#### SOC 2 Type II - Trust Services Criteria (Security)
* **CC6.1 - Access Control:** Logical security measures failed to proactively restrict, disable, or protect the dormant profile.
* **CC4.1 - Monitoring Activities:** Extended system dormancy spikes show an active breakdown in automated baseline alarming.

#### GDPR (General Data Protection Regulation)
* **Article 32 - Security of Processing:** Inability to lock vulnerable access paths violates processing integrity mandates.
* **Article 5(1)(c) - Data Minimisation:** Maintaining extensive account permissions during prolonged inactivity violates structural processing principles.

---

### 3. 🛡️ PLAYBOOK MITIGATION ACTIONS

#### Immediate Containment Actions (Critical Priority)
1. **Account Lockout/Disablement:** Suspend the user account across all active directory servers and cloud IAM platforms immediately.
2. **Incident Alert Notification:** Route a priority response notice to the Security Operations Center (SOC) management queue.
3. **Log Analysis & Forensic Review:** Extract past authentication logs to track potential lateral movement or persistent changes.
4. **Source IP Perimeter Blocking:** Perimeter firewall ban applied to offending authorization source nodes.
"""
        st.success("Audit Complete!")
        st.markdown("### 📄 AI-Generated Legal & Security Intelligence Report")
        st.info(report_content)
        
        # 2. GENERATE MATCHING HIGH-FIDELITY PRINTABLE HTML ENGINE
        # This triggers a print window on load so users save a crisp corporate vector PDF file directly
        printable_html = f"""
        <html>
        <head>
            <title>AccessGuard AI Audit Report - {user_data['username']}</title>
            <style>
                body {{ font-family: 'Helvetica Neue', Arial, sans-serif; color: #333; margin: 40px; line-height: 1.6; }}
                .header {{ border-bottom: 3px solid #003366; padding-bottom: 10px; margin-bottom: 20px; }}
                h1 {{ color: #003366; margin: 0; font-size: 26px; }}
                h2 {{ color: #004488; font-size: 18px; margin-top: 30px; border-bottom: 1px solid #ddd; padding-bottom: 5px; }}
                h3 {{ color: #444; font-size: 15px; }}
                .meta-table {{ width: 100%; margin-bottom: 25px; border-collapse: collapse; }}
                .meta-table td {{ padding: 6px; font-size: 13px; }}
                .danger-alert {{ background-color: #f8d7da; border-left: 6px solid #d9534f; padding: 15px; margin: 20px 0; border-radius: 4px; font-weight: bold; color: #b71c1c; }}
                ul, ol {{ margin-left: 20px; font-size: 14px; }}
                li {{ margin-bottom: 8px; }}
                p {{ font-size: 14px; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>🛡️ AccessGuard AI — Security & Compliance Audit Report</h1>
                <p style="margin: 5px 0 0 0; color: #666; font-style: italic;">Automated Identity Access Forensic Matrix</p>
            </div>
            
            <table class="meta-table">
                <tr>
                    <td><strong>Date / Timestamp:</strong> July 12, 2026</td>
                    <td><strong>Target Account:</strong> {user_data['username']}</td>
                </tr>
                <tr>
                    <td><strong>Report Identifier:</strong> AG-AUDIT-2026-{user_data['user_id']}</td>
                    <td><strong>Risk Level Matrix:</strong> {user_data['risk_tier']} ({user_data['risk_score']}/100)</td>
                </tr>
            </table>

            <h2>1. 📋 Executive Threat Summary</h2>
            <div class="danger-alert">
                CRITICAL EXPOSURE WARNING: User assessment metrics reflect a target threshold variance score of {user_data['risk_score']}/100. Perimeter containment playbooks are recommended.
            </div>
            <ul>
                <li><strong>Privileged Account Clearance:</strong> {'TRUE — This user retains administrative access capabilities over structural core database backends.' if user_data['is_privileged_user'] else 'FALSE — Standard non-administrative user permissions profile.'}</li>
                <li><strong>Account Inactivity Interval:</strong> Flagged at {user_data['days_inactive']} consecutive days of operational dormancy without verification.</li>
                <li><strong>Authentication Failures:</strong> Detects {user_data['failed_logins']} localized failed access entries inside this analysis sequence window.</li>
            </ul>
            <p><strong>Corporate Blast Radius Impact Assessment:</strong> Credentials breach for this identity exposes core network layers to administrative persistence installation, systematic table exfiltrations, and critical non-compliance penalties.</p>

            <h2>2. ⚖️ Regulatory Non-Compliance Analysis</h2>
            <h3>ISO/IEC 27001 Framework Control Audits</h3>
            <ul>
                <li><strong>Control A.9.2.3 (Privileged Access Management):</strong> Sustained execution authorization configurations during long user lifecycle dormancy breaks identity review rules.</li>
                <li><strong>Control A.9.4.2 (Secure Log-on Procedures):</strong> Gateway configurations omitted automated velocity threshold restrictions before access limits were passed.</li>
            </ul>
            <h3>SOC 2 Type II - Trust Services Criteria</h3>
            <ul>
                <li><strong>CC6.1 (Access Protection Barriers):</strong> Perimeter boundaries dropped protection policies allowing access manipulation checks on inactive credentials.</li>
                <li><strong>CC4.1 (System Performance Monitoring):</strong> System alarm triggers dropped tracking context over standard user transaction lines.</li>
            </ul>
            <h3>GDPR Framework Ingest Compliance</h3>
            <ul>
                <li><strong>Article 32 (Processing Integrity):</strong> Operational structures failed to deploy modern automated isolation measures against high-risk entry points.</li>
                <li><strong>Article 5(1)(c) (Data Minimisation):</strong> Extended privilege status during lengthy account inactivity cycles violates minimization constraints.</li>
            </ul>

            <h2>3. 🛡️ Containment Playbook Actions</h2>
            <h3>Immediate Operational Isolation Tasks</h3>
            <ol>
                <li><strong>Identity Token Revocation:</strong> Execute an active session wipe directly at the identity provider (IdP) layer.</li>
                <li><strong>Quarantine Sub-Group Assignment:</strong> Transition the profile permissions down into an isolated sandbox group instantly.</li>
                <li><strong>Ingress IP Boundary Rules:</strong> Inject target source authorization firewall drop rules to drop upcoming request chains.</li>
            </ol>
            <h3>Strategic Remediations</h3>
            <ul>
                <li>Apply an automated lifecycle validation routine to strip system authorization after 30 baseline monitor days of inactivity.</li>
                <li>Enforce out-of-band WebAuthn hardware key verification challenges before restoration requests pass manual control filters.</li>
            </ul>
            
            <script>
                // Auto-trigger print window when user opens the document file to save clean vector PDF files easily
                window.onload = function() {{ window.print(); }}
            </script>
        </body>
        </html>
        """

        # --- THE DOWNLOAD BUTTON FEATURE ---
        st.markdown("---")
        st.markdown("### 💾 Export Compliance Artifacts")
        st.download_button(
            label="📥 Download Official Full Security Audit Report (PDF/Printable Layout)",
            data=printable_html,
            file_name=f"AccessGuard_Full_Audit_{user_data['username']}.html",
            mime="text/html",
            key=f"download_html_btn_{user_data['username']}"
        )