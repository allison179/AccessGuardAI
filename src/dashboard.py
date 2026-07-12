import io
import os
import re
import sys
import markdown
import pandas as pd
import plotly.express as px
import streamlit as st
from dotenv import load_dotenv
from groq import Groq

# Load workspace environment configurations
load_dotenv()

# 1. Page & Layout Setup Configuration
st.set_page_config(page_title="AccessGuard AI Dashboard", layout="wide")

st.title("🛡️ AccessGuard AI — IAM Security & Compliance Analytics")
st.subheader("Real-time Identity Risk Monitoring & Regulatory Auditing")
st.markdown("---")

# 2. Native Dynamic PDF Generator (Sanitized against Emojis to prevent Segfaults)
def generate_pdf(user_data, ai_markdown):
    """Converts AI markdown directly to styled HTML and builds a true PDF blob natively."""
    # Strip emojis from the AI text before rendering to protect ReportLab/xhtml2pdf from crashing
    clean_markdown = re.sub(r'[\U00010000-\U0010ffff]', '', ai_markdown)
    html_content = markdown.markdown(clean_markdown)
    
    full_html = f"""
    <html>
    <head>
    <meta charset="utf-8">
    <title>AccessGuard Executive AI Audit - {user_data['username']}</title>
    <style>
        @page {{
            size: letter;
            margin: 20mm;
        }}
        body {{
            font-family: Helvetica, Arial, sans-serif;
            color: #2D3748;
            line-height: 1.6;
            font-size: 11pt;
        }}
        .header {{
            text-align: center;
            border-bottom: 3px solid #1A365D;
            padding-bottom: 12px;
            margin-bottom: 25px;
        }}
        .header h1 {{
            color: #1A365D;
            margin: 0;
            font-size: 22pt;
            font-weight: 700;
        }}
        .header p {{
            color: #718096;
            margin: 5px 0 0 0;
            font-style: italic;
            font-size: 10pt;
        }}
        .meta-box {{
            background-color: #F7FAFC;
            border-left: 4px solid #3182CE;
            padding: 15px;
            margin-bottom: 30px;
        }}
        .meta-table {{
            width: 100%;
            border-collapse: collapse;
        }}
        .meta-table td {{
            padding: 4px 8px;
            font-size: 10pt;
        }}
        .meta-label {{
            font-weight: bold;
            color: #2B6CB0;
            width: 20%;
        }}
        h1 {{
            color: #1A365D;
            font-size: 15pt;
            margin-top: 25px;
            margin-bottom: 10px;
            border-bottom: 1px solid #E2E8F0;
            padding-bottom: 4px;
        }}
        h2 {{
            color: #2B6CB0;
            font-size: 12pt;
            margin-top: 20px;
            margin-bottom: 6px;
        }}
        p, li {{
            margin-bottom: 10px;
        }}
        strong {{
            color: #1A365D;
        }}
    </style>
    </head>
    <body>
        <div class="header">
            <h1>AccessGuard AI Enterprise Compliance Report</h1>
            <p>Official Executive Security & Infrastructure Assessment</p>
        </div>
        <div class="meta-box">
            <table class="meta-table">
                <tr>
                    <td class="meta-label">Subject Identity:</td>
                    <td>{user_data['username']} ({user_data['user_id']})</td>
                    <td class="meta-label">Risk Profile:</td>
                    <td><strong>{user_data['risk_tier']}</strong> ({user_data['risk_score']}/100)</td>
                </tr>
                <tr>
                    <td class="meta-label">Telemetry:</td>
                    <td>{user_data['failed_logins']} failed logins | {user_data['days_inactive']} days inactive</td>
                    <td class="meta-label">Compliance Status:</td>
                    <td>{user_data['regulatory_impact']}</td>
                </tr>
            </table>
        </div>
        <div class="report-content">
            {html_content}
        </div>
    </body>
    </html>
    """
    
    # Try lightweight parsing engine first
    try:
        from xhtml2pdf import pisa
        pdf_buffer = io.BytesIO()
        pisa_status = pisa.CreatePDF(full_html, dest=pdf_buffer)
        if not pisa_status.err:
            return pdf_buffer.getvalue()
    except ImportError:
        pass

    try:
        from weasyprint import HTML
        return HTML(string=full_html).write_pdf()
    except ImportError:
        raise ImportError("Ensure xhtml2pdf or weasyprint is explicitly defined in requirements.txt.")

# 3. Compliance Rule Processor Engine
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

# 4. Data Layer Pipeline Resolution
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

# 5. RENDERING VISUAL METRIC GRID
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

# 6. RENDERING ANALYTICS CHARTS GRID
left_col, right_col = st.columns(2)
color_map = {"Low": "#2ca02c", "Medium": "#ffbb78", "High": "#ff7f0e", "Critical": "#b62525"}

# Fixed deprecated 'use_container_width' to use the new layout system properties
with left_col:
    st.markdown("### 📊 Risk Tier Distribution")
    fig = px.pie(df, names="risk_tier", color="risk_tier", color_discrete_map=color_map, hole=0.4)
    fig.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font_color="white")
    st.plotly_chart(fig, width="stretch")

with right_col:
    st.markdown("### 📈 User Risk Scores vs. Failed Logins")
    fig2 = px.scatter(df, x="failed_logins", y="risk_score", color="risk_tier", size="days_inactive",
                      hover_name="username", color_discrete_map=color_map)
    fig2.update_layout(paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)", font_color="white")
    st.plotly_chart(fig2, width="stretch")

st.markdown("---")

# 7. RENDERING RISK DATA REGISTRY TABLE
st.markdown("### 🔍 Identity & Compliance Risk Registry")
styled_df = df.style.map(lambda v: "background-color: #bb1212; color: white;" if v == "Critical" else "", subset=["risk_tier"])
st.dataframe(styled_df, width="stretch")

st.markdown("---")

# 8. THE CORE AI THREAT ENGINE BLOCK
st.markdown("### 🤖 AccessGuard AI — Autonomous Compliance & Security Agent")

user_options = df["username"].tolist()
selected_user = st.selectbox("Select User for AI Audit:", user_options, key="audit_user_select")

# Streamlit application state tracking configurations
if "cached_markdown" not in st.session_state: st.session_state.cached_markdown = None
if "cached_pdf" not in st.session_state: st.session_state.cached_pdf = None
if "last_user" not in st.session_state: st.session_state.last_user = None

# Flush previous results instantly if selector value modifications register
if st.session_state.last_user != selected_user:
    st.session_state.cached_markdown = None
    st.session_state.cached_pdf = None

if st.button("🚀 Run AI Security & Compliance Audit"):
    user_data = df[df["username"] == selected_user].iloc[0]
    st.session_state.last_user = selected_user

    with st.spinner(f"Generating AI Security Audit for {selected_user}..."):
        prompt = f"""
You are an elite Cybersecurity Incident Response Specialist and Regulatory Compliance Auditor.
Generate an official Cybersecurity Incident Report.

User Details:
- Username: {user_data['username']}
- User ID: {user_data['user_id']}

Security Metrics:
- Risk Score: {user_data['risk_score']}/100
- Risk Tier: {user_data['risk_tier']}
- Failed Logins: {user_data['failed_logins']}
- Days Inactive: {user_data['days_inactive']}
- Privileged User: {user_data['is_privileged_user']}
- Compliance Violations: {user_data['regulatory_impact']}

Generate the report using proper Markdown.
Include the following sections:
# Executive Threat Summary
# Regulatory Non-Compliance Analysis
# Risk Assessment
# Incident Response Playbook
# Executive Recommendations
"""

        try:
            # Build the explicit target runtime Groq client instance
            client = Groq(api_key=st.secrets["GROQ_API_KEY"])

            completion = client.chat.completions.create(
                model="llama-3.3-70b-versatile",
                messages=[{"role": "user", "content": prompt}],
                temperature=0.3,
                max_tokens=1500,
            )

            ai_text = completion.choices[0].message.content

            # Persist properties cleanly inside memory states
            st.session_state.cached_markdown = ai_text
            st.session_state.cached_pdf = generate_pdf(user_data, ai_text)
            
            # Use dynamic rerun framework to render updates smoothly
            st.rerun()

        except Exception as e:
            st.error(f"❌ AI Audit Failed: {e}")

# 9. OUTPUT & PDF DOWNLOAD PRESENTATION WORKSPACE
if st.session_state.cached_markdown and st.session_state.cached_pdf:
    st.markdown("---")
    st.markdown("## 📄 AI Generated Security Audit")
    st.markdown(st.session_state.cached_markdown)

    st.markdown("---")
    st.download_button(
        label="📥 Download Executive PDF Report",
        data=st.session_state.cached_pdf,
        file_name=f"AccessGuard_Report_{st.session_state.last_user}.pdf",
        mime="application/pdf"
    )