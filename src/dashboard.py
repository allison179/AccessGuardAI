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
from fpdf import FPDF

# Load workspace environment configurations
load_dotenv()

# 1. Page & Layout Setup Configuration
st.set_page_config(page_title="AccessGuard AI Dashboard", layout="wide")

st.title("🛡️ AccessGuard AI — IAM Security & Compliance Analytics")
st.subheader("Real-time Identity Risk Monitoring & Regulatory Auditing")
st.markdown("---")

# 2. Pure Python Crash-Proof PDF Generator Engine
# 2. Pure Python Crash-Proof PDF Generator Engine (Unicode Safe)
def generate_pdf(user_data, ai_markdown):
    """Compiles a pure Python PDF layout via fpdf2, cleansing all unsupported characters."""
    
    # 1. Cleanse the AI text: strip out non-ASCII/emojis so Helvetica doesn't crash
    clean_text = re.sub(r'[^\x00-\x7F]+', '', ai_markdown)
    
    # 2. Cleanse user metadata strings to remove status emojis like "✅" or "⚠️"
    clean_username = re.sub(r'[^\x00-\x7F]+', '', str(user_data['username'])).strip()
    clean_uid = re.sub(r'[^\x00-\x7F]+', '', str(user_data['user_id'])).strip()
    clean_tier = re.sub(r'[^\x00-\x7F]+', '', str(user_data['risk_tier'])).strip()
    clean_impact = re.sub(r'[^\x00-\x7F]+', '', str(user_data['regulatory_impact'])).strip()
    
    pdf = FPDF(orientation="P", unit="mm", format="letter")
    pdf.set_auto_page_break(auto=True, margin=20)
    pdf.add_page()
    
    # Header Banner Block
    pdf.set_fill_color(26, 54, 93) # Deep Blue
    pdf.rect(0, 0, 216, 38, "F")
    
    pdf.set_text_color(255, 255, 255)
    pdf.set_font("Helvetica", "B", 18)
    pdf.cell(0, 12, "AccessGuard AI Enterprise Compliance Report", ln=True, align="C")
    pdf.set_font("Helvetica", "I", 10)
    pdf.cell(0, 4, "Official Executive Security & Infrastructure Assessment", ln=True, align="C")
    pdf.ln(12)
    
    # Metadata Block Panel
    pdf.set_text_color(45, 55, 72)
    pdf.set_fill_color(247, 250, 252)
    pdf.rect(15, 42, 186, 26, "DF")
    
    pdf.set_font("Helvetica", "B", 10)
    pdf.set_xy(18, 44)
    pdf.cell(40, 6, f"Subject Identity: {clean_username} ({clean_uid})")
    pdf.set_xy(120, 44)
    pdf.cell(40, 6, f"Risk Profile: {clean_tier} ({user_data['risk_score']}/100)")
    
    pdf.set_xy(18, 52)
    pdf.cell(40, 6, f"Telemetry: {user_data['failed_logins']} failed logins | {user_data['days_inactive']} days inactive")
    pdf.set_xy(120, 52)
    pdf.set_font("Helvetica", "", 9)
    pdf.cell(40, 6, f"Compliance: {clean_impact[:45]}")
    
    pdf.set_xy(15, 74)
    
    # Process lines from AI Markdown
    pdf.set_font("Helvetica", "", 10)
    lines = clean_text.split("\n")
    for line in lines:
        if line.strip().startswith("#"):
            # Header conversions
            clean_head = line.replace("#", "").strip()
            pdf.set_font("Helvetica", "B", 14)
            pdf.set_text_color(26, 54, 93)
            pdf.ln(6)
            pdf.cell(0, 8, clean_head, ln=True)
            pdf.set_font("Helvetica", "", 10)
            pdf.set_text_color(45, 55, 72)
        elif line.strip().startswith("-") or line.strip().startswith("*"):
            # Bullet point alignment layout logic
            clean_bullet = line.strip()[1:].strip()
            pdf.set_x(20)
            pdf.multi_cell(0, 6, f"* {clean_bullet}")
        elif line.strip():
            # Standard structural text layout
            pdf.multi_cell(0, 6, line.strip())
            pdf.ln(2)
            
    return pdf.output()

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

# 7. RENDERING RISK DATA REGISTRY TABLE
st.markdown("### 🔍 Identity & Compliance Risk Registry")
styled_df = df.style.map(lambda v: "background-color: #bb1212; color: white;" if v == "Critical" else "", subset=["risk_tier"])
st.dataframe(styled_df, use_container_width=True)

st.markdown("---")

# 8. THE CORE AI THREAT ENGINE BLOCK
st.markdown("### 🤖 AccessGuard AI — Autonomous Compliance & Security Agent")

user_options = df["username"].tolist()
selected_user = st.selectbox("Select User for AI Audit:", user_options, key="audit_user_select")

# Streamlit application state tracking configurations
if "cached_markdown" not in st.session_state: st.session_state.cached_markdown = None
if "cached_pdf" not in st.session_state: st.session_state.cached_pdf = None
if "last_user" not in st.session_state: st.session_state.last_user = None

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
            client = Groq(api_key=st.secrets["GROQ_API_KEY"])

            completion = client.chat.completions.create(
                model="llama-3.3-70b-versatile",
                messages=[{"role": "user", "content": prompt}],
                temperature=0.3,
                max_tokens=1500,
            )

            ai_text = completion.choices[0].message.content

            # Cache components cleanly inside state parameters
            st.session_state.cached_markdown = ai_text
            st.session_state.cached_pdf = generate_pdf(user_data, ai_text)
            
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