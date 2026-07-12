import os
import pandas as pd
import plotly.express as px
import streamlit as st
from dotenv import load_dotenv
from groq import Groq
from pdf_generator import generate_pdf

# Load workspace properties
load_dotenv()

st.set_page_config(page_title="AccessGuard AI Dashboard", layout="wide")

st.title("🛡️ AccessGuard AI — IAM Security & Compliance Analytics")
st.subheader("Real-time Identity Risk Monitoring & Regulatory Auditing")
st.markdown("---")

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

# --- METRIC GRID ---
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

# --- VISUAL CHARTS ---
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

st.markdown("### 🔍 Identity & Compliance Risk Registry")
styled_df = df.style.map(lambda v: "background-color: #bb1212; color: white;" if v == "Critical" else "", subset=["risk_tier"])
st.dataframe(styled_df, use_container_width=True)

st.markdown("---")

# --- AI THREAT ENGINE ---
st.markdown("### 🤖 AccessGuard AI — Autonomous Compliance & Security Agent")

user_options = df["username"].tolist()
selected_user = st.selectbox("Select User for AI Audit:", user_options, key="audit_user_select")

if "cached_markdown" not in st.session_state: st.session_state.cached_markdown = None
if "cached_html" not in st.session_state: st.session_state.cached_html = None
if "last_user" not in st.session_state: st.session_state.last_user = None

if st.session_state.last_user != selected_user:
    st.session_state.cached_markdown = None
    st.session_state.cached_html = None

import re # Make sure this import is available at the top or inside the block

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
            client = Groq(
                api_key=st.secrets["GROQ_API_KEY"]
            )

            completion = client.chat.completions.create(
                model="llama-3.3-70b-versatile",
                messages=[
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                temperature=0.3,
                max_tokens=1500,
            )

            ai_text = completion.choices[0].message.content

            st.session_state.cached_markdown = ai_text

            formatted_html_body = (
                ai_text.replace("### ", "<h3>")
                .replace("## ", "<h2>")
                .replace("# ", "<h1>")
                .replace("**", "<strong>")
                .replace("\n", "<br/>")
            )

            st.session_state.cached_html = f"""
<html>
<head>
<title>AccessGuard Executive AI Audit - {user_data['username']}</title>

<style>
body {{
    font-family: Arial, sans-serif;
    padding:40px;
    max-width:900px;
    margin:auto;
    color:#222;
    line-height:1.7;
}}

h1 {{
    color:#002244;
    border-bottom:2px solid #003366;
    padding-bottom:8px;
}}

h2 {{
    color:#004488;
    margin-top:25px;
    border-bottom:1px solid #ddd;
    padding-bottom:4px;
}}

h3 {{
    color:#333;
}}

strong {{
    font-weight:bold;
}}
</style>

</head>

<body>

<div style="text-align:center;margin-bottom:30px;">
<h1 style="border:none;">
🛡️ AccessGuard AI Enterprise Compliance Report
</h1>

<p>
<i>AI Generated Executive Security Assessment</i>
</p>

</div>

<hr>

{formatted_html_body}

<script>
window.onload = function() {{
    window.print();
}};
</script>

</body>
</html>
"""

            st.success("✅ AI Audit Generated Successfully!")

        except Exception as e:
            st.error(f"❌ AI Audit Failed: {e}")

if st.session_state.cached_markdown and st.session_state.cached_html:

    st.markdown("---")
    st.markdown("## 📄 AI Generated Security Audit")

    st.markdown(st.session_state.cached_markdown)

    st.markdown("---")

    pdf_bytes = generate_pdf(
    user_data,
    ai_text
    )
    
    pdf = generate_pdf(user_data, ai_text)

    st.download_button(
    "📥 Download Executive PDF",
    data=pdf,
    file_name=f"AccessGuard_Report_{user_data['username']}.pdf",
    mime="application/pdf"
    )