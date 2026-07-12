import os
import io
import streamlit as st
import pandas as pd
import plotly.express as px
from dotenv import load_dotenv
from groq import Groq
import markdown

# Load workspace properties
load_dotenv()

# --- 📄 EMBEDDED PDF GENERATION ENGINE ---
def generate_pdf(user_data, ai_markdown):
    """Converts AI markdown directly to styled HTML and builds a true PDF blob natively."""
    html_content = markdown.markdown(ai_markdown)
    
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
            font-family: 'Helvetica Neue', Helvetica, Arial, sans-serif;
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
            font-size: 24pt;
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
            font-size: 16pt;
            margin-top: 30px;
            margin-bottom: 12px;
            border-bottom: 1px solid #E2E8F0;
            padding-bottom: 5px;
        }}
        h2 {{
            color: #2B6CB0;
            font-size: 13pt;
            margin-top: 20px;
            margin-bottom: 8px;
        }}
        p, li {{
            margin-bottom: 12px;
        }}
        strong {{
            color: #1A365D;
        }}
    </style>
    </head>
    <body>
        <div class="header">
            <h1>🛡️ AccessGuard AI Enterprise Compliance Report</h1>
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
    
    try:
        from xhtml2pdf import pisa
        pdf_buffer = io.BytesIO()
        pisa_status = pisa.CreatePDF(full_html, dest=pdf_buffer)
        if not pisa_status.err:
            return pdf_buffer.getvalue()
    except ImportError:
        pass

    from weasyprint import HTML
    return HTML(string=full_html).write_pdf()

# --- Mock Data Framework (Ensure df is generated or imported here in your actual file) ---
# Example: df = pd.read_csv("your_data.csv") or dynamic database fetching
# selected_user = st.selectbox("Select Target Profile", df["username"].unique())

# --- 🚀 MAIN AUDIT EXECUTION BUTTON BUTTON ---
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

            st.success("✅ AI Audit Generated Successfully!")

        except Exception as e:
            st.error(f"❌ AI Audit Failed: {e}")

# --- RENDERING WORKSPACE ---
if st.session_state.get("cached_markdown") and st.session_state.get("cached_pdf"):
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