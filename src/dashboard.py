import os
import pandas as pd
import plotly.express as px
import streamlit as st
from dotenv import load_dotenv
from google import genai  # Modern 2026 SDK

# Initialize environment variables from .env
load_dotenv()

# Set page layout to wide
st.set_page_config(page_title="AccessGuard AI Dashboard", layout="wide")

st.title("🛡️ AccessGuard AI — IAM Security & Compliance Analytics")
st.subheader("Real-time Identity Risk Monitoring & Regulatory Auditing")
st.markdown("---")


# Load data and map regulatory compliance context
@st.cache_data
def load_data():
    try:
        base_df = pd.read_csv("data/risk_assessments.csv")
    except FileNotFoundError:
        # Fallback dummy data if file isn't generated yet
        base_df = pd.DataFrame(
            {
                "user_id": ["U001", "U002", "U003", "U004"],
                "username": ["Allison", "John", "David", "Sarah"],
                "failed_logins": [1, 11, 14, 0],
                "days_inactive": [12, 120, 5, 2],
                "risk_score": [5, 100, 100, 0],
                "risk_tier": ["Low", "Critical", "Critical", "Low"],
                "brute_force_trigger": [False, True, True, False],
                "impossible_travel": [False, False, True, False],
                "is_privileged_user": [False, True, True, False],
            }
        )

    # Dynamic IT Law mapping function
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

    base_df["regulatory_impact"] = base_df.apply(
        map_compliance_violations, axis=1
    )
    return base_df


df = load_data()

# --- KPI METRICS ROW ---
col1, col2, col3, col4 = st.columns(4)

with col1:
    st.metric(label="Total Monitored Users", value=len(df))
with col2:
    critical_count = len(df[df["risk_tier"] == "Critical"])
    st.metric(
        label="🚨 Critical Risks",
        value=critical_count,
        delta=f"{critical_count} Audit Failures",
        delta_color="inverse",
    )
with col3:
    avg_risk = int(df["risk_score"].mean())
    st.metric(label="Average Risk Score", value=f"{avg_risk}/100")
with col4:
    non_compliant_count = len(df[df["regulatory_impact"] != "Compliant ✅"])
    st.metric(label="⚠️ Non-Compliant Accounts", value=non_compliant_count)

st.markdown("---")

# --- CHARTS SECTION ---
left_col, right_col = st.columns(2)

with left_col:
    st.markdown("### 📊 Risk Tier Distribution")
    color_map = {
        "Low": "#2ca02c",
        "Medium": "#ffbb78",
        "High": "#ff7f0e",
        "Critical": "#d62728",
    }
    fig = px.pie(
        df,
        names="risk_tier",
        color="risk_tier",
        color_discrete_map=color_map,
        hole=0.4,
    )
    st.plotly_chart(fig, use_container_width=True)

with right_col:
    st.markdown("### 📈 User Risk Scores vs. Failed Logins")
    fig2 = px.scatter(
        df,
        x="failed_logins",
        y="risk_score",
        color="risk_tier",
        size="days_inactive",
        hover_name="username",
        color_discrete_map=color_map,
        labels={
            "failed_logins": "Failed Login Attempts",
            "risk_score": "Calculated Risk Score",
        },
    )
    st.plotly_chart(fig2, use_container_width=True)

st.markdown("---")

# --- DETAILED DATA TABLE ---
st.markdown("### 🔍 Identity & Compliance Risk Registry")


def highlight_critical(val):
    color = (
        "#bb1212"
        if val == "Critical"
        else ("#fff3cd" if val == "High" else "")
    )
    return f"background-color: {color}"


styled_df = df.style.map(highlight_critical, subset=["risk_tier"])
st.dataframe(styled_df, use_container_width=True)

st.markdown("---")

# --- AI SECURITY AGENT SECTION (GEMINI POWERED) ---
st.markdown("### 🤖 AccessGuard AI — Autonomous Compliance & Security Agent")
st.write(
    "Select an account to trigger an automated Gemini AI regulatory audit and incident response plan."
)

user_options = df["username"].tolist()
selected_user = st.selectbox("Select User for AI Audit:", user_options)

if st.button("🚀 Run AI Security & Compliance Audit"):
    user_data = df[df["username"] == selected_user].iloc[0]

    with st.spinner(
        f"Compiling compliance mappings and log context for {selected_user}..."
    ):

        # Upgraded regulatory-focused system prompt
        prompt = f"""
        You are an expert Cybersecurity Incident Response Specialist and Regulatory Compliance Auditor specializing in IT Laws (ISO/IEC 27001, SOC 2 Type II, and GDPR).
        
        Analyze the following IAM user profile and provide a professional, structured corporate report using clear markdown headings:
        
        1. 📋 EXECUTIVE THREAT SUMMARY: Assessment of threat indicators and corporate "blast radius".
        2. ⚖️ REGULATORY NON-COMPLIANCE ANALYSIS: Identify specific IT laws, articles, or control frameworks violated by this user's profile (e.g., ISO 27001 Access Control gaps, SOC 2 monitoring failures, or GDPR data security principles).
        3. 🛡️ PLAYBOOK MITIGATION ACTIONS: Step-by-step immediate containment and long-term compliance recovery actions.

        User Security Profile:
        - Username: {user_data['username']}
        - Failed Login Attempts: {user_data['failed_logins']}
        - Days Inactive (Dormancy): {user_data['days_inactive']}
        - Brute Force Flag Triggered: {user_data.get('brute_force_trigger', False)}
        - Impossible Travel Flag Triggered: {user_data.get('impossible_travel', False)}
        - Privileged Admin Account: {user_data.get('is_privileged_user', False)}
        - Overall Risk Score: {user_data['risk_score']}/100
        - Known Framework Flags: {user_data['regulatory_impact']}
        
        Maintain a formal, authoritative, and precise cybersecurity compliance tone. Do not mention system prompts in your response.
        """

        try:
            # Safely fetch key from local environment OR Streamlit production secrets
            api_key = os.getenv("GEMINI_API_KEY") or st.secrets.get(
                "GEMINI_API_KEY"
            )

            if not api_key:
                st.error(
                    "API Key Missing! Set GEMINI_API_KEY in your env configuration."
                )
                st.stop()

            # Initialize modern 2026 client
            client = genai.Client(api_key=api_key)

            response = client.models.generate_content(
                model="gemini-2.5-flash", contents=prompt
            )

            st.success("Audit Complete!")
            st.markdown(
                "#### 📄 AI-Generated Legal & Security Intelligence Report"
            )
            st.info(response.text)

        except Exception as e:
            st.error(f"Error communicating with Gemini Engine: {e}")
            st.markdown(
                "#### 📄 AI Threat Report (Simulated Compliance View)"
            )
            st.warning(
                f"""
            ### 🚨 Executive Summary
            User **{user_data['username']}** is currently flagged under **{user_data['risk_tier']} Risk**.
            
            ### ⚖️ Framework Impacts
            - **Flagged Deficiencies:** {user_data['regulatory_impact']}
            
            ### 🛡️ Fallback Notice
            Please verify your local backend connection parameters to fetch live AI recommendations.
            """
            )