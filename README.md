# AccessGuard AI

Agentic IAM Security Analytics and Compliance Platform built using Python, Streamlit, SQLite, Google Cloud, and AI Agents.

## Goals

- Analyze IAM data
- Detect dormant accounts
- Detect excessive permissions
- Generate risk scores
- Provide AI-powered security recommendations
- Create compliance reports
- Visualize security insights through dashboards

## Planned Tech Stack

- Python
- Pandas
- SQLite
- Streamlit
- Google Cloud Storage
- CrewAI
- Git/GitHub

**Real-time Identity Risk Monitoring & Regulatory Auditing**
This dashboard continuously tracks **real-time behavioral logs** to calculate risk scores and catch active identity attacks (like brute-force or hijacked sessions). Concurrently, it instantly maps those security anomalies to explicit global IT frameworks (**SOC 2, ISO 27001, and GDPR**) to flag compliance failures before they result in data breaches or regulatory fines.

Dashboard(1)<img width="2121" height="1103" alt="image" src="https://github.com/user-attachments/assets/bc6cff0d-15e7-42e5-9399-fe10a7f7c266" />
* **📊 Risk Tier Distribution:** This pie chart breaks down your entire user base by severity (Low, Medium, High, Critical), instantly showing the overall proportion of compromised or non-compliant accounts that require immediate attention.
* **📈 User Risk Scores vs. Failed Logins:** This scatter plot maps login failures against total calculated risk while factoring in account dormancy (bubble size), allowing analysts to visually isolate dangerous outliers—such as an active admin experiencing a brute-force attack—at a single glance.
Dashboard(2)<img width="2064" height="793" alt="image" src="https://github.com/user-attachments/assets/ce0b5d77-8720-4b10-98d8-0db812920cda" />

🔍 Identity & Compliance Risk Registry

This section displays your searchable master database, dynamically highlighting high-risk and critical users using conditional color-coding. Simultaneously, it acts as a legal translator by automatically appending precise regulatory violations (**like GDPR Art. 32 or ISO 27001**) directly to each flagged user's row based on their specific security anomalies.

Identity and Compliance risk registry<img width="2046" height="383" alt="image" src="https://github.com/user-attachments/assets/7b7c4b22-cc50-4299-b2e8-32fdfa3d826c" />

**🤖 AccessGuard AI — Autonomous Compliance & Security Agent**
This section is the brain of the platform. When a security analyst selects a flagged user, the Gemini AI engine acts as an automated incident responder and compliance auditor by delivering a structured report with three items:

* **Executive Threat Summary:** It analyzes raw behavioral anomalies (like impossible travel or high failed logins) to calculate the account's immediate "blast radius" and threat level.
* **Regulatory Non-Compliance Audit:** It identifies the exact clauses and global IT frameworks (such as ISO 27001 access control gaps, SOC 2 monitoring failures, or GDPR data security principles) being broken by that user's profile.
* **Playbook Mitigation Actions:** It generates an instant, step-by-step technical containment strategy—instructing the security team precisely how to isolate the account, revoke active OAuth tokens, and reset multi-factor authentication (MFA) to bring the user back into compliance.
<img width="2026" height="1022" alt="image" src="https://github.com/user-attachments/assets/10d47feb-769b-4e8d-8745-3c6098ce1f31" />
<img width="1967" height="991" alt="image" src="https://github.com/user-attachments/assets/f099fca5-7c51-429e-bb79-ddf8c36c37e4" />
<img width="2056" height="852" alt="image" src="https://github.com/user-attachments/assets/c586fe2f-ff0d-48a5-af2b-7ae0410ae540" />
<img width="2085" height="888" alt="image" src="https://github.com/user-attachments/assets/59f709cc-79ec-476a-a04f-e6824d5d2eb2" />
<img width="2059" height="1043" alt="image" src="https://github.com/user-attachments/assets/7d11f0ed-4615-4210-9115-798e6e3a3c90" />
<img width="2081" height="925" alt="image" src="https://github.com/user-attachments/assets/df728cde-d41d-443d-b9f0-8f1fda90ea98" />
