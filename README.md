# 🛡️ AccessGuard AI — IAM Security & Compliance Analytics

AccessGuard AI is an **Agentic IAM Security Analytics and Compliance Platform** built using Python, Streamlit, and Groq inference pipelines.

The platform continuously tracks real-time behavioral identity logs to calculate risk profiles, catch active credential attacks (e.g., brute-force or hijacked sessions), and instantly maps anomalies to explicit global IT frameworks (**SOC 2, ISO 27001, GDPR, and India's DPDPA 2023**) to catch compliance failures before they scale into data breaches or regulatory fines.

🖥️ **Live Application:** [AccessGuard AI Dashboard](https://accessguardai-xewgkp5ksxfxet9uk5ms7u.streamlit.app/)

---

## 🚀 Key Features

* **📊 Risk Tier Distribution:** This pie chart breaks down your entire user base by severity (Low, Medium, High, Critical), instantly showing the overall proportion of compromised or non-compliant accounts that require immediate attention.
* **📈 User Risk Scores vs. Failed Logins:** This scatter plot maps login failures against total calculated risk while factoring in account dormancy (bubble size), allowing analysts to visually isolate dangerous outliers—such as an active admin experiencing a brute-force attack—at a single glance.
* **🔍 Identity & Compliance Risk Registry:** This section displays your searchable master database, dynamically highlighting high-risk and critical users using conditional color-coding. Simultaneously, it acts as a legal translator by automatically appending precise regulatory violations (**like GDPR Art. 32, ISO 27001, and DPDPA Sec. 8**) directly to each flagged user's row based on their specific security anomalies.
* **🤖 Autonomous Compliance & Security Agent:** This section is the brain of the platform. When a security analyst selects a flagged user, the Groq inference engine acts as an automated incident responder and compliance auditor by delivering a structured report with three core items:
  * **Executive Threat Summary:** It analyzes raw behavioral anomalies (like impossible travel or high failed logins) to calculate the account's immediate "blast radius" and threat level.
  * **Regulatory Non-Compliance Audit:** It identifies the exact clauses and global IT frameworks (such as ISO 27001 access control gaps, SOC 2 monitoring failures, GDPR data security principles, and DPDPA compliance pillars) being broken by that user's profile.
  * **Playbook Mitigation Actions:** It generates an instant, step-by-step technical containment strategy—instructing the security team precisely how to isolate the account, revoke active OAuth tokens, and reset multi-factor authentication (MFA) to bring the user back into compliance.

---

## 🛠️ Current Tech Stack

* **Language:** Python 3.11+
* **Data Processing:** Pandas
* **Frontend UI:** Streamlit
* **AI Inference:** `groq` SDK (`llama-3.3-70b-versatile`)
* **Visualizations:** Plotly Express
* **Document Compilation:** FPDF2 (Pure Python PDF compiler)

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

**PDF Generation**:
<img width="605" height="559" alt="image" src="https://github.com/user-attachments/assets/f17cdcc8-ae91-411c-ab89-27517f808930" />


Workflow:
<img width="3514" height="2766" alt="mermaid-diagram" src="https://github.com/user-attachments/assets/d7d8e02b-0f56-45e6-a964-c92f36579aae" />


## 1. Data Ingestion (Backend)

The dashboard starts by reading your raw cybersecurity log data (stored in a CSV file).

* **The Tech:** It loads this data into a **Pandas DataFrame** (an in-memory data table). To keep the app fast, it uses **caching**, meaning it loads the file into memory once rather than reading it from the hard drive every time you click a button.

## 2. Compliance Mapping (Logic Layer)

Before showing anything on the screen, the code runs a script to check if any security rules or international laws are being broken.

* **The Tech:** It uses conditional Python statements (**If/Else logic**) to scan the data columns. For example: if `days_inactive > 90`, it appends a text string flagging a **GDPR violation**. This converts raw numbers into clear legal compliance metadata.

## 3. UI Rendering (Frontend)

The app displays your data using interactive graphs and a clean master list of users.

* **The Tech:** The interface is built with **Streamlit** (a Python frontend framework). The pie charts and scatter plots are generated via **Plotly**, which sends interactive charts directly to your web browser. The master list uses **conditional formatting** to automatically style dangerous user rows in red based on their calculated risk scores.

### 4. AI Agent Auditing & Document Generation (LLM Layer)

When a security analyst triggers an audit for a high-risk user, the platform executes a real-time containment and reporting pipeline powered by ultra-low-latency inference.

* **The AI Inference Tech:** The application extracts the user's operational telemetry row, serializes it into a structured payload, and transmits it via the official **`groq` SDK** to the **`llama-3.3-70b-versatile`** model. Operating at a low temperature setting (0.3) to minimize hallucinations, the model functions as an automated incident responder—instantly outputting a specialized, multi-section containment playbook in Markdown format.
* **The PDF Generation Engine:** Once the Markdown payload is returned, the application passes it to a native, pure-Python document generation pipeline powered by **`fpdf2`**. To prevent the binary segmentation faults common to heavy web-rendering engines in cloud containers, the engine implements a strict regex pre-filter (`[^\x00-\x7F]+`) to sanitize non-ASCII characters and emojis. The text is dynamically parsed into explicit layout cells and margins, compiled directly in-memory as a binary byte-stream, and delivered seamlessly via a secure Streamlit download bridge.

## 🔧 Installation & Local Deployment

1. **Clone the Repository:**
   ```bash
   git clone [https://github.com/allison179/AccessGuardAI.git](https://github.com/allison179/AccessGuardAI.git)
   cd AccessGuardAI

pip install -r requirements.txt

GROQ_API_KEY = "your-groq-api-key"

python src/generate_login_history.py

streamlit run src/dashboard.py
