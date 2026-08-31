# SOC Analyst Agent — Zero-Trust Enterprise Pipeline

> **Hackathon Target:** [All Things Agentic Hackathon](https://allthingsagentichackathon.devpost.com/) · **Track:** *The Fortified Enterprise Fleet*  
> **Google Cloud Project:** `newproject-464521` (Project #`434061698035`, Region `us-central1`)  
> **Live HTTPS Web Console:** [https://soc-analyst-agent-ek2ft62bza-uc.a.run.app](https://soc-analyst-agent-ek2ft62bza-uc.a.run.app)  

---

## 1. Executive Overview

Enterprise Security Operations Centers (SOCs) process thousands of untrusted inputs daily (monitored emails, support tickets, web log streams). When autonomous AI agents process this raw data, they expose the enterprise to high-risk attack vectors: **prompt injections, jailbreaks, Base64/Hex obfuscation evasions, multi-stage campaign attacks, and malicious C2 URLs**.

The **SOC Analyst Agent** establishes a production-grade, zero-trust security pipeline built on **Google Cloud Platform**:
- **Vertex AI Model Armor** inline edge guardrail with **Pre-Screening Decode-and-Rescan** (closing Base64, Hexadecimal, and URL-encoding evasion gaps).
- **Google Cloud Web Risk API** (`webrisk.googleapis.com`) for real-time URL phishing and malware classification.
- **Gemini 3.5 Flash** for intelligent incident severity triage.
- **Gemini Enterprise Agent Platform (GEAP) Memory Bank** for domain-scoped context recall and **Multi-Stage Cross-Ticket Campaign Correlation**.
- **Deterministic Agent Gateway Policy Choke Point** enforcing read-only ingestion isolation and identity authority.
- **Enterprise SIEM & ITSM Connectors** featuring outbound dispatchers for **Jira Service Desk REST API**, **ServiceNow Incident API**, and **Splunk HEC (HTTP Event Collector)**.
- **Inbound Webhook Synchronization** (`/api/v1/webhooks/jira`, `/api/v1/webhooks/servicenow`, `/api/v1/webhooks/{source}`) reconciling analyst updates into Cloud Firestore.
- **Immutable SHA-256 Cryptographic Audit Certificates** (SOC 2 / ISO 27001 legal auditing).

---

## 2. System Architecture & Component Interaction

The diagram below details how the **React Web Console / Dashboard Frontend** communicates with the **FastAPI Backend**, **Vertex AI Model Armor**, **Google Cloud Web Risk API**, **Gemini 3.5 Flash**, **GEAP Memory Bank**, **Cloud Firestore**, and **Enterprise Connectors**:

```mermaid
flowchart TD
    subgraph Client Layer
        UI[Cyber SOC Web Console\nReact / Tailwind / SSE Dashboard]
        INBOUND_WH[Inbound ITSM Webhooks\nJira / ServiceNow Analyst Sync]
    end

    subgraph FastAPI Backend & Routing
        API[FastAPI Gateway Engine\nsoc_agent/server.py]
        SSE[Server-Sent Events Stream\n/live/stream Real-Time Feed]
    end

    subgraph Stage 1: Isolated Ingestion & Threat Intel
        ING[Ingestion Sandbox\nRead-Only Agent Isolation]
        IOC[IOC Extraction Engine\nIPs / Hashes / URLs]
        WEBRISK[Google Cloud Web Risk API\nwebrisk.googleapis.com]
    end

    subgraph Stage 2: Vertex AI Model Armor Guardrail
        ARMOR{Vertex AI Model Armor\nsoc-analyst-armor-template}
        DECODE[Pre-Screening Engine\nBase64 / Hex / URL Decode-and-Rescan]
        QUARANTINE[Quarantine Edge Containment\nBlocked Threat Isolated]
    end

    subgraph Stage 3: Gemini 3.5 & GEAP Memory Bank
        GEMINI[Triage Agent\nGemini 3.5 Flash]
        MEMORY[(GEAP Memory Bank\nReasoning Engine ID 5030737937319329792)]
        CAMPAIGN[Cross-Ticket Campaign\nCorrelation Engine]
    end

    subgraph Stage 4: Agent Gateway & Connectors
        GATEWAY{Agent Gateway Policy Choke Point\nIdentity: action-agent}
        HITL[Human SOC Analyst Review Queue\nApprove / Quarantine / Close]
        JIRA[Jira Service Desk REST API]
        SNOW[ServiceNow Incident API]
        SPLUNK[Splunk HEC Collector]
    end

    subgraph Stage 5: Persistence & Audit Layer
        STORE[(Cloud Firestore Database\ncases/{caseId} & traces/{caseId})]
        AUDIT[Immutable Audit Trail Engine\nSHA-256 Merkle Hash Chain]
    end

    UI -->|POST /ingest| API
    INBOUND_WH -->|POST /api/v1/webhooks/*| API
    API -->|Subscribe| SSE -->|Real-Time Hop Telemetry| UI
    
    API --> ING --> IOC --> WEBRISK
    ING --> DECODE --> ARMOR
    
    ARMOR -- "VERDICT: BLOCKED" --> QUARANTINE --> STORE
    ARMOR -- "VERDICT: CLEAN" --> GEMINI
    WEBRISK -->|Phishing / Malware Verdict| GEMINI
    
    GEMINI <-->|Domain Context Search| MEMORY
    GEMINI <-->|Scattered Vector Recall| CAMPAIGN
    
    GEMINI -->|Triage Severity| GATEWAY
    GATEWAY -- "Severity: High / Critical" --> HITL --> UI
    GATEWAY -- "Action Authorized" --> JIRA
    GATEWAY -- "Action Authorized" --> SNOW
    GATEWAY -- "Action Authorized" --> SPLUNK
    
    JIRA & SNOW & SPLUNK --> STORE
    GATEWAY --> AUDIT --> STORE
```

---

## 3. Core Enterprise Capabilities

### A. Pre-Screening Decode-and-Rescan Edge Perimeter
Attackers wrap malicious prompts inside Base64, Hexadecimal, or URL-encoded tracking strings (e.g. `Ticket update ref#4471: <encoded_blob>`). `BaseModelArmor.screen()` extracts candidates, decodes printable strings, and re-screens them through Vertex AI Model Armor. If any candidate trips a filter, the case is auto-quarantined.

### B. Google Cloud Web Risk API Integration
Extracted URLs are screened against Google's global threat database (`webrisk.googleapis.com`) for `MALWARE`, `SOCIAL_ENGINEERING`, and `UNWANTED_SOFTWARE`.

### C. Multi-Stage Cross-Ticket Campaign Correlation
Attackers split prompt injections across separate support tickets (Ticket 1: System prompt override context $\rightarrow$ Ticket 2: Credential dump payload). The pipeline queries GEAP Memory Bank by sender domain, correlates Ticket $N$ with Ticket $N-1$, and escalates multi-stage injection attempts to `CRITICAL` (`multi-stage-campaign`).

### D. Enterprise SIEM & ITSM Outbound Connectors
- **Jira Service Desk REST API**: Dispatches incident tickets directly to Jira under project key `JIRA_PROJECT_KEY`.
- **ServiceNow Incident API**: Creates incidents in ServiceNow with `correlation_id` matching `case_id`, setting impact/urgency.
- **Splunk HEC (HTTP Event Collector)**: Indexes structured event logs to Splunk HTTP collector endpoints.
- **Simulation Fallback Mode**: When credentials are unset, connectors generate mock incident keys (`SOC-1042`, `INC001042`), guaranteeing seamless offline demo execution.

### E. Inbound Webhook Status Reconciliation
Inbound webhooks (`/api/v1/webhooks/jira`, `/api/v1/webhooks/servicenow`, `/api/v1/webhooks/{source}`) capture status transitions (e.g., Jira issue changed to `In Progress` or ServiceNow incident state changed to `Resolved`) and analyst work notes, synchronizing status in Cloud Firestore and publishing SSE stream updates.

### F. Immutable Cryptographic Audit Certificate Engine
Every processed case generates a tamper-evident SHA-256 Merkle chain audit certificate:
$$\text{Certificate Hash}_n = \text{SHA256}(\text{Hash}_{n-1} + \text{Case ID} + \text{Verdict} + \text{Actor Identity} + \text{Timestamp})$$

---

## 4. API Endpoints Reference

| Endpoint | Method | Description |
| :--- | :---: | :--- |
| `POST /ingest` | `POST` | Ingests alert through the 5-stage zero-trust pipeline. |
| `GET /corpus` | `GET` | Fetches the 12 curated attack corpus preset cases. |
| `POST /api/v1/redteam/encode` | `POST` | Red Team Attack Studio payload mutator (Base64, Hex, URL, Ticket wrap). |
| `GET /api/v1/audit/verify/{case_id}` | `GET` | Cryptographically verifies SHA-256 Merkle audit certificate for a case. |
| `POST /api/v1/webhooks/jira` | `POST` | Inbound webhook handler for Jira Service Desk analyst updates. |
| `POST /api/v1/webhooks/servicenow` | `POST` | Inbound webhook handler for ServiceNow incident status updates. |
| `POST /api/v1/webhooks/{source}` | `POST` | Generic webhook handler for custom SIEM/ITSM tools. |
| `POST /api/admin/evals/run` | `POST` | Runs benchmark evals suite with LLM-as-a-Judge and payload mutation metrics. |
| `GET /health` | `GET` | Health check endpoint. |

---

## 5. Spin-up & Local Reproducibility Guide

Follow these step-by-step instructions to set up and run the project locally.

### Prerequisites
- **Python**: `3.11` or higher installed
- **Node.js**: `v18+` (for React frontend build)
- **Git**: installed

### Step-by-Step Setup

```bash
# 1. Clone the repository and navigate into the workspace
git clone https://github.com/aryan123197/soc-analyst-agent.git
cd soc-analyst-agent

# 2. Activate virtual environment and install Python dependencies
source venv/bin/activate
pip install -r requirements.txt

# 3. Build the React Frontend static assets
cd frontend
npm install
npm run build
cd ..

# 4. Copy environment configuration (.env)
cp .env.example .env

# 5. Run the complete automated test suite (100% passing)
pytest tests/ -q

# 6. Execute the interactive SIEM/ITSM Connectors Demo Script
python soc_agent/scripts/demo_connectors.py

# 7. Start the FastAPI backend server with live web UI
uvicorn soc_agent.server:app --reload --port 8000
```

Open your browser to **`http://localhost:8000/`** to interact with the Cyber SOC Command Center UI!

---

## 6. Cloud Run Deployment Guide

To deploy the application to Google Cloud Run:

```bash
# Set Google Cloud Project and deploy using the automated deployment script
chmod +x deploy.sh
./deploy.sh
```

Or deploy directly using the Google Cloud SDK:

```bash
gcloud run deploy soc-analyst-agent \
  --source . \
  --region us-central1 \
  --platform managed \
  --allow-unauthenticated \
  --set-env-vars "GOOGLE_CLOUD_PROJECT=newproject-464521,GOOGLE_CLOUD_LOCATION=us-central1,AGENT_ENGINE_ID=5030737937319329792,MODEL_ARMOR_TEMPLATE_ID=soc-analyst-armor-template"
```

