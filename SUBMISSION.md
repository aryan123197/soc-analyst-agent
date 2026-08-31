# Devpost Submission — SOC Analyst Agent

**Track Target:** The Fortified Enterprise Fleet  
**Hackathon:** [All Things Agentic Hackathon](https://allthingsagentichackathon.devpost.com/)  
**Google Cloud Project Name:** `SOC Analyst Agent` (Project ID: `newproject-464521`, Region `us-central1`)  
**Live Cloud Run HTTPS URL:** [https://soc-analyst-agent-ek2ft62bza-uc.a.run.app](https://soc-analyst-agent-ek2ft62bza-uc.a.run.app)  

---

## Project Title
**SOC Analyst Agent — Zero-Trust Enterprise Security Pipeline**

## Tagline
A zero-trust security pipeline shielding enterprise AI agent fleets with Vertex AI Model Armor, Gemini 3.5 Flash, GEAP Memory Bank, and deterministic Agent Gateway policy controls.

---

## Elevator Pitch (Short — 194 chars)
SOC Analyst Agent is a zero-trust GCP security pipeline defending AI agent fleets from prompt injection & obfuscation using Vertex AI Model Armor, Gemini 3.5, and deterministic gateway controls.

---

## About the Project

### 💡 Inspiration
Modern Security Operations Centers (SOCs) are overwhelmed by thousands of daily alerts, support tickets, and monitored email streams. While autonomous AI agents promise to automate SOC triage and incident response, putting AI agents on the frontlines introduces a dangerous new attack surface. 

In enterprise environments, untrusted external inputs—such as a customer support ticket or a security log—often contain hidden adversarial payloads: **indirect prompt injections, tool poisoning, Base64/Hex obfuscation evasions, and multi-ticket campaign attacks**. When an autonomous agent ingests these raw payloads without strict perimeter defenses, the attacker can hijack the agent's instructions, trick it into granting elevated privileges, or exfiltrate sensitive credentials.

We built **SOC Analyst Agent** to prove that enterprise AI agent fleets can operate with high autonomy while remaining battle-hardened against modern AI threats. By building a zero-trust, defense-in-depth security pipeline on Google Cloud, we isolated untrusted data, placed AI guardrails at the edge, and enforced deterministic policy controls.

---

### 🛡️ What It Does
**SOC Analyst Agent** is a zero-trust security pipeline that automates SOC alert ingestion, threat intelligence enrichment, prompt injection defense, and incident triage—while ensuring that no untrusted input can ever compromise the agent fleet.

The pipeline enforces a 4-stage zero-trust architecture:

1. **Stage 1: Read-Only Ingestion & Threat Intel Extraction:** Untrusted data (emails, tickets, log streams) is isolated in a read-only sandbox. An IOC Engine extracts technical Indicators of Compromise (IPs, MD5/SHA256 hashes, URLs) and screens links in real time via **Google Cloud Web Risk API**.
2. **Stage 2: Vertex AI Model Armor Edge Defense:** Inputs pass through an inline **Vertex AI Model Armor** guardrail. Our custom **Decode-and-Rescan Engine** decodes Base64, Hexadecimal, and URL-encoded candidate substrings, catching obfuscated evasions before they reach the LLM. Malicious inputs are auto-quarantined at the edge.
3. **Stage 3: Gemini 3.5 Flash Triage & GEAP Memory Bank:** Clean inputs are triaged by **Gemini 3.5 Flash**, enriched by domain-scoped historical context recalled from **Gemini Enterprise Agent Platform (GEAP) Memory Bank**. This enables the agent to detect **multi-stage cross-ticket campaign attacks** that appear benign in isolation but trigger privilege escalation when correlated across tickets.
4. **Stage 4: Deterministic Agent Gateway Policy Choke Point:** External actions (`escalate`, `close`, `notify`) must pass through a deterministic Gateway Policy Choke Point. Authorized actions automatically dispatch outbound incidents to **Jira Service Desk**, **ServiceNow ITSM**, **Salesforce Service Cloud**, **Splunk HEC**, and **PagerDuty**, sealed with an **Immutable SHA-256 Cryptographic Audit Certificate**.

---

### ⚙️ How We Built It
We built **SOC Analyst Agent** natively on **Google Cloud Platform** and modern open-source standards:

* **Vertex AI Model Armor (`google-cloud-modelarmor 0.7.1`):** Edge guardrail template (`soc-analyst-armor-template`) enforcing Prompt Injection & Jailbreak prevention, Sensitive Data Protection (SDP), and Malicious URI screening.
* **Gemini 3.5 Flash (`google-genai 2.20.0`):** High-speed LLM reasoning engine for alert classification and severity assessment.
* **GEAP Memory Bank (`google-cloud-aiplatform 1.165.1`):** Reasoning Engine (`5030737937319329792`) providing domain-scoped memory recall for multi-turn campaign correlation.
* **Google Cloud Web Risk API (`webrisk.googleapis.com`):** Real-time URL malware and phishing classification.
* **Cloud Run & Artifact Registry:** Serverless container deployment (`soc-analyst-agent`) providing high availability and HTTPS endpoints.
* **Cloud Firestore (`google-cloud-firestore 2.29.0`):** Persistence for incident cases, historical memory recall, and telemetry traces.
* **OpenTelemetry (`opentelemetry-sdk`):** Multi-hop distributed tracing generating millisecond-accurate waterfall span graphs.
* **FastAPI & React Web Console:** Server-Sent Events (SSE) streaming dashboard rendering live incident cards, threat intel boxes, and interactive Red Team Attack Studio.

---

### 🚧 Challenges We Faced

1. **Closing Obfuscation Evasion Gaps in Model Armor:**  
   During empirical security probing, we discovered that while standard text injections were blocked by Model Armor, **bare Base64 strings** and **Hex/URL-encoded payloads wrapped in plausible business text** (e.g. `Ticket update ref#4471: <encoded_blob>`) bypassed content filters because screeners evaluate literal text.  
   *Our Solution:* We engineered `_decode_candidates()` into `BaseModelArmor.screen()`, which scans inputs for candidate encoded substrings, decodes valid UTF-8 strings, and re-screens them against Model Armor. This closed the evasion gap completely.

2. **Navigating Live GEAP Memory Bank API Behaviors:**  
   Integration testing against the live Memory Bank API revealed that certain fields like `description` and `display_name` were dropped by the backend service, and `scope` required exact-set matching.  
   *Our Solution:* We encoded case references directly into fact strings (`"[case:<ref>] ..."`), allowing domain-scoped historical memory recall to function reliably across multi-ticket campaigns.

3. **Enforcing Policy Gates without LLM Self-Policing:**  
   Relying on LLMs to enforce their own permission boundaries is inherently unsafe.  
   *Our Solution:* We engineered a deterministic, non-LLM policy gateway (`gateway.py`) that strictly validates actor identity and allowed action types, acting as a single choke point before any external API is touched.

---

### 🏆 Accomplishments That We're Proud Of

* **100% Test Pass Rate:** Built a comprehensive automated test suite with **67 passing tests** covering telemetry, threat intel, red-team mutation, live SSE endpoints, and pipeline security.
* **Production GCP Deployment:** Fully deployed to Google Cloud Run under project **`SOC Analyst Agent`** (Project ID: `newproject-464521`), with 100% live HTTPS endpoint availability.
* **Legal-Grade Cryptographic Auditability:** Implemented append-only SHA-256 Merkle root hash certificates for every processed incident, providing tamper-evident audit trails for SOC 2 and ISO 27001 compliance.
* **Full Enterprise SIEM & ITSM Connectors:** Built bi-directional synchronization supporting **Jira Service Desk**, **ServiceNow ITSM**, **Salesforce Cloud**, **Splunk HEC**, and **PagerDuty**.

---

### 🎓 What We Learned
* **Content screening must precede context assembly:** Passing un-screened external content into an LLM context—even with strong system prompts—invites indirect prompt injection.
* **Decode-and-rescan is required for edge defense:** Attackers routinely use simple encoding schemes to bypass string-matching screeners; edge pre-screening must decode candidate blobs before evaluation.
* **Testing against live GCP APIs is essential:** Mocked unit tests passed proto fields that live services dropped. Validating against actual Google Cloud APIs was key to producing a production-ready application.

---

### 🔮 What's Next for SOC Analyst Agent
* **Automated SOAR Playbook Execution:** Expanding the Gateway to trigger automated Cloud Functions for IP blocking and firewall rule updates.
* **Expanded SIEM Connectors:** Adding native connectors for Microsoft Sentinel, CrowdStrike Falcon, and Elastic Security.
* **Multi-Tenant Policy Gateways:** Extending gateway IAM authorization to support multi-region enterprise fleets.
