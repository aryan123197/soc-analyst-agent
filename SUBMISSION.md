# Devpost Submission — SOC Analyst Agent

**Track Target:** The Fortified Enterprise Fleet  
**Hackathon:** [All Things Agentic Hackathon](https://allthingsagentichackathon.devpost.com/)  
**Google Cloud Project:** `newproject-464521` (Project Number `434061698035`, Region `us-central1`)  

---

## Project Title
**SOC Analyst Agent — Zero-Trust Enterprise Agent Pipeline**

## Tagline
A resilient Security Operations Center (SOC) agent pipeline enforcing zero-trust boundaries with Vertex AI Model Armor, Gemini 3.5 Flash, GEAP Memory Bank, and an Agent Gateway Policy Choke Point.

---

## Elevator Pitch
Autonomous security agents in modern enterprise fleets are constantly exposed to untrusted external data—support tickets, monitored emails, and scraped alert logs. Attackers exploit these vectors with prompt injections, tool poisoning, malicious C2 links, and base64/hex obfuscation to hijack agent workflows or exfiltrate sensitive data. 

**SOC Analyst Agent** establishes a zero-trust defense perimeter for enterprise agent fleets. By placing an inline **Vertex AI Model Armor guardrail with automatic decode-and-rescan pre-screening** ahead of **Gemini 3.5 Flash** triage and forcing all external actions through a single **Agent Gateway Policy Choke Point**, our pipeline ensures malicious payloads are auto-quarantined at the edge before ever reaching executive agent execution contexts.

---

## 1. The Problem
Enterprise AI agents designed to automate SOC triage and incident response face critical security vulnerabilities:
1. **Direct & Indirect Prompt Injections:** Payloads hidden in ticket bodies instructing the agent to ignore system instructions, change contact info, or exfiltrate credentials.
2. **Tool Poisoning & Forced Privilege Escalation:** Fake `<tool_description>` tags crafted to look like internal API schemas that trick the agent into granting administrative permissions.
3. **Malicious URIs & C2 Links:** Zero-day phishing and malware links embedded in incident reports.
4. **Obfuscation Evasions:** Payloads wrapped in Base64, Hexadecimal, or URL-encoded tracking parameters (`https://...?redirect=...`) disguised within plausible business text that bypass standard literal-text content filters.

---

## 2. Our Solution & Architecture
We built a resilient, 5-stage zero-trust pipeline on Google Cloud:

```
[Untrusted Inputs] (Tickets, Emails, Alerts)
       │
       ▼
1. INGESTION AGENT (Read-Only Isolation)
       │
       ▼
2. VERTEX AI MODEL ARMOR (Inline Guardrail + Decode-and-Rescan)
       ├─► [BLOCKED] ──► Auto-Quarantine + Firestore Telemetry Trace
       ▼
    [CLEAN]
       │
       ▼
3. TRIAGE AGENT (Gemini 3.5 Flash + GEAP Memory Bank)
       │ (Recalls historical attacker domains & past incident context)
       ▼
4. AGENT GATEWAY (Single Authorized Policy Choke Point)
       │ (Enforces actor identity & allowed actions: escalate, close, notify)
       ▼
5. ACTION AGENT & PERSISTENCE (Firestore Cases & Observability Traces)
```

### Key Architectural Pillars:
- **Ingestion Isolation:** Upstream agents operate in a strictly read-only posture with zero action tools.
- **Model Armor Guardrail (`soc-analyst-armor-template`):** Active filters for Prompt Injection & Jailbreaks, Sensitive Data Protection (SDP), and Malicious URIs (Google Safe Browsing).
- **Decode-and-Rescan Engine:** Automatically detects Base64, Hex, and URL-encoded candidate substrings in input content, safely decodes them, and re-screens the decoded text against Model Armor before passing to LLM triage.
- **Gemini 3.5 Flash + GEAP Memory Bank:** High-speed automated triage enriched by domain-scoped memory recall from previous incident cases (Agent Engine `5030737937319329792`).
- **Agent Gateway Policy Choke Point:** Deterministic in-process gateway ensuring only authorized action agents (`agent_action_authority`) can execute external actions (`escalate`, `close`, `notify`).

---

## 3. Live GCP Tech Stack & APIs Used
- **Vertex AI Model Armor (`google-cloud-modelarmor 0.7.1`):** Provisioned template `soc-analyst-armor-template` in `us-central1`.
- **Gemini 3.5 Flash (`google-genai 2.20.0`):** Configured on global endpoint (`GEMINI_LOCATION=global`) for instant triage reasoning.
- **GEAP Memory Bank (`google-cloud-aiplatform 1.165.1` / `aiplatform_v1beta1`):** Reasoning Engine ID `5030737937319329792` storing per-sender domain incident context.
- **Cloud Firestore (`google-cloud-firestore 2.29.0`):** Incident case management (`cases/{caseId}`) and end-to-end reasoning telemetry (`traces/{caseId}`).
- **FastAPI & Web Console (`fastapi 0.141.1`):** Real-time Cyber SOC Web Dashboard UI with Server-Sent Events (SSE) stream.

---

## 4. Challenges & Engineering Breakthroughs

### Breakthrough 1: Closing Obfuscation Evasion Gaps
During empirical probing against the live Model Armor API, we discovered that while raw injection text was caught, **bare Base64 blobs** and **Hex/URL-encoded payloads wrapped in plausible business context** (e.g. `Ticket update ref#4471: <encoded_blob>`) passed through as `CLEAN` because content screeners evaluate literal text strings.  
*Our Fix:* Built `_decode_candidates()` in `BaseModelArmor.screen()`, which scans for encoded substrings, safely decodes valid UTF-8 strings, and re-screens decoded candidates. All obfuscated evasion samples in our test corpus now trigger automatic quarantine.

### Breakthrough 2: Navigating GEAP Memory Bank API Quirks
Integration testing against the live Memory Bank service revealed critical un-documented behaviors:
1. `description` and `display_name` fields in `create_memory` are silently dropped by the live backend.
2. `scope` matching is exact-set rather than subset-matching.  
*Our Fix:* Encoded case references directly into fact strings (`"[case:<ref>] ..."`), allowing per-sender domain memory recall to function reliably.

### Breakthrough 3: Deterministic Policy Gateway
Rather than relying on LLM self-policing, we implemented a single deterministic gateway choke point (`gateway.py`) that strictly validates actor identity and allowed actions, guaranteeing read-only isolation for upstream triage.

---

## 5. What We Learned
- **Content screening must precede context assembly:** Passing un-screened external content into an LLM context—even with strong system prompts—invites indirect prompt injection.
- **Verification against live GCP APIs is essential:** Mocked unit tests passed proto fields that the live service dropped; testing against real Google Cloud services was key to producing a robust pipeline.

---

## 6. What's Next for SOC Analyst Agent
- **Cross-Case Behavioral Correlation:** Expanding Memory Bank recall to detect multi-turn account takeover patterns across separate tickets.
- **Automated C2 Sandbox Dispatch:** Automatically dispatching extracted malicious URIs to isolated malware analysis sandboxes.
- **Multi-Tenant Policy Gateways:** Extending gateway IAM authorization for multi-region enterprise fleets.
