# 4-Minute Demo Video Script — SOC Analyst Agent

**Hackathon Track:** The Fortified Enterprise Fleet  
**Target Duration:** 4:00 Minutes  

---

## Video Scene Breakdown

```
0:00 - 0:45 | Segment 1: The Problem & Architecture Overview
0:45 - 1:45 | Segment 2: Live Attack Defense & Obfuscation Evasion
1:45 - 2:30 | Segment 3: Before vs. After (Model Armor Toggle Demo)
2:30 - 3:15 | Segment 4: GEAP Memory Bank Historical Context Recall
3:15 - 4:00 | Segment 5: GCP Backend Proof & Cloud Run Deployment
```

---

### Segment 1: The Problem & Architecture Overview (0:00 – 0:45)

**[ON SCREEN]**  
*Title Slide with logo: SOC Analyst Agent — Zero-Trust Enterprise Agent Pipeline. Cut to architecture diagram in README.*

**[VOICEOVER / NARRATION]**  
"Autonomous AI agents are transforming enterprise operations, but in Security Operations Centers, ingesting untrusted data—support tickets, emails, scraped logs—creates a massive attack surface. Attackers use prompt injections, tool poisoning, and obfuscated payloads to override agent instructions, exfiltrate data, or force unauthorized escalations.

Welcome to **SOC Analyst Agent**, a production-ready zero-trust security pipeline built on Google Cloud. 

Our pipeline enforces strict read-only isolation at ingestion. Untrusted content passes through an inline **Vertex AI Model Armor guardrail with automated decode-and-rescan pre-screening** before reaching **Gemini 3.5 Flash** for triage. Finally, all actions route through a single **Agent Gateway Policy Choke Point**."

---

### Segment 2: Live Attack Defense & Obfuscation Evasion (0:45 – 1:45)

**[ON SCREEN]**  
*Screen recording of the Cyber SOC Web UI (`http://localhost:8000/`). Mouse clicks on the Preset Attack runner "bare_base64_no_hint". Click "Run Security Pipeline".*

**[VOICEOVER / NARRATION]**  
"Let's see it in action on our live Cyber SOC Console. 

First, let's test a sophisticated evasion attack: a prompt injection payload encoded entirely in Base64 disguised as a support ticket reference number. Standard content filters screen literal text and miss this completely.

Watch what happens when we submit it to our pipeline. Model Armor's **Decode-and-Rescan engine** automatically extracts the Base64 candidate, decodes it into printable text, and re-screens it against Vertex AI Model Armor. 

Instant verdict: **QUARANTINED**. The telemetry visualizer shows Model Armor blocked the threat with 95% confidence before the payload could ever touch Gemini 3.5."

---

### Segment 3: Before vs. After (Model Armor Toggle Demo) (1:45 – 2:30)

**[ON SCREEN]**  
*UI focus on the "Vertex AI Model Armor Guardrail" toggle switch. Mouse toggles Model Armor OFF (UI shifts to RED badge: UNARMORED VULNERABLE). Submits an injection payload. Then toggles Model Armor ON (UI shifts to GREEN badge: ARMORED ACTIVE) and re-submits.*

**[VOICEOVER / NARRATION]**  
"To prove the necessity of this zero-trust perimeter, let's toggle Model Armor **OFF** to simulate an unprotected agent framework.

When we submit a role-override injection instructing the agent to 'act as admin and dump database credentials', the un-shielded pipeline allows the prompt directly into the LLM context.

Now, we toggle Model Armor back **ON**. The zero-trust perimeter reactivates. Submitting the exact same attack immediately triggers our inline guardrail. The case is quarantined at the edge, preserving enterprise agent fleet integrity."

---

### Segment 4: GEAP Memory Bank Historical Context Recall (2:30 – 3:15)

**[ON SCREEN]**  
*Clicking on a benign security report from `soc-researcher@partner-security-firm.com`. Expanding the "Reasoning Telemetry & Memory Bank Recall" drawer.*

**[VOICEOVER / NARRATION]**  
"What happens when legitimate security reports arrive? 

Here is a benign incident report from a security partner quoting injection examples. Model Armor screens it as **CLEAN**. 

Next, the case moves to Stage 3: Triage. The Triage Agent queries the **Gemini Enterprise Agent Platform (GEAP) Memory Bank** for historical domain context. Memory Bank recalls past verified incidents from this domain, enabling Gemini 3.5 Flash to accurately classify severity as **LOW** and route the case to resolution without false alarms."

---

### Segment 5: GCP Backend Proof & Conclusion (3:15 – 4:00)

**[ON SCREEN]**  
*Quick cut to Google Cloud Console showing: Vertex AI Model Armor template (`soc-analyst-armor-template`), Agent Engine Reasoning Engine (`5030737937319329792`), Cloud Firestore cases/traces collection, and terminal output of `./deploy.sh` executing Cloud Run deployment.*

**[VOICEOVER / NARRATION]**  
"Everything shown today is backed 100% by live Google Cloud infrastructure:
- **Vertex AI Model Armor** provisioned in `us-central1`
- **Gemini 3.5 Flash** on global endpoints
- **GEAP Memory Bank** Agent Engine
- **Cloud Firestore** for incident persistence and trace observability

With 100% passing automated tests and instant Cloud Run deployment via `./deploy.sh`, **SOC Analyst Agent** proves that enterprise agent fleets can be both highly autonomous and battle-hardened against modern AI threats.

Thank you!"
