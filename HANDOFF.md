# SOC Analyst Agent — Handoff

**Last updated:** 2026-08-27 · **GCP project:** `newproject-464521` (project number `434061698035`) · **Region:** `us-central1`

A pipeline that ingests untrusted security alerts, screens them for prompt-injection
and data-exfiltration attacks, triages them with an LLM, and routes any external
action through a single policy choke point.

---

## Pipeline shape

```
ingestion → Model Armor screen → triage (Gemini + Memory Bank) → action (gateway)
```

Everything upstream of the gateway is read-only by construction. The gateway is the
only component that can touch anything external.

| Stage | Module | Backing service |
|---|---|---|
| Ingestion | `soc_agent/agents/ingestion.py` | — |
| Screening | `soc_agent/services/model_armor.py` | **Real** GCP Model Armor |
| Triage | `soc_agent/agents/triage.py` | **Real** Gemini 3.5 Flash |
| Recall | `soc_agent/services/memory_bank.py` | **Real** GEAP Memory Bank |
| Case store | `soc_agent/services/store.py` | **Real** Firestore |
| Action policy | `soc_agent/services/gateway.py` | **Local** — see below |
| Traces | `soc_agent/services/trace.py` | Firestore + `/traces` HTML view |

---

## What is real vs. local

**Real GCP services:** Model Armor, Gemini, Memory Bank, Firestore.

**Deliberately local:** `gateway.py` (identity + allowed-action policy). This is *not*
an unfinished stub — it was a researched decision. Google's Agent Gateway is L7 network
infrastructure under `networkservices.googleapis.com` (not enabled here), which solves a
different problem than the in-process policy check this pipeline needs. The Agent Identity
API exists but its Python client is at `0.1.0` — a single release, versus `google-cloud-modelarmor`'s
mature `0.7.1`. Wiring either would cost two API enablements and a v0.1.0 dependency to
replace 48 lines that already do the job. **Present the local gateway as an intentional
choke-point design, not a gap.**

---

## Configuration

`.env` (gitignored — not in the repo, recreate from `.env.example`):

```
GOOGLE_CLOUD_PROJECT=newproject-464521
GOOGLE_CLOUD_LOCATION=us-central1
GEMINI_MODEL=gemini-3.5-flash
AGENT_ENGINE_ID=5030737937319329792
```

Two settings that look wrong but are not:

- **`GEMINI_LOCATION` is unset on purpose.** It defaults to `global` in `config.py`.
  Gemini 3.5+ is served *only* from the global endpoint, never regional ones like
  `us-central1`. Setting it to the GCP region will break triage.
- **`GOOGLE_CLOUD_LOCATION` vs `GEMINI_LOCATION` are split deliberately** (commit `f08fbe7`)
  for exactly that reason.

Backend selection is derived, not configured — see `config.py`:

| Condition | Effect |
|---|---|
| `GOOGLE_CLOUD_PROJECT` unset | Local JSON store + heuristic screening (no GCP needed) |
| `GOOGLE_CLOUD_PROJECT` set | Firestore + real Model Armor |
| `+ AGENT_ENGINE_ID` set | Real Memory Bank; otherwise falls back to Firestore |

**Failure mode to know:** `triage()` wraps the LLM call in `try/except` and silently
falls back to a regex heuristic. A misconfigured model produces *degraded triage, not an
error*. If results look suspiciously keyword-shaped, verify the model resolves before
debugging anything else.

---

## GCP resources this depends on

| Resource | Identifier | Created by |
|---|---|---|
| Model Armor template | `soc-analyst-armor-template` | `python -m soc_agent.scripts.provision_model_armor` |
| Agent Engine (Memory Bank) | `reasoningEngines/5030737937319329792` | `python -m soc_agent.scripts.provision_memory_bank` |

Both scripts are idempotent — safe to re-run.

### Required IAM (easy to miss)

Memory Bank embeds every fact via `text-embedding-005`, so its service agent needs
prediction access **in addition to** the role it gets automatically:

```
gcloud projects add-iam-policy-binding newproject-464521 \
  --member="serviceAccount:service-434061698035@gcp-sa-aiplatform-re.iam.gserviceaccount.com" \
  --role="roles/aiplatform.user"
```

Already applied to this project. Without it, every write fails with
`403 ... aiplatform.endpoints.predict`. Embedding cannot be disabled, so this is mandatory.

---

## Memory Bank: three non-obvious API behaviors

All verified against the live service. The proto is misleading on each — **do not trust
it without a read-back.**

1. **`description` and `display_name` are silently dropped.** `create_memory` accepts them
   and returns success; only `fact` and `scope` persist. Per-entry metadata must be encoded
   into `fact`. This code uses a `"[case:<ref>] "` prefix, parsed off on read.
2. **Scope matching is exact, not subset.** A memory stored with scope `{a,b,c}` is *not*
   returned by a query for `{a,b}`. So `scope` cannot carry per-entry metadata without making
   entries unretrievable by their common key. This is why `case_ref` lives in the fact text.
3. **Memory Bank is v1beta1-only.** `aiplatform_v1` has zero Memory types. Expect churn.

Also: every call is parented to an Agent Engine — there is no project-level Memory Bank.
`create_memory` is a long-running operation (writes block on `.result()`); retrieval is synchronous.

> **Lesson worth carrying:** behavior #1 shipped past a green mocked test suite. The mocks
> echoed `description` back because that is what the proto implies; the live API discarded it,
> and `similar_past_cases` would have been silently empty in the demo. **Verify writes by
> reading them back against the real service.**

---

## Running it

```bash
source venv/bin/activate
pip install -r requirements.txt

pytest tests/ -q          # 18 tests
python run_demo.py        # scripted attack corpus
uvicorn soc_agent.server:app --reload
```

Endpoints: `POST /ingest` · `GET /traces` (HTML) · `GET /traces/{case_id}` · `GET /health`

> `/health`, not `/healthz` — the latter collided with Cloud Run routing (commit `50b4b04`).

**Test-suite caveat:** `tests/test_pipeline.py` makes live Model Armor calls and takes
~2.5 min. Intermittent `504 DeadlineExceeded` failures are network flake, not regressions —
re-run the single test to confirm before investigating.

---

## Known open items

- **Five probe memories** remain in the live Memory Bank under `.test` subject keys
  (`evil-corp.test`, `roundtrip2.test`, `scopetest.test`, `pipeline-e2e.test` ×2). Inert and
  scoped away from demo domains, but they are test residue. The `evil-corp.test` entry
  predates the `case_ref` fix and has no `[case:]` prefix — it exercises the empty-`case_ref`
  fallback path.
- **No README.** This document is the only prose describing the system.
- **Multi-turn injection is out of scope** and documented as such (commit `2d5f9fb`).
- **Memory Bank writes are synchronous LROs**, adding latency per triage. Fine at demo
  volume; would need batching for real throughput.
