import type { IngestResult } from "./types";

/**
 * The pipeline as five stages. On a blocked run, everything downstream of
 * Model Armor renders as explicitly *not reached* rather than merely absent --
 * that the LLM was never invoked is the whole point of the demo, so it has to
 * be visible, not inferred from a missing panel.
 */

type State = "done" | "blocked" | "skipped";

interface Stage {
  key: string;
  name: string;
  state: State;
  body: React.ReactNode;
}

function Row({ children }: { children: React.ReactNode }) {
  return <dl>{children}</dl>;
}

function Item({ k, v }: { k: string; v: React.ReactNode }) {
  return (
    <>
      <dt>{k}</dt>
      <dd>{v}</dd>
    </>
  );
}

export function Stages({ res, armorAtRun }: { res: IngestResult; armorAtRun: boolean }) {
  const blocked = res.armor.verdict === "blocked";
  const { armor, triage, action } = res;

  const stages: Stage[] = [
    {
      key: "ingestion",
      name: "1 · ingestion",
      state: "done",
      body: <Row><Item k="case" v={<code>{res.case_id}</code>} /></Row>,
    },
    {
      key: "model_armor",
      name: "2 · model armor",
      state: blocked ? "blocked" : "done",
      body: armorAtRun ? (
        <Row>
          <Item k="verdict" v={<span className={`tag ${armor.verdict}`}>{armor.verdict}</span>} />
          {armor.threat_type && <Item k="threat" v={armor.threat_type} />}
          <Item k="confidence" v={armor.confidence.toFixed(2)} />
          {armor.matched_signal && <Item k="matched" v={<code>{armor.matched_signal}</code>} />}
        </Row>
      ) : (
        <span style={{ color: "var(--bad)" }}>
          armor_enabled=false — content passed to the model unscreened
        </span>
      ),
    },
    {
      key: "triage",
      name: "3 · triage (LLM)",
      state: blocked ? "skipped" : "done",
      body: blocked ? (
        "never invoked — the model did not see this content"
      ) : triage ? (
        <Row>
          <Item k="severity" v={<span className={`tag ${triage.severity}`}>{triage.severity}</span>} />
          <Item k="category" v={triage.category} />
          <Item k="reasoning" v={triage.reasoning} />
          <Item
            k="recalled"
            v={
              triage.similar_past_cases.length
                ? triage.similar_past_cases.map((c) => <code key={c}>{c} </code>)
                : "no similar past cases"
            }
          />
        </Row>
      ) : null,
    },
    {
      key: "action",
      name: "4 · action gateway & connectors",
      state: blocked ? "skipped" : "done",
      body: blocked ? (
        "quarantined — no gateway call issued"
      ) : action ? (
        <div>
          <Row>
            <Item k="action" v={<code>{action.type}</code>} />
            <Item k="identity" v={<code>{action.actor_agent_identity}</code>} />
            {!armorAtRun && (
              <Item
                k="note"
                v={
                  <span style={{ color: "var(--bad)" }}>
                    executed on unscreened input
                  </span>
                }
              />
            )}
          </Row>

          {res.integrations && (
            <div style={{ marginTop: 8, paddingTop: 6, borderTop: "1px dashed rgba(255,255,255,0.1)" }}>
              <div style={{ fontSize: 10, color: "var(--accent-cyan)", fontWeight: 700, marginBottom: 4 }}>
                🌐 ENTERPRISE SIEM & ITSM CONNECTORS
              </div>
              <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
                {res.integrations.jira && (
                  <span className="tag clean" style={{ fontSize: 10 }}>
                    Jira: {res.integrations.jira.issue_key || res.integrations.jira.status}
                  </span>
                )}
                {res.integrations.servicenow && (
                  <span className="tag clean" style={{ fontSize: 10 }}>
                    ServiceNow: {res.integrations.servicenow.number || res.integrations.servicenow.status}
                  </span>
                )}
                {res.integrations.splunk && (
                  <span className="tag clean" style={{ fontSize: 10 }}>
                    Splunk HEC: {res.integrations.splunk.status}
                  </span>
                )}
              </div>
            </div>
          )}
        </div>
      ) : null,
    },
    {
      key: "memory_bank",
      name: "5 · memory bank",
      state: blocked ? "skipped" : "done",
      body: blocked ? "not reached" : "case summary written for future recall",
    },
  ];

  return (
    <div>
      {res.threat_intel && res.threat_intel.has_threats && (
        <div style={{ background: "rgba(245, 158, 11, 0.1)", border: "1px solid rgba(245, 158, 11, 0.3)", borderRadius: 8, padding: "0.65rem 0.85rem", marginBottom: 12 }}>
          <div style={{ color: "var(--amber)", fontSize: 11, fontWeight: 700 }}>🔍 THREAT INTEL ALERT & GOOGLE WEB RISK</div>
          <div style={{ fontSize: 11, color: "var(--fg)", whiteSpace: "pre-wrap", marginTop: 4 }}>{res.threat_intel.formatted_summary}</div>
        </div>
      )}

      {stages.map((s, i) => (
        <div key={s.key}>
          <div className={`stage ${s.state}`}>
            <div className="stage-head">
              <span className="stage-name">{s.name}</span>
              {s.state === "blocked" && <span className="tag blocked">blocked</span>}
              {s.state === "skipped" && <span className="tag low">not reached</span>}
            </div>
            <div className="stage-detail">{s.body}</div>
          </div>
          {i < stages.length - 1 && (
            <div className={`connector${s.state === "blocked" ? " severed" : ""}`} />
          )}
        </div>
      ))}

      {res.external_status && (
        <div style={{ background: "rgba(14, 165, 233, 0.1)", border: "1px solid rgba(14, 165, 233, 0.3)", borderRadius: 8, padding: "0.65rem 0.85rem", marginTop: 12 }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <span style={{ fontSize: 11, fontWeight: 700, color: "#38bdf8" }}>📌 INBOUND ITSM WEBHOOK SYNC</span>
            <span className="tag clean" style={{ fontSize: 10 }}>{res.external_status}</span>
          </div>
          {res.external_notes && (
            <div style={{ fontSize: 11, color: "#e2e8f0", marginTop: 4 }}>
              Analyst Update: {res.external_notes}
            </div>
          )}
        </div>
      )}

      {res.audit_certificate && (
        <div style={{ background: "rgba(16, 185, 129, 0.08)", border: "1px solid rgba(16, 185, 129, 0.3)", borderRadius: 8, padding: "0.65rem 0.85rem", marginTop: 12 }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <span style={{ fontSize: 11, fontWeight: 700, color: "var(--ok)" }}>🔐 IMMUTABLE CRYPTOGRAPHIC AUDIT CERTIFICATE</span>
            <span style={{ fontSize: 10, fontFamily: "var(--mono)", color: "var(--ok)", fontWeight: 700 }}>VERIFIED (SHA-256)</span>
          </div>
          <div style={{ fontSize: 10, fontFamily: "var(--mono)", color: "var(--faint)", marginTop: 4 }}>
            Cert: {res.audit_certificate.certificate_id} | Merkle Root: {res.audit_certificate.merkle_root_hash.slice(0, 16)}... | Actor: {res.audit_certificate.actor_identity}
          </div>
        </div>
      )}
    </div>
  );


}

export function TraceSteps({ res }: { res: IngestResult }) {
  return (
    <div className="trace">
      <div style={{ color: "var(--faint)" }}>trace_id={res.trace.trace_id}</div>
      {res.trace.steps.map((s, i) => (
        <div key={i}>
          <span style={{ color: "var(--faint)" }}>{s.timestamp.slice(11, 23)}</span>{" "}
          <span className="hop">{s.hop.padEnd(12)}</span> {s.detail}
        </div>
      ))}
    </div>
  );
}
