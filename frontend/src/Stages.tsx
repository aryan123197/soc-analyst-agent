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
      name: "4 · action gateway",
      state: blocked ? "skipped" : "done",
      body: blocked ? (
        "quarantined — no gateway call issued"
      ) : action ? (
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
