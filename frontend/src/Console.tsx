import { useEffect, useRef, useState } from "react";
import { encodeRedTeam, fetchCorpus, postIngest } from "./api";
import { Stages, TraceSteps } from "./Stages";
import type { CorpusCase, IngestResult } from "./types";

interface Run {
  id: number;
  res: IngestResult;
  armorAtRun: boolean;
}

const CHANNELS = ["email", "ticket", "scraped_page"];

export function Console() {
  const [corpus, setCorpus] = useState<CorpusCase[]>([]);
  const [corpusError, setCorpusError] = useState<string | null>(null);
  const [channel, setChannel] = useState("email");
  const [sender, setSender] = useState("");
  const [rawText, setRawText] = useState("");
  const [armorEnabled, setArmorEnabled] = useState(true);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [runs, setRuns] = useState<Run[]>([]);
  const seq = useRef(0);

  useEffect(() => {
    const ac = new AbortController();
    fetchCorpus(ac.signal)
      .then((cases) => {
        setCorpus(cases);
        if (cases.length) load(cases[0]);
      })
      .catch((e: unknown) => {
        if (!ac.signal.aborted) setCorpusError(String(e));
      });
    return () => ac.abort();
  }, []);

  function load(c: CorpusCase) {
    setChannel(c.source_channel);
    setSender(c.sender);
    setRawText(c.raw_text);
  }

  async function handleMutate(type: string) {
    if (!rawText.trim()) return;
    try {
      const res = await encodeRedTeam(rawText, type);
      setRawText(res.mutated_payload);
    } catch (e: unknown) {
      setError("Mutation error: " + String(e));
    }
  }

  async function run() {
    if (running || !rawText.trim()) return;
    const armorAtRun = armorEnabled;
    setRunning(true);
    setError(null);
    try {
      const res = await postIngest({
        source_channel: channel,
        sender,
        raw_text: rawText,
        armor_enabled: armorAtRun,
      });
      seq.current += 1;
      setRuns((prev) => [{ id: seq.current, res, armorAtRun }, ...prev].slice(0, 2));
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setRunning(false);
    }
  }

  return (
    <div className="cols">
      <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
        <div className="panel armor">
          <div className="label">
            <span
              style={{
                fontFamily: "var(--mono)",
                fontSize: 12,
                letterSpacing: "0.18em",
                color: "var(--muted)",
              }}
            >
              MODEL ARMOR
            </span>
            <span style={{ fontSize: 12, color: "var(--faint)" }}>request flag</span>
          </div>
          <div className="seg">
            <button
              className="on"
              aria-pressed={armorEnabled}
              onClick={() => setArmorEnabled(true)}
            >
              ON
            </button>
            <button
              className="off"
              aria-pressed={!armorEnabled}
              onClick={() => setArmorEnabled(false)}
            >
              OFF
            </button>
          </div>
          {!armorEnabled && (
            <div className="armor-warning">
              screening disabled — untrusted content will reach the model and the gateway
            </div>
          )}
        </div>

        <div className="panel">
          <div className="two">
            <div>
              <label className="field" htmlFor="ch">source_channel</label>
              <select id="ch" value={channel} onChange={(e) => setChannel(e.target.value)}>
                {CHANNELS.map((c) => (
                  <option key={c} value={c}>{c}</option>
                ))}
              </select>
            </div>
            <div>
              <label className="field" htmlFor="sn">sender</label>
              <input id="sn" value={sender} onChange={(e) => setSender(e.target.value)} />
            </div>
          </div>
          <label className="field" htmlFor="rt">raw_text</label>
          <textarea id="rt" value={rawText} onChange={(e) => setRawText(e.target.value)} />

          <div style={{ display: "flex", gap: 6, margin: "8px 0" }}>
            <button style={{ fontSize: 11, padding: "4px 8px" }} onClick={() => handleMutate("base64")}>📦 Base64</button>
            <button style={{ fontSize: 11, padding: "4px 8px" }} onClick={() => handleMutate("hex")}>🔢 Hex</button>
            <button style={{ fontSize: 11, padding: "4px 8px" }} onClick={() => handleMutate("url")}>🌐 URL</button>
            <button style={{ fontSize: 11, padding: "4px 8px" }} onClick={() => handleMutate("wrapped_ticket")}>🎟️ Ticket</button>
          </div>

          <button className="run" onClick={run} disabled={running || !rawText.trim()}>
            {running ? "RUNNING…" : "RUN PIPELINE"}
          </button>
        </div>


        <div className="panel">
          <div className="row" style={{ marginBottom: 10 }}>
            <h2 style={{ margin: 0 }}>Preset alerts</h2>
            <span style={{ fontSize: 12, color: "var(--faint)" }}>
              {corpus.length ? `${corpus.length} loadable` : "—"}
            </span>
          </div>
          {corpusError ? (
            <div className="error">
              <strong>GET /corpus failed</strong>
              {corpusError}
              <br />
              Presets are unavailable. Paste an alert into raw_text to run the pipeline.
            </div>
          ) : (
            <div className="presets">
              {corpus.map((c) => (
                <button key={c.label} onClick={() => load(c)}>
                  <div className="preset-label">
                    <span>{c.label}</span>
                    <span className={`tag ${c.expected_verdict}`}>{c.expected_verdict}</span>
                  </div>
                  <div className="preset-desc">{c.description}</div>
                </button>
              ))}
            </div>
          )}
        </div>
      </div>

      <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
        {error && (
          <div className="error">
            <strong>POST /ingest failed</strong>
            {error}
            <br />
            No result is shown because none was produced. Check that the backend is
            running and reachable, then run again.
          </div>
        )}

        {runs.length === 0 && !error && (
          <div className="panel">
            <div className="empty">
              Load a preset or paste an alert, then run the pipeline.
              <br />
              <br />
              To show the security argument: run an injection with{" "}
              <strong style={{ color: "var(--bad)" }}>ARMOR OFF</strong> and watch it reach
              the gateway, then run the same payload with{" "}
              <strong style={{ color: "var(--ok)" }}>ARMOR ON</strong> and watch it stop at
              stage two. Both runs stay on screen.
            </div>
          </div>
        )}

        {runs.length > 0 && (
          <div className="runs">
            {runs.map((r, i) => (
              <div className="run-slot" key={r.id}>
                <div className="slot-label">
                  {i === 0 ? "latest run" : "previous run"} · armor{" "}
                  <span style={{ color: r.armorAtRun ? "var(--ok)" : "var(--bad)" }}>
                    {r.armorAtRun ? "on" : "off"}
                  </span>{" "}
                  · <span className={`tag ${r.res.status === "quarantined" ? "blocked" : "clean"}`}>
                    {r.res.status}
                  </span>
                </div>
                <Stages res={r.res} armorAtRun={r.armorAtRun} />
                <div className="panel">
                  <h2>Reasoning trace</h2>
                  <TraceSteps res={r.res} />
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
