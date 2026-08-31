import { useEffect, useRef, useState } from "react";
import { setReplay } from "./api";
import type { LiveEvent, TraceStep } from "./types";

/**
 * Watches GET /live/stream. Unlike the console (one request, one response),
 * these stages really do resolve incrementally -- each hop arrives as its own
 * event while the pipeline is still running, so nothing here is animated on a
 * timer. A card only shows a hop the backend actually published.
 */

interface LiveCase {
  case_id: string;
  sender: string;
  source_channel: string;
  preview: string;
  hops: TraceStep[];
  outcome: "pending" | "quarantined" | "actioned";
  armor_threat_type?: string | null;
  severity?: string | null;
  action_taken?: string | null;
  external_status?: string | null;
  external_source?: string | null;
}

const MAX_CARDS = 40;

export function LiveFeed() {
  const [cases, setCases] = useState<LiveCase[]>([]);
  const [connected, setConnected] = useState(false);
  const [replayOn, setReplayOn] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const esRef = useRef<EventSource | null>(null);

  useEffect(() => {
    const es = new EventSource("/live/stream");
    esRef.current = es;
    es.onopen = () => setConnected(true);
    es.onerror = () => setConnected(false);
    es.onmessage = (m) => {
      let ev: LiveEvent;
      try {
        ev = JSON.parse(m.data) as LiveEvent;
      } catch {
        return;
      }
      setCases((prev) => {
        if (ev.type === "case_start") {
          const card: LiveCase = {
            case_id: ev.case_id,
            sender: ev.sender,
            source_channel: ev.source_channel,
            preview: ev.preview,
            hops: [],
            outcome: "pending",
          };
          return [card, ...prev].slice(0, MAX_CARDS);
        }
        return prev.map((c) => {
          if (c.case_id !== ev.case_id) return c;
          if (ev.type === "hop") {
            return {
              ...c,
              hops: [...c.hops, { hop: ev.hop, detail: ev.detail, timestamp: ev.timestamp }],
            };
          }
          if (ev.type === "webhook_received") {
            return {
              ...c,
              external_status: ev.external_status,
              external_source: ev.source,
            };
          }
          if (ev.type === "case_complete") {
            return {
              ...c,
              outcome: ev.outcome,
              armor_threat_type: ev.armor_threat_type,
              severity: ev.severity,
              action_taken: ev.action_taken,
            };
          }
          return c;
        });

      });
    };
    return () => es.close();
  }, []);

  async function toggleReplay() {
    const next = replayOn ? "stop" : "start";
    try {
      const r = await setReplay(next);
      setReplayOn(r.running);
      setError(null);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }

  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
      <div className="panel row">
        <span style={{ display: "flex", alignItems: "center", gap: 10 }}>
          <span className={`dot ${connected ? "live" : "dead"}`} />
          <span style={{ fontFamily: "var(--mono)", fontSize: 13 }}>
            {connected ? "connected to /live/stream" : "disconnected"}
          </span>
          <span style={{ color: "var(--faint)", fontSize: 13 }}>
            {cases.length} case{cases.length === 1 ? "" : "s"}
          </span>
        </span>
        <button className="run" style={{ width: "auto", margin: 0 }} onClick={toggleReplay}>
          {replayOn ? "STOP REPLAY FEED" : "START REPLAY FEED"}
        </button>
      </div>

      {error && (
        <div className="error">
          <strong>POST /live/replay failed</strong>
          {error}
        </div>
      )}

      {!connected && (
        <div className="error">
          <strong>Not receiving events</strong>
          The browser is not connected to GET /live/stream. Nothing below is updating.
        </div>
      )}

      {cases.length === 0 ? (
        <div className="panel">
          <div className="empty">
            No cases yet. Start the replay feed to generate synthetic SOC traffic, or run
            an alert from the Console tab — both appear here as the pipeline processes them.
          </div>
        </div>
      ) : (
        <div className="feed">
          {cases.map((c) => (
            <div className={`feed-card ${c.outcome}`} key={c.case_id}>
              <div className="feed-meta">
                <code>{c.case_id}</code>
                <span>{c.source_channel}</span>
                <span>{c.sender}</span>
                {c.outcome !== "pending" && (
                  <span className={`tag ${c.outcome === "quarantined" ? "blocked" : "clean"}`}>
                    {c.outcome}
                  </span>
                )}
                {c.armor_threat_type && <span className="tag blocked">{c.armor_threat_type}</span>}
                {c.severity && <span className={`tag ${c.severity}`}>{c.severity}</span>}
                {c.action_taken && <code>{c.action_taken}</code>}
                {c.external_status && (
                  <span className="tag clean" style={{ fontSize: 11 }}>
                    📌 {c.external_source?.toUpperCase()}: {c.external_status}
                  </span>
                )}
              </div>
              <div className="feed-preview">{c.preview}</div>
              <div className="feed-hops">
                {c.hops.map((h) => h.hop).join(" → ") || "…"}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

