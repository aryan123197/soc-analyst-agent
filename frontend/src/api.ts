import type { CorpusCase, IngestResult } from "./types";

/**
 * Every call is a relative path: same-origin in the container, proxied by Vite
 * in dev. Failures throw -- nothing here ever substitutes fabricated data for a
 * real response. A demo that invents results is worse than one that shows an error.
 */

async function asJson<T>(res: Response): Promise<T> {
  if (!res.ok) {
    throw new Error(`${res.status} ${res.statusText}`);
  }
  return (await res.json()) as T;
}

export async function fetchCorpus(signal?: AbortSignal): Promise<CorpusCase[]> {
  return asJson<CorpusCase[]>(await fetch("/corpus", { signal }));
}

export interface IngestRequest {
  source_channel: string;
  sender: string;
  raw_text: string;
  armor_enabled: boolean;
}

export async function postIngest(
  req: IngestRequest,
  signal?: AbortSignal,
): Promise<IngestResult> {
  const res = await fetch("/ingest", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(req),
    signal,
  });
  const data = await asJson<IngestResult>(res);
  if (!data?.trace?.steps) {
    throw new Error("malformed response: missing trace.steps");
  }
  return data;
}

export async function setReplay(
  action: "start" | "stop",
  interval = 8,
): Promise<{ running: boolean; interval: number }> {
  return asJson(
    await fetch("/live/replay", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ action, interval }),
    }),
  );
}

export async function encodeRedTeam(
  payload: string,
  encoding_type: string
): Promise<{ original_payload: string; encoding_type: string; mutated_payload: string }> {
  return asJson(
    await fetch("/api/v1/redteam/encode", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ payload, encoding_type }),
    })
  );
}

export async function sendWebhook(
  source: string,
  payload: Record<string, unknown>
): Promise<{ status: string; case_id: string; update: unknown }> {
  return asJson(
    await fetch(`/api/v1/webhooks/${source}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    })
  );
}


