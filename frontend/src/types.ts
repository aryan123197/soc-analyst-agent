/** Mirrors the response models in soc_agent/server.py. */

export type Verdict = "clean" | "blocked";
export type Hop = "ingestion" | "model_armor" | "triage" | "action" | "memory_bank";

export interface Armor {
  verdict: Verdict;
  threat_type: string | null;
  confidence: number;
  screened_at: string;
  matched_signal: string | null;
}

export interface Triage {
  severity: "low" | "medium" | "high" | "critical";
  /** Free text from the LLM -- never key styling off this value. */
  category: string;
  reasoning: string;
  similar_past_cases: string[];
}

export interface ActionRecord {
  type: "escalated" | "closed" | "notified";
  actor_agent_identity: string;
  executed_at: string;
}

export interface TraceStep {
  hop: Hop;
  detail: string;
  timestamp: string;
}

export interface ThreatDetail {
  ioc: string;
  type: string;
  risk_score: number;
  detail: string;
  source: string;
}

export interface ThreatIntelReport {
  has_threats: boolean;
  ips_found: string[];
  hashes_found: string[];
  urls_found: string[];
  threat_details: ThreatDetail[];
  risk_score_max: number;
  formatted_summary: string;
}

export interface AuditCertificate {
  case_id: string;
  certificate_id: string;
  timestamp: string;
  merkle_root_hash: string;
  previous_block_hash: string;
  outcome: string;
  model_armor_verdict: string;
  actor_identity: string;
  signature: string;
  verified: boolean;
}

export interface IngestResult {
  case_id: string;
  status: "quarantined" | "actioned";
  armor: Armor;
  triage: Triage | null;
  action: ActionRecord | null;
  trace: { trace_id: string; case_id: string; steps: TraceStep[] };
  threat_intel?: ThreatIntelReport | null;
  audit_certificate?: AuditCertificate | null;
}


export interface CorpusCase {
  label: string;
  description: string;
  source_channel: string;
  sender: string;
  raw_text: string;
  expected_verdict: Verdict;
}

/** Events off GET /live/stream (see soc_agent/services/events.py). */
export type LiveEvent =
  | {
      type: "case_start";
      timestamp: string;
      case_id: string;
      trace_id: string;
      source_channel: string;
      sender: string;
      preview: string;
    }
  | ({ type: "hop"; trace_id: string; case_id: string } & TraceStep)
  | {
      type: "case_complete";
      timestamp: string;
      case_id: string;
      outcome: "quarantined" | "actioned";
      armor_verdict: Verdict;
      armor_threat_type: string | null;
      severity: Triage["severity"] | null;
      category: string | null;
      action_taken: ActionRecord["type"] | null;
    };
