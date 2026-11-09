/**
 * The defensive assessment's data model: what a run is asked to do, what it reports while it
 * runs, and the report it produces.
 */

import type { Severity } from '../types/index.js';

export type { Severity };

/** How the deployment established that the operator owns a site's hostname. */
export type OwnershipVerification = 'zone' | 'txt' | 'unverified';

export interface AssessmentRequest {
  /** Assigned by the caller (the Worker); unique per run. */
  id: string;
  repo?: {
    /** An https:// git URL. */
    url: string;
    /** Optional read-only token, used for this clone only and never written to disk or logs. */
    token?: string;
    /** Optional branch or tag. */
    ref?: string;
  };
  site?: {
    /** An http(s) URL of a public page of the operator's site. */
    url: string;
    verification: OwnershipVerification;
  };
  /** The model id the operators run on. */
  model: string;
  /** False runs only the deterministic scanners (no model calls). */
  useModel?: boolean;
}

export type FindingCategory = 'code' | 'secret' | 'dependency' | 'config' | 'web' | 'tls' | 'dns';

/** How sure the assessment is: tool-confirmed, model-triaged likely, or needing a human look. */
export type Confidence = 'confirmed' | 'likely' | 'needs-review';

export interface DefensiveFinding {
  id: string;
  title: string;
  severity: Severity;
  category: FindingCategory;
  cwe?: string[];
  cve?: string[];
  /** Where: a repository file and line, or a URL. */
  location?: { file?: string; line?: number; url?: string };
  /** What was observed, with secret values redacted. */
  evidence: string;
  description: string;
  remediation: string;
  /** The check that proves the fix worked. */
  retest: string;
  /** The scanner or operator that produced it. */
  source: string;
  confidence: Confidence;
  /** The model's triage note, when an operator reviewed it. */
  triage?: string;
  /** Concrete Cloudflare controls that mitigate it (filled in by the report). */
  cloudflare?: CloudflareControl[];
}

export interface CloudflareControl {
  control: string;
  action: string;
  docs: string;
}

export type AssessmentStatus = 'queued' | 'running' | 'completed' | 'failed' | 'cancelled';

export type AssessmentEventType = 'phase' | 'operator' | 'tool_call' | 'tool_result' | 'finding' | 'log' | 'error' | 'done';

export interface AssessmentEvent {
  seq: number;
  at: number;
  type: AssessmentEventType;
  /** The operator callsign or scanner name the event belongs to. */
  actor?: string;
  message: string;
  data?: Record<string, unknown>;
}

export interface AssessmentReport {
  id: string;
  generatedAt: string;
  engine: { name: string; version: string; source: string; model?: string };
  targets: {
    repo?: { url: string; commit?: string; files?: number };
    site?: { url: string; verification: OwnershipVerification };
  };
  summary: {
    counts: Record<Severity, number>;
    riskScore: number;
    executive: string;
    topActions: string[];
  };
  findings: DefensiveFinding[];
  hardenWithCloudflare: Array<CloudflareControl & { findings: string[] }>;
  disclosureDraft?: string;
  /** Checks that could not run and why, so a gap is never silent. */
  coverage: Array<{ check: string; status: 'ran' | 'skipped' | 'failed'; note?: string }>;
}
