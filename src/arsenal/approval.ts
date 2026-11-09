/**
 * T3MP3ST Arsenal: the capability-approval gate.
 *
 * A tool with a gated risk tier (intrusive, credential, dangerous) is inert until approved: either
 * pre-authorized for the run (`preApprovedTools`) or approved interactively once. With no approver
 * wired, a gated tool is denied. Every gated decision is audited.
 *
 * The defensive build ships no gated tool: every built-in is passive or local_read. The gate stays
 * in Arsenal.execute() so anything gated that is ever added fails closed.
 *
 * This module is pure (no I/O); the host injects the approver and sinks through the policy.
 */

import type { RiskTier } from '../types/index.js';

// Re-exported so callers can `import { ..., RiskTier } from './approval.js'` in one place.
export type { RiskTier };

/** Tiers that require the tool to be APPROVED (interactively or via the allowlist) before it can run. */
const GATED_TIERS: ReadonlySet<RiskTier> = new Set<RiskTier>(['intrusive', 'credential', 'dangerous']);

/** The hottest tiers — an approved call still fires a loud, audited, NON-BLOCKING warning each time. */
const SPICY_TIERS: ReadonlySet<RiskTier> = new Set<RiskTier>(['credential', 'dangerous']);

/** True for a tool whose risk requires approval before it can execute. Undefined/safe/active → false.
 *  A type guard so callers narrow `riskTier?` to a defined RiskTier after the check. */
export function isGatedRisk(risk?: RiskTier): risk is RiskTier {
  return risk !== undefined && GATED_TIERS.has(risk);
}

/** True for a tool whose action warrants a loud warning even when approved (exploits, cred attacks). */
export function isSpicyRisk(risk?: RiskTier): boolean {
  return risk !== undefined && SPICY_TIERS.has(risk);
}

/** What the agent is about to do — enough for a human to make a call, or for the audit trail. */
export interface ApprovalRequest {
  /** The tool being invoked (the approval unit — "approve once" approves this name). */
  tool: string;
  /** The tool's risk tier (drives gating + spiciness). */
  risk: RiskTier;
  /** The operator/agent that wants to run it, when known. */
  operator?: string;
  /** The resolved target the action would hit, when known (informational for the warning/audit). */
  target?: string;
  /** A one-line human-readable summary of the specific action (tool + key params + target). */
  action: string;
}

/** How a gated call was resolved — recorded on every audit entry. */
export type ApprovalOutcome =
  | 'allowed-preapproved' // already on the allowlist or approved earlier this session
  | 'allowed-interactive' // the operator said yes just now (and the tool is now free)
  | 'denied-declined' // the operator said no
  | 'denied-no-approver'; // fail-safe: gated, not approved, and no approver was wired

/** One immutable audit record. The controller keeps the full trail for the engagement report. */
export interface ApprovalRecord extends ApprovalRequest {
  outcome: ApprovalOutcome;
  /** Whether a spicy warning was surfaced for this call. */
  spicy: boolean;
  /** Epoch-ms when the decision was made. */
  at: number;
}

export interface ApprovalPolicy {
  /**
   * Tools pre-authorized up front — the headless/unattended allowlist. A gated tool named here runs
   * free (still audited, still warns on spicy actions). This is also the store the "approve once"
   * interactive path writes into.
   */
  preApprovedTools?: string[];
  /**
   * Interactive approver, asked ONCE per gated tool the first time it is used. Return true to approve
   * the tool for the rest of the session. If omitted, a gated tool that isn't pre-approved is DENIED
   * (fail-safe) — the unattended/headless posture.
   */
  requestApproval?: (req: ApprovalRequest) => Promise<boolean>;
  /**
   * Sink for the non-blocking spicy-action warning — surface it live (CLI banner / UI toast / event).
   * Called on every spicy call that is allowed; the same request is also written to the audit trail.
   */
  onWarning?: (req: ApprovalRequest) => void;
  /**
   * Sink for EVERY gated decision (allowed or denied), fired as it is recorded to the audit trail.
   * The engine wires this to an SSE event so the dashboard sees a live approval/audit feed.
   */
  onDecision?: (record: ApprovalRecord) => void;
  /** Injected clock for deterministic tests. Defaults to Date.now. */
  now?: () => number;
}

/**
 * Holds the session's approved-tool set + the full audit trail, and adjudicates each gated call.
 * One instance per engine/mission; wired onto the Arsenal via setApprovalController().
 */
export class ApprovalController {
  private readonly approved: Set<string>;
  private readonly audit: ApprovalRecord[] = [];
  private readonly now: () => number;

  constructor(private readonly policy: ApprovalPolicy = {}) {
    this.approved = new Set(policy.preApprovedTools ?? []);
    this.now = policy.now ?? Date.now;
  }

  /** Approve a tool for the rest of the session ("approve once, then free"). */
  approveTool(name: string): void {
    this.approved.add(name);
  }

  /** Is this tool currently approved (via the allowlist or an earlier interactive yes)? */
  isApproved(name: string): boolean {
    return this.approved.has(name);
  }

  /** The names currently approved (defensive copy). */
  approvedTools(): string[] {
    return [...this.approved];
  }

  /** The full audit trail (defensive copy) — every gated decision + whether it warned. */
  getAudit(): ApprovalRecord[] {
    return this.audit.map((r) => ({ ...r }));
  }

  /**
   * The gate. Called from Arsenal.execute() BEFORE a tool's handler runs.
   *
   *  - ungated risk (safe/active/undefined) → allowed, nothing recorded.
   *  - gated + already approved → allowed; a spicy call fires the (non-blocking) warning. Audited.
   *  - gated + not approved + an approver is wired → ask once; yes approves the tool + allows (spicy
   *    still warns), no denies. Audited.
   *  - gated + not approved + NO approver → DENIED (fail-safe). Audited.
   */
  async gate(req: ApprovalRequest): Promise<{ allowed: boolean; reason: string }> {
    if (!isGatedRisk(req.risk)) return { allowed: true, reason: 'ungated' };

    const spicy = isSpicyRisk(req.risk);
    const warnIfSpicy = (): void => {
      if (spicy && this.policy.onWarning) this.policy.onWarning(req);
    };
    const record = (outcome: ApprovalOutcome): void => {
      const rec: ApprovalRecord = { ...req, outcome, spicy, at: this.now() };
      this.audit.push(rec);
      this.policy.onDecision?.(rec);
    };

    // Already approved — the allowlist, or an earlier "approve once".
    if (this.approved.has(req.tool)) {
      warnIfSpicy();
      record('allowed-preapproved');
      return { allowed: true, reason: `approved (${req.risk})` };
    }

    // Not yet approved — ask the human once, if an approver is wired.
    if (this.policy.requestApproval) {
      const ok = await this.policy.requestApproval(req);
      if (ok) {
        this.approveTool(req.tool); // approve once, then free
        warnIfSpicy();
        record('allowed-interactive');
        return { allowed: true, reason: `operator approved ${req.tool}` };
      }
      record('denied-declined');
      return { allowed: false, reason: `${req.tool} (${req.risk}) was declined by the operator` };
    }

    // Fail-safe: gated, not approved, no way to ask.
    record('denied-no-approver');
    return {
      allowed: false,
      reason:
        `${req.tool} is a ${req.risk} tool and is not authorized. Approve it up front ` +
        `(pre-authorization allowlist) or via an interactive approver before use.`,
    };
  }
}
