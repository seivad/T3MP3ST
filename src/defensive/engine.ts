/**
 * The defensive assessment engine: one run of white-box analysis and/or passive posture checks,
 * with T3MP3ST operators triaging and explaining what the deterministic scanners found.
 *
 *   prepare      clone the repository (one-shot token, no hooks, shallow)
 *   secrets      gitleaks + built-in rules
 *   dependencies OSV (osv-scanner or the OSV API)
 *   config       IaC / CI / container / Wrangler rules
 *   code         SAST rules ranked by T3MP3ST code-ingest exposure
 *   posture      passive checks of the site
 *   triage       Scanner and Analyst operators review candidates with read-only repo tools
 *   summary      Coordinator writes the executive summary
 *   report       JSON + Markdown
 *
 * Every event is redacted before it is stored, and the token a repository was cloned with never
 * enters an event, a report or the work directory.
 */

import { mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { Arsenal, BUILTIN_TOOLS } from '../arsenal/index.js';
import { ApprovalController } from '../arsenal/approval.js';
import { createRepoTools } from '../arsenal/repo-tools.js';
import { AgentLoop } from '../agent/index.js';
import { LLMBackbone } from '../llm/index.js';
import { createOperator, ARCHETYPE_PROFILES, type OperatorAgent } from '../operators/index.js';
import { ingestRepoToSourceContext } from '../recon/whitebox.js';
import { redactSecrets, redactString } from '../redact.js';
import type { OperatorArchetype, Task } from '../types/index.js';
import { scanDependencies } from './deps.js';
import { scanConfig } from './iac.js';
import { buildReport, renderMarkdown } from './report.js';
import { cloneRepository } from './repo.js';
import { scanCode } from './sast.js';
import { findingId } from './scan-util.js';
import { scanSecrets } from './secrets.js';
import type { AssessmentEvent, AssessmentEventType, AssessmentReport, AssessmentRequest, AssessmentStatus, DefensiveFinding, Severity } from './types.js';
import { runPassivePosture } from './web.js';

export const ENGINE_VERSION = '1.0.0-defensive';

const MAX_EVENTS = 3000;
const SEVERITIES = new Set(['critical', 'high', 'medium', 'low', 'info']);

export interface EngineOptions {
  /** Where runs keep their clone and report. */
  workRoot: string;
  /** OpenAI-compatible base URL the operators' model is served at (…/v1). */
  llmBaseUrl?: string;
  /** Overall time box for one run. */
  timeoutMs?: number;
  /** Allow loopback/private site targets (local fixture runs only). */
  allowLocalTargets?: boolean;
  /** Allow file:// repository URLs (local fixture runs only). */
  allowLocalRepos?: boolean;
}

/** One assessment's live state. */
export class Assessment {
  status: AssessmentStatus = 'queued';
  phase = 'queued';
  readonly events: AssessmentEvent[] = [];
  report?: AssessmentReport;
  markdown?: string;
  error?: string;
  readonly startedAt = Date.now();
  finishedAt?: number;
  private seq = 0;
  readonly abort = new AbortController();

  constructor(readonly request: AssessmentRequest) {}

  emit(type: AssessmentEventType, message: string, actor?: string, data?: Record<string, unknown>): void {
    const event: AssessmentEvent = {
      seq: ++this.seq,
      at: Date.now(),
      type,
      actor,
      message: redactString(message).slice(0, 2000),
      data: data && JSON.stringify(data).length <= 8000 ? (redactSecrets(data) as Record<string, unknown>) : undefined,
    };
    this.events.push(event);
    if (this.events.length > MAX_EVENTS) this.events.splice(0, this.events.length - MAX_EVENTS);
  }

  eventsAfter(seq: number): AssessmentEvent[] {
    return this.events.filter((e) => e.seq > seq);
  }

  /** Public state, without the request's token. */
  snapshot() {
    const { repo, site, model, useModel } = this.request;
    return {
      id: this.request.id,
      status: this.status,
      phase: this.phase,
      startedAt: this.startedAt,
      finishedAt: this.finishedAt,
      error: this.error,
      request: { repo: repo ? { url: repo.url, ref: repo.ref, private: !!repo.token } : undefined, site, model, useModel },
      lastSeq: this.seq,
      counts: this.report?.summary.counts,
    };
  }
}

function summarizeArgs(args: Record<string, unknown>): string {
  return Object.entries(args)
    .filter(([, v]) => v !== undefined && typeof v !== 'object')
    .map(([k, v]) => `${k}=${String(v).slice(0, 80)}`)
    .join(' ');
}

/** The final fenced JSON block of an operator's debrief. */
export function parseDebrief(text: string): Array<Record<string, unknown>> {
  const blocks = [...(text || '').matchAll(/```(?:json)?\s*([\s\S]*?)```/g)].map((m) => m[1]).reverse();
  for (const candidate of blocks.length ? blocks : [text]) {
    const start = candidate.indexOf('{');
    const end = candidate.lastIndexOf('}');
    if (start < 0 || end <= start) continue;
    try {
      const parsed = JSON.parse(candidate.slice(start, end + 1)) as { findings?: unknown };
      if (Array.isArray(parsed.findings)) return parsed.findings.filter((f): f is Record<string, unknown> => !!f && typeof f === 'object');
    } catch {
      /* next block */
    }
  }
  return [];
}

/**
 * Applies an operator's triage to the candidates: a matched candidate takes the verdict
 * (false positives are dropped), and an unmatched finding is added as needs-review.
 */
export function mergeTriage(
  candidates: DefensiveFinding[],
  debrief: Array<Record<string, unknown>>,
  operator: string,
): { findings: DefensiveFinding[]; dismissed: number; added: number } {
  const byTitle = new Map(candidates.map((c) => [c.title.toLowerCase(), c]));
  const dismissed = new Set<string>();
  let added = 0;
  const extra: DefensiveFinding[] = [];
  for (const item of debrief) {
    const title = String(item.title ?? '').trim();
    if (!title) continue;
    const verdict = String(item.verdict ?? '').toLowerCase();
    const details = String(item.details ?? '').trim();
    const match =
      byTitle.get(title.toLowerCase()) ??
      (item.id ? candidates.find((c) => c.id === String(item.id)) : undefined) ??
      candidates.find((c) => c.location?.file && c.location.line && `${title} ${details}`.includes(`${c.location.file}:${c.location.line}`));
    if (match) {
      if (verdict === 'false_positive' || verdict === 'false positive') {
        dismissed.add(match.id);
        continue;
      }
      if (verdict === 'confirmed') match.confidence = 'confirmed';
      else if (verdict === 'likely' && match.confidence === 'needs-review') match.confidence = 'likely';
      if (details) match.triage = `${operator}: ${redactString(details).slice(0, 800)}`;
      const fix = String(item.remediation ?? '').trim();
      if (fix && fix.length > 20 && !match.remediation.includes(fix)) match.remediation = `${match.remediation} Suggested change: ${redactString(fix).slice(0, 800)}`;
      continue;
    }
    if (verdict === 'false_positive') continue;
    const severity = SEVERITIES.has(String(item.severity)) ? (String(item.severity) as Severity) : 'medium';
    const file = typeof item.file === 'string' ? item.file : /([\w./-]+\.\w+):(\d+)/.exec(`${title} ${details}`)?.[1];
    const line = typeof item.line === 'number' ? item.line : Number(/([\w./-]+\.\w+):(\d+)/.exec(`${title} ${details}`)?.[2]) || undefined;
    extra.push({
      id: findingId('model', operator, title, file, line),
      title: redactString(title).slice(0, 200),
      severity,
      category: 'code',
      cwe: Array.isArray(item.cwe) ? item.cwe.map(String) : undefined,
      cve: Array.isArray(item.cve) ? item.cve.map(String) : undefined,
      location: file ? { file, line } : undefined,
      evidence: redactString(details || title).slice(0, 2000),
      description: redactString(details || title).slice(0, 1200),
      remediation: redactString(String(item.remediation ?? 'Review and fix the code path described above.')).slice(0, 1200),
      retest: redactString(String(item.retest ?? 'Re-run the assessment and confirm the finding is gone.')).slice(0, 600),
      source: operator,
      confidence: 'needs-review',
    });
    added++;
  }
  return { findings: [...candidates.filter((c) => !dismissed.has(c.id)), ...extra], dismissed: dismissed.size, added };
}

function task(name: string, description: string, archetype: OperatorArchetype): Task {
  return {
    id: `task-${Math.random().toString(36).slice(2, 10)}`,
    missionId: 'assessment',
    name,
    description,
    phase: ARCHETYPE_PROFILES[archetype].primaryPhase,
    operatorType: archetype,
    status: 'pending',
    priority: 8,
    dependencies: [],
    createdAt: Date.now(),
  };
}

function candidateDigest(findings: DefensiveFinding[], limit: number): string {
  return JSON.stringify(
    findings.slice(0, limit).map((f) => ({
      id: f.id,
      title: f.title,
      severity: f.severity,
      cwe: f.cwe,
      location: f.location,
      evidence: f.evidence.slice(0, 300),
    })),
    null,
    1,
  );
}

/** Runs one assessment to completion, recording events and the report on `run`. */
export async function runAssessment(run: Assessment, options: EngineOptions): Promise<void> {
  const req = run.request;
  const signal = run.abort.signal;
  const workDir = join(options.workRoot, req.id.replace(/[^a-zA-Z0-9-]/g, ''));
  const coverage: AssessmentReport['coverage'] = [];
  let findings: DefensiveFinding[] = [];
  let repoPath: string | undefined;
  let commit: string | undefined;
  let repoFiles: number | undefined;
  const timeout = setTimeout(() => run.abort.abort(new Error('assessment time box reached')), options.timeoutMs ?? 25 * 60_000);
  const phase = (name: string, message: string) => {
    if (signal.aborted) throw signal.reason instanceof Error ? signal.reason : new Error('cancelled');
    run.phase = name;
    run.emit('phase', message, undefined, { phase: name });
  };
  const addFindings = (source: string, list: DefensiveFinding[]) => {
    findings.push(...list);
    for (const f of list.slice(0, 40)) run.emit('finding', f.title, source, { severity: f.severity, category: f.category, confidence: f.confidence });
    if (list.length > 40) run.emit('finding', `…and ${list.length - 40} more from ${source}`, source);
  };

  run.status = 'running';
  mkdirSync(workDir, { recursive: true });
  try {
    if (req.repo) {
      phase('prepare', `Cloning ${req.repo.url}${req.repo.token ? ' (private, read-only token for this clone only)' : ''}`);
      const cloned = await cloneRepository(req.repo.url, workDir, { token: req.repo.token, ref: req.repo.ref, signal, allowFile: options.allowLocalRepos });
      repoPath = cloned.path;
      commit = cloned.commit;
      run.emit('log', `Checked out ${commit.slice(0, 12)}`, 'git');

      phase('secrets', 'Scanning for secrets committed to the repository');
      const secrets = await scanSecrets(repoPath, signal);
      addFindings(secrets.gitleaks ? 'gitleaks + built-in rules' : 'built-in secret rules', secrets.findings);
      coverage.push({ check: 'Secrets in code', status: 'ran', note: secrets.gitleaks ? 'gitleaks and built-in rules' : 'built-in rules (gitleaks not installed)' });

      phase('dependencies', 'Auditing dependencies against the OSV database');
      try {
        const deps = await scanDependencies(repoPath, signal);
        addFindings(deps.engine, deps.findings);
        coverage.push({ check: 'Dependency audit (OSV)', status: 'ran', note: deps.engine === 'osv-scanner' ? 'osv-scanner' : `OSV API, ${deps.packages ?? 0} pinned packages` });
      } catch (error) {
        coverage.push({ check: 'Dependency audit (OSV)', status: 'failed', note: error instanceof Error ? error.message : String(error) });
        run.emit('error', `Dependency audit failed: ${error instanceof Error ? error.message : String(error)}`, 'osv');
      }

      phase('config', 'Reviewing infrastructure-as-code, CI and container configuration');
      const config = scanConfig(repoPath);
      addFindings('configuration review', config);
      coverage.push({ check: 'IaC / CI / container configuration', status: 'ran' });

      phase('code', 'Static analysis of application code (T3MP3ST code-ingest ranking)');
      const code = scanCode(repoPath);
      repoFiles = code.files;
      addFindings('static analysis', code.findings);
      coverage.push({ check: 'Static analysis (SAST rules + code-ingest exposure ranking)', status: 'ran', note: `${code.files} source files ingested` });
    }

    const arsenal = new Arsenal();
    arsenal.registerMany(BUILTIN_TOOLS);
    // No tool in this build is gated, but a controller with no approver makes any future gated
    // tool fail closed rather than run.
    arsenal.setApprovalController(new ApprovalController({}));
    if (req.site) {
      const host = new URL(req.site.url).hostname;
      arsenal.setScope({ allowedHosts: [host], allowLoopback: !!options.allowLocalTargets, allowPrivate: !!options.allowLocalTargets });
      phase('posture', `Passive posture checks of ${req.site.url} (ownership: ${req.site.verification})`);
      const posture = await runPassivePosture(req.site.url, {
        arsenal,
        signal,
        onTool: (name, args, result) => {
          run.emit('tool_call', `${name} ${summarizeArgs(args)}`, 'Posture', { tool: name });
          run.emit('tool_result', `${name}: ${result.success ? (result.output ?? '').split('\n')[0] : `failed: ${result.error}`}`, 'Posture', { tool: name, success: result.success });
        },
      });
      addFindings('passive posture', posture.findings);
      coverage.push(...posture.coverage);
    }

    const useModel = req.useModel !== false && !!options.llmBaseUrl;
    let executive: string | undefined;
    let topActions: string[] | undefined;
    if (useModel) {
      const llm = new LLMBackbone({
        provider: 'local',
        model: req.model,
        baseUrl: options.llmBaseUrl,
        nativeTools: true,
        maxTokens: 4096,
        temperature: 0.2,
        timeout: 240_000,
      });
      const operatorArsenal = new Arsenal();
      operatorArsenal.registerMany(BUILTIN_TOOLS);
      if (repoPath) operatorArsenal.registerMany(createRepoTools(repoPath));
      operatorArsenal.setApprovalController(new ApprovalController({}));
      operatorArsenal.setScope({ allowedHosts: req.site ? [new URL(req.site.url).hostname] : [], allowLoopback: !!options.allowLocalTargets, allowPrivate: !!options.allowLocalTargets });

      const wire = (op: OperatorAgent) => {
        op.attachAgentLoop(new AgentLoop(llm, operatorArsenal, { tools: [...op.profile.tools], maxIterations: 8, maxTokens: 160_000, maxToolOutputLength: 6000, maxConcurrency: 2 }));
        op.on('agent:thinking', ({ content }) => content.trim() && run.emit('operator', content.trim().slice(0, 600), op.callsign));
        op.on('agent:tool_call', ({ name, args }) => run.emit('tool_call', `${name} ${summarizeArgs(args)}`, op.callsign, { tool: name }));
        op.on('agent:tool_result', ({ name, result }) =>
          run.emit('tool_result', `${name}: ${result.success ? (result.output ?? '').split('\n')[0].slice(0, 200) : `failed: ${String(result.error).slice(0, 200)}`}`, op.callsign, { tool: name, success: result.success }));
        return op;
      };

      try {
        if (repoPath) {
          phase('triage', 'Operators triage the scanners\' candidates');
          const supply = findings.filter((f) => f.category === 'dependency' || f.category === 'secret' || f.category === 'config');
          if (supply.length) {
            const scanner = wire(createOperator('Sentinel', 'scanner', llm));
            run.emit('operator', `Sentinel (${scanner.profile.name}) is reviewing ${supply.length} supply-chain, secret and configuration candidates`, 'Sentinel');
            const result = await scanner.assignTask(task('Triage supply-chain, secret and configuration findings',
              `Candidates from the deterministic scanners (JSON):\n${candidateDigest(supply, 30)}\n\nFor each candidate you check, emit a finding with its exact "title" and a "verdict" of "confirmed", "likely" or "false_positive", plus your reasoning in "details" and a precise "remediation".`, 'scanner'));
            const merged = mergeTriage(supply, parseDebrief(result.output ?? ''), 'Sentinel (supply chain & configuration)');
            findings = [...findings.filter((f) => !supply.includes(f)), ...merged.findings];
            run.emit('log', `Sentinel: ${merged.dismissed} dismissed as false positives, ${merged.added} added`, 'Sentinel');
          }
          signal.throwIfAborted();
          const code = findings.filter((f) => f.category === 'code');
          const analyst = wire(createOperator('Oracle', 'analyst', llm));
          try {
            analyst.setSourceContext(ingestRepoToSourceContext(repoPath, 14_000).sourceContext);
          } catch {
            /* the analyst can still read files with its tools */
          }
          run.emit('operator', `Oracle (${analyst.profile.name}) is reviewing the code${code.length ? ` and ${code.length} static-analysis candidates` : ''}`, 'Oracle');
          const result = await analyst.assignTask(task('Review the application code',
            `Static-analysis candidates (JSON):\n${candidateDigest(code, 30)}\n\nTriage each candidate (exact "title", a "verdict" of "confirmed", "likely" or "false_positive"), then report any other issue you confirm by reading the code, with "file" and "line".`, 'analyst'));
          const merged = mergeTriage(code, parseDebrief(result.output ?? ''), 'Oracle (code review)');
          findings = [...findings.filter((f) => f.category !== 'code'), ...merged.findings];
          run.emit('log', `Oracle: ${merged.dismissed} dismissed as false positives, ${merged.added} added`, 'Oracle');
          coverage.push({ check: 'Operator triage (model)', status: 'ran', note: req.model });
        }

        phase('summary', 'Coordinator writes the executive summary');
        const coordinator = createOperator('Aegis', 'coordinator', llm);
        const digest = findings
          .filter((f) => f.severity !== 'info')
          .slice(0, 40)
          .map((f) => `- [${f.severity}] ${f.title} (${f.confidence}) | fix: ${f.remediation.slice(0, 160)}`)
          .join('\n');
        const summary = await coordinator.assignTask(task('Executive summary',
          `Findings:\n${digest || '(none)'}\n\nReply with JSON only: {"executive":"three sentences","topActions":["…","…"]}`, 'coordinator'));
        const json = /\{[\s\S]*\}/.exec(summary.output ?? '')?.[0];
        if (json) {
          try {
            const parsed = JSON.parse(json) as { executive?: unknown; topActions?: unknown };
            if (typeof parsed.executive === 'string') executive = redactString(parsed.executive).slice(0, 1500);
            if (Array.isArray(parsed.topActions)) topActions = parsed.topActions.map((a) => redactString(String(a)).slice(0, 300)).slice(0, 5);
          } catch {
            /* fall back to the computed summary */
          }
        }
        run.emit('operator', executive ?? 'Summary computed from the findings', 'Aegis');
      } catch (error) {
        if (signal.aborted) throw error;
        coverage.push({ check: 'Operator triage (model)', status: 'failed', note: error instanceof Error ? error.message : String(error) });
        run.emit('error', `Model step failed, continuing with scanner results: ${error instanceof Error ? error.message : String(error)}`, 'operators');
      }
    } else {
      coverage.push({ check: 'Operator triage (model)', status: 'skipped', note: options.llmBaseUrl ? 'disabled for this run' : 'no model endpoint configured' });
    }

    phase('report', 'Building the report');
    const report = buildReport({
      id: req.id,
      findings,
      targets: {
        repo: req.repo ? { url: req.repo.url, commit, files: repoFiles } : undefined,
        site: req.site,
      },
      coverage,
      model: useModel ? req.model : undefined,
      executive,
      topActions,
      engineVersion: ENGINE_VERSION,
    });
    run.report = report;
    run.markdown = renderMarkdown(report);
    writeFileSync(join(workDir, 'report.json'), JSON.stringify(report, null, 2));
    writeFileSync(join(workDir, 'report.md'), run.markdown);
    run.status = 'completed';
    run.emit('done', `Assessment complete: ${report.summary.counts.critical} critical, ${report.summary.counts.high} high, ${report.summary.counts.medium} medium, ${report.summary.counts.low} low`, undefined, { counts: report.summary.counts });
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    run.status = signal.aborted && !/time box/.test(message) ? 'cancelled' : 'failed';
    run.error = redactString(message);
    run.emit(run.status === 'cancelled' ? 'done' : 'error', run.status === 'cancelled' ? 'Assessment cancelled' : `Assessment failed: ${run.error}`);
  } finally {
    clearTimeout(timeout);
    run.finishedAt = Date.now();
    if (repoPath) rmSync(repoPath, { recursive: true, force: true });
  }
}
