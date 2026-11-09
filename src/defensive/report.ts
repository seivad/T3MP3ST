/** Builds the assessment report and renders it as Markdown. */

import { SEVERITY_SCORES } from '../evidence/index.js';
import { controlsFor, hardenPlan } from './cloudflare.js';
import type { AssessmentReport, DefensiveFinding, Severity } from './types.js';

const ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
const WEIGHT: Record<Severity, number> = { critical: 40, high: 15, medium: 5, low: 1, info: 0 };

export function sortFindings(findings: DefensiveFinding[]): DefensiveFinding[] {
  const conf = { confirmed: 0, likely: 1, 'needs-review': 2 } as const;
  return [...findings].sort(
    (a, b) => SEVERITY_SCORES[b.severity] - SEVERITY_SCORES[a.severity] || conf[a.confidence] - conf[b.confidence] || a.title.localeCompare(b.title),
  );
}

export function severityCounts(findings: DefensiveFinding[]): Record<Severity, number> {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) counts[f.severity]++;
  return counts;
}

/** 0 (nothing found) to 100 (severe), saturating: one critical alone is 40. */
export function riskScore(findings: DefensiveFinding[]): number {
  const raw = findings.reduce((sum, f) => sum + WEIGHT[f.severity] * (f.confidence === 'needs-review' ? 0.5 : 1), 0);
  return Math.min(100, Math.round(raw));
}

function defaultExecutive(findings: DefensiveFinding[]): string {
  const counts = severityCounts(findings);
  const top = sortFindings(findings)[0];
  if (!top) return 'No issues were found by the checks that ran. Review the coverage table for checks that were skipped.';
  return `The assessment found ${findings.length} issue(s): ${counts.critical} critical, ${counts.high} high, ${counts.medium} medium. ` +
    `The most important is "${top.title}". Fix it first: ${top.remediation.split('. ')[0]}.`;
}

/** A draft advisory for the owner's security contact. The assessor never sends it. */
export function disclosureDraft(report: Pick<AssessmentReport, 'targets' | 'findings' | 'generatedAt'>): string | undefined {
  // A disclosure about a site whose ownership is not verified is not ours to draft.
  if (report.targets.site?.verification === 'unverified') return undefined;
  const serious = report.findings.filter((f) => f.severity === 'critical' || f.severity === 'high');
  if (serious.length === 0) return undefined;
  const target = report.targets.site?.url ?? report.targets.repo?.url ?? 'the assessed system';
  return [
    `Subject: Security findings for ${target} (${serious.length} high-priority)`,
    '',
    'DRAFT: review, edit and send this yourself. The Security Assessor never sends it.',
    '',
    `On ${report.generatedAt.slice(0, 10)} an internal defensive assessment of ${target} found the following high-priority issues:`,
    '',
    ...serious.map((f, i) => `${i + 1}. [${f.severity.toUpperCase()}] ${f.title}${f.cwe?.length ? ` (${f.cwe.join(', ')})` : ''}\n   Fix: ${f.remediation}\n   Verify: ${f.retest}`),
    '',
    'Evidence is in the attached report. Secret values are redacted; rotate any credential listed regardless.',
    'Please confirm receipt and an expected fix date.',
  ].join('\n');
}

export function buildReport(input: {
  id: string;
  findings: DefensiveFinding[];
  targets: AssessmentReport['targets'];
  coverage: AssessmentReport['coverage'];
  model?: string;
  executive?: string;
  topActions?: string[];
  engineVersion: string;
}): AssessmentReport {
  const findings = sortFindings(input.findings).map((f) => ({ ...f, cloudflare: f.cloudflare ?? controlsFor(f) }));
  const generatedAt = new Date().toISOString();
  const base = {
    id: input.id,
    generatedAt,
    engine: {
      name: 'T3MP3ST defensive profile',
      version: input.engineVersion,
      source: 'https://github.com/seivad/T3MP3ST/tree/defensive',
      model: input.model,
    },
    targets: input.targets,
    summary: {
      counts: severityCounts(findings),
      riskScore: riskScore(findings),
      executive: input.executive?.trim() || defaultExecutive(findings),
      topActions: input.topActions?.length
        ? input.topActions
        : findings.filter((f) => f.severity !== 'info').slice(0, 5).map((f) => `${f.title}: ${f.remediation.split('. ')[0]}.`),
    },
    findings,
    hardenWithCloudflare: hardenPlan(findings),
    coverage: input.coverage,
  };
  return { ...base, disclosureDraft: disclosureDraft(base) };
}

const esc = (s: string) => s.replace(/\|/g, '\\|');

/** The report as Markdown, for export and for the R2 copy. */
export function renderMarkdown(report: AssessmentReport): string {
  const lines: string[] = [];
  const c = report.summary.counts;
  lines.push(`# Security assessment report`, '');
  lines.push(`- **Report ID:** ${report.id}`, `- **Generated:** ${report.generatedAt}`);
  if (report.targets.repo) lines.push(`- **Repository:** ${report.targets.repo.url}${report.targets.repo.commit ? ` @ \`${report.targets.repo.commit.slice(0, 12)}\`` : ''}`);
  if (report.targets.site) lines.push(`- **Site:** ${report.targets.site.url} (ownership: ${report.targets.site.verification})`);
  lines.push(`- **Engine:** ${report.engine.name} ${report.engine.version}${report.engine.model ? `, model \`${report.engine.model}\`` : ''} ([source](${report.engine.source}))`, '');
  lines.push('## Summary', '', report.summary.executive, '');
  lines.push(`| Critical | High | Medium | Low | Info | Risk score |`, `|---|---|---|---|---|---|`, `| ${c.critical} | ${c.high} | ${c.medium} | ${c.low} | ${c.info} | ${report.summary.riskScore}/100 |`, '');
  if (report.summary.topActions.length) {
    lines.push('### Top actions', '', ...report.summary.topActions.map((a, i) => `${i + 1}. ${a}`), '');
  }
  lines.push('## Findings', '');
  for (const sev of ORDER) {
    const group = report.findings.filter((f) => f.severity === sev);
    if (!group.length) continue;
    lines.push(`### ${sev[0].toUpperCase()}${sev.slice(1)} (${group.length})`, '');
    for (const f of group) {
      lines.push(`#### ${f.title}`, '');
      const meta = [
        `**Confidence:** ${f.confidence}`,
        f.cwe?.length ? `**CWE:** ${f.cwe.join(', ')}` : '',
        f.cve?.length ? `**CVE:** ${f.cve.join(', ')}` : '',
        f.location?.file ? `**Location:** \`${f.location.file}${f.location.line ? `:${f.location.line}` : ''}\`` : f.location?.url ? `**Location:** ${f.location.url}` : '',
        `**Source:** ${f.source}`,
      ].filter(Boolean);
      lines.push(meta.join(' · '), '', f.description, '', '**Evidence**', '', '```', f.evidence, '```', '');
      if (f.triage) lines.push(`**Triage:** ${f.triage}`, '');
      lines.push(`**Remediation:** ${f.remediation}`, '', `**Retest:** ${f.retest}`, '');
      if (f.cloudflare?.length) lines.push(`**Cloudflare controls:** ${f.cloudflare.map((x) => `[${x.control}](${x.docs})`).join(', ')}`, '');
    }
  }
  if (report.hardenWithCloudflare.length) {
    lines.push('## Harden with Cloudflare', '', 'Edge controls reduce exposure while code fixes ship. They do not replace the fixes above.', '');
    lines.push('| Control | What to do | Findings |', '|---|---|---|');
    for (const h of report.hardenWithCloudflare) lines.push(`| [${esc(h.control)}](${h.docs}) | ${esc(h.action)} | ${h.findings.length} |`);
    lines.push('');
  }
  lines.push('## Coverage', '', '| Check | Status | Note |', '|---|---|---|');
  for (const cov of report.coverage) lines.push(`| ${esc(cov.check)} | ${cov.status} | ${esc(cov.note ?? '')} |`);
  lines.push('');
  if (report.disclosureDraft) lines.push('## Disclosure draft (human-sent only)', '', '```text', report.disclosureDraft, '```', '');
  lines.push('---', '', `Generated by the T3MP3ST defensive build (AGPL-3.0, source: ${report.engine.source}). Passive checks and read-only code analysis only.`);
  return lines.join('\n');
}
