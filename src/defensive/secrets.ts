/**
 * Secrets in code: credentials committed to the operator's repository.
 *
 * Two sources, merged by file and line: gitleaks (its full rule set, run with --redact, when the
 * binary is installed), and a built-in rule set that needs nothing. A finding never carries the
 * secret: evidence shows the rule, the location and a masked prefix.
 */

import { findingId, isTestPath, maskSecret, readRepoText, runScanner, walkRepo } from './scan-util.js';
import type { DefensiveFinding, Severity } from './types.js';

interface SecretRule {
  id: string;
  label: string;
  severity: Severity;
  pattern: RegExp;
  /** Which capture group holds the secret (default 0). */
  group?: number;
}

/** High-signal provider formats plus generic assignments of long literal values to secret-named keys. */
export const SECRET_RULES: SecretRule[] = [
  { id: 'aws-access-key', label: 'AWS access key ID', severity: 'critical', pattern: /\b(AKIA|ASIA)[0-9A-Z]{16}\b/ },
  { id: 'github-token', label: 'GitHub token', severity: 'critical', pattern: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/ },
  { id: 'github-fine-grained', label: 'GitHub fine-grained token', severity: 'critical', pattern: /\bgithub_pat_[A-Za-z0-9_]{60,}\b/ },
  { id: 'gitlab-token', label: 'GitLab token', severity: 'critical', pattern: /\bglpat-[A-Za-z0-9\-_]{20}\b/ },
  { id: 'slack-token', label: 'Slack token', severity: 'high', pattern: /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/ },
  { id: 'stripe-live-key', label: 'Stripe live secret key', severity: 'critical', pattern: /\b(sk|rk)_live_[0-9a-zA-Z]{20,}\b/ },
  { id: 'google-api-key', label: 'Google API key', severity: 'high', pattern: /\bAIza[0-9A-Za-z\-_]{35}\b/ },
  { id: 'openai-key', label: 'OpenAI API key', severity: 'critical', pattern: /\bsk-(proj-)?[A-Za-z0-9_-]{32,}\b/ },
  { id: 'anthropic-key', label: 'Anthropic API key', severity: 'critical', pattern: /\bsk-ant-[A-Za-z0-9_-]{32,}\b/ },
  { id: 'cloudflare-api-token', label: 'Cloudflare API token', severity: 'critical', pattern: /(?:CLOUDFLARE|CF)_API_(?:TOKEN|KEY)\s*[:=]\s*["']?([A-Za-z0-9_-]{37,40})["']?/i, group: 1 },
  { id: 'private-key', label: 'Private key', severity: 'critical', pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY( BLOCK)?-----/ },
  { id: 'db-url-password', label: 'Database URL with password', severity: 'critical', pattern: /\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp):\/\/[^:\s/"'@]+:([^@\s"'/]{4,})@/i, group: 1 },
  { id: 'jwt', label: 'JSON Web Token', severity: 'medium', pattern: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/ },
  {
    id: 'generic-secret-assignment',
    label: 'Hardcoded secret',
    severity: 'high',
    pattern: /\b(?:[A-Za-z0-9_]*?(?:secret|passw(?:or)?d|pwd|api[_-]?key|access[_-]?key|auth[_-]?token|private[_-]?key|client[_-]?secret|token))\b["']?\s*(?:[:=]|=>)\s*["'`]([^"'`\s]{8,})["'`]/i,
    group: 1,
  },
];

/** Values that are clearly placeholders, not secrets. */
const PLACEHOLDER = /^(?:x+|\*+|changeme|change_me|your[_-]?.*|example.*|dummy.*|placeholder.*|test.*|sample.*|redacted|<.*>|\$\{.*\}|\{\{.*\}\}|process\.env.*|os\.environ.*|env\(.*)$/i;

const SKIP_FILES = /(^|\/)(package-lock\.json|yarn\.lock|pnpm-lock\.yaml|poetry\.lock|Cargo\.lock|go\.sum|composer\.lock)$|\.(min\.js|map|svg|png|jpe?g|gif|ico|woff2?|ttf|pdf|zip|gz)$/i;

const REMEDIATION =
  'Revoke and rotate the credential now (assume it is compromised: it is in the repository history). ' +
  'Move it to a secret store (Workers Secrets via `wrangler secret put`, or your platform\'s equivalent) and read it from the environment. ' +
  'Purge it from git history (git filter-repo or BFG) and enable secret scanning / push protection on the repository.';

/** Runs the built-in rules over every text file under `root`. */
export function scanSecretsBuiltin(root: string): DefensiveFinding[] {
  const findings: DefensiveFinding[] = [];
  for (const file of walkRepo(root)) {
    if (SKIP_FILES.test(file)) continue;
    const text = readRepoText(root, file);
    if (text === null) continue;
    const lines = text.split('\n');
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (line.length > 4000) continue;
      for (const rule of SECRET_RULES) {
        const match = rule.pattern.exec(line);
        if (!match) continue;
        const value = match[rule.group ?? 0] ?? match[0];
        if (rule.id === 'generic-secret-assignment' && (PLACEHOLDER.test(value) || /^[a-z_.]+$/i.test(value) && value.length < 12)) continue;
        findings.push(secretFinding(file, i + 1, rule.id, rule.label, rule.severity, value, 'built-in secret rules'));
        break; // one finding per line
      }
    }
  }
  return findings;
}

function secretFinding(file: string, line: number, ruleId: string, label: string, severity: Severity, value: string, source: string): DefensiveFinding {
  const test = isTestPath(file);
  return {
    id: findingId('secret', file, line, ruleId),
    title: `${label} committed in ${file}`,
    severity: test && severity === 'critical' ? 'high' : severity,
    category: 'secret',
    cwe: ['CWE-798'],
    location: { file, line },
    evidence: `${file}:${line} matches rule "${ruleId}" (value ${maskSecret(value)}, redacted)`,
    description: `A ${label.toLowerCase()} is hardcoded in source control. Anyone with read access to the repository, its forks or its history can use it.${test ? ' The file looks like a test or fixture; confirm whether the value is real.' : ''}`,
    remediation: REMEDIATION,
    retest: `Re-scan the repository: no secret is reported at ${file}:${line}, and the old credential is rejected by the provider.`,
    source,
    confidence: test ? 'needs-review' : 'confirmed',
  };
}

interface GitleaksResult {
  RuleID?: string;
  Description?: string;
  File?: string;
  StartLine?: number;
  Secret?: string;
}

/** Runs gitleaks (if installed) in directory mode with redaction; null when it is not installed. */
export async function scanSecretsGitleaks(root: string, signal?: AbortSignal): Promise<DefensiveFinding[] | null> {
  const { stdout, missing } = await runScanner(
    'gitleaks',
    ['dir', root, '--no-banner', '--redact', '--report-format', 'json', '--report-path', '/dev/stdout', '--exit-code', '0', '--log-level', 'error'],
    { signal, timeoutMs: 300_000 },
  );
  if (missing) return null;
  let results: GitleaksResult[] = [];
  try {
    const start = stdout.indexOf('[');
    results = start >= 0 ? (JSON.parse(stdout.slice(start)) as GitleaksResult[]) : [];
  } catch {
    return [];
  }
  return results
    .filter((r) => r.File && r.StartLine)
    .map((r) => {
      const file = r.File!.startsWith(root) ? r.File!.slice(root.length).replace(/^\/+/, '') : r.File!;
      return secretFinding(file, r.StartLine!, r.RuleID ?? 'gitleaks', r.Description || 'Secret', 'high', 'REDACTED', 'gitleaks');
    });
}

/** Both sources, deduplicated by file and line (the built-in label wins: it is more specific). */
export async function scanSecrets(root: string, signal?: AbortSignal): Promise<{ findings: DefensiveFinding[]; gitleaks: boolean }> {
  const builtin = scanSecretsBuiltin(root);
  const leaks = await scanSecretsGitleaks(root, signal);
  const seen = new Set(builtin.map((f) => `${f.location?.file}:${f.location?.line}`));
  const merged = [...builtin];
  for (const f of leaks ?? []) {
    const key = `${f.location?.file}:${f.location?.line}`;
    if (!seen.has(key)) {
      seen.add(key);
      merged.push(f);
    }
  }
  return { findings: merged, gitleaks: leaks !== null };
}
