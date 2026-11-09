/**
 * Infrastructure-as-code and configuration review: Dockerfiles, Compose, GitHub Actions,
 * Terraform, Kubernetes manifests, Wrangler config and committed environment files.
 */

import { findingId, readRepoText, walkRepo } from './scan-util.js';
import type { DefensiveFinding, Severity } from './types.js';

interface ConfigRule {
  id: string;
  title: string;
  cwe: string;
  severity: Severity;
  files: RegExp;
  /** Matches a line, or (with `whole`) is tested against the whole file and reports line 1. */
  pattern: RegExp;
  whole?: boolean;
  /** For `whole` rules: the rule fires when the pattern does NOT match. */
  absent?: boolean;
  description: string;
  remediation: string;
}

const DOCKERFILE = /(^|\/)(Dockerfile|Containerfile)(\.[\w-]+)?$/;
const COMPOSE = /(^|\/)(docker-)?compose(\.[\w-]+)?\.ya?ml$/;
const WORKFLOW = /(^|\/)\.github\/workflows\/[^/]+\.ya?ml$/;
const TERRAFORM = /\.tf$/;
const K8S = /\.(ya?ml)$/;
const WRANGLER = /(^|\/)wrangler\.(toml|jsonc?)$/;

export const CONFIG_RULES: ConfigRule[] = [
  {
    id: 'docker-root-user',
    title: 'Container runs as root',
    cwe: 'CWE-250',
    severity: 'medium',
    files: DOCKERFILE,
    pattern: /^\s*USER\s+(?!root\b|0\b)\S+/m,
    whole: true,
    absent: true,
    description: 'The image never switches to an unprivileged user, so a compromise of the app is a compromise of root in the container.',
    remediation: 'Create a dedicated user and add `USER <name>` before the entrypoint.',
  },
  {
    id: 'docker-latest-tag',
    title: 'Base image not pinned',
    cwe: 'CWE-1357',
    severity: 'low',
    files: DOCKERFILE,
    pattern: /^\s*FROM\s+(?!scratch\b)[^\s@:]+(?::latest)?(?:\s+AS\s+\w+)?\s*$/i,
    description: 'The base image floats (`latest` or no tag), so builds are not reproducible and can silently pick up a compromised image.',
    remediation: 'Pin the base image by version and digest (`image:1.2.3@sha256:…`) and update it deliberately.',
  },
  {
    id: 'docker-remote-add',
    title: 'Dockerfile fetches remote content without verification',
    cwe: 'CWE-494',
    severity: 'medium',
    files: DOCKERFILE,
    pattern: /^\s*ADD\s+https?:\/\/|curl[^|\n]*\|\s*(?:ba|z)?sh\b|wget[^|\n]*\|\s*(?:ba|z)?sh\b/i,
    description: 'The build downloads and runs remote content without a checksum, a supply-chain risk.',
    remediation: 'Download to a file, verify a pinned SHA-256, then use it.',
  },
  {
    id: 'docker-secret-env',
    title: 'Secret baked into the image',
    cwe: 'CWE-798',
    severity: 'high',
    files: DOCKERFILE,
    pattern: /^\s*(?:ENV|ARG)\s+\w*(?:SECRET|PASSWORD|TOKEN|API_KEY|PRIVATE_KEY)\w*\s*[= ]\s*\S{6,}/i,
    description: 'A credential is set in the Dockerfile and ends up in every image layer and registry copy.',
    remediation: 'Pass secrets at run time (or with BuildKit `--secret`), never in ENV/ARG defaults.',
  },
  {
    id: 'compose-privileged',
    title: 'Privileged container in Compose',
    cwe: 'CWE-250',
    severity: 'high',
    files: COMPOSE,
    pattern: /^\s*privileged:\s*true/,
    description: 'A privileged container can take over the host.',
    remediation: 'Remove `privileged: true`; grant only the specific capabilities needed.',
  },
  {
    id: 'compose-db-exposed',
    title: 'Database port published on all interfaces',
    cwe: 'CWE-668',
    severity: 'medium',
    files: COMPOSE,
    pattern: /^\s*-\s*["']?(?:0\.0\.0\.0:)?(?:3306|5432|6379|27017|9200|11211):\d+/,
    description: 'A datastore port is published to every interface of the host.',
    remediation: 'Bind to 127.0.0.1 or keep the service on an internal network only.',
  },
  {
    id: 'gha-pull-request-target',
    title: 'GitHub Actions: pull_request_target checks out untrusted code',
    cwe: 'CWE-829',
    severity: 'critical',
    files: WORKFLOW,
    pattern: /pull_request_target[\s\S]*ref:\s*\$\{\{\s*github\.event\.pull_request\.head\.(?:sha|ref)/,
    whole: true,
    description: 'The workflow runs with repository secrets and write permissions on code from a fork\'s pull request.',
    remediation: 'Use `pull_request` for untrusted code, or split into a privileged workflow that never checks out the PR head.',
  },
  {
    id: 'gha-script-injection',
    title: 'GitHub Actions: untrusted event data in a run step',
    cwe: 'CWE-78',
    severity: 'high',
    files: WORKFLOW,
    pattern: /\$\{\{\s*github\.event\.(?:issue|pull_request|comment|review|head_commit|discussion)\.[\w.]*(?:title|body|message|name|label|ref)\s*\}\}/,
    description: 'Attacker-controlled text (an issue title, a PR body) is expanded into a shell script.',
    remediation: 'Pass the value through an environment variable (`env: TITLE: ${{ … }}`) and quote "$TITLE" in the script.',
  },
  {
    id: 'gha-unpinned-action',
    title: 'GitHub Actions: third-party action not pinned to a commit',
    cwe: 'CWE-1357',
    severity: 'low',
    files: WORKFLOW,
    pattern: /uses:\s*(?!actions\/|github\/|\.\/)[\w.-]+\/[\w./-]+@(?:main|master|v?\d+(?:\.\d+)?)\s*$/,
    description: 'A third-party action is referenced by a moving tag or branch, so its owner (or an attacker who takes it over) can change what runs with your secrets.',
    remediation: 'Pin to a full commit SHA and let Dependabot propose updates.',
  },
  {
    id: 'gha-write-all',
    title: 'GitHub Actions: workflow token has write-all permissions',
    cwe: 'CWE-250',
    severity: 'medium',
    files: WORKFLOW,
    pattern: /^\s*permissions:\s*write-all/,
    description: 'Every job gets a token that can write to the repository.',
    remediation: 'Default to `permissions: contents: read` and grant writes per job.',
  },
  {
    id: 'tf-public-bucket',
    title: 'Terraform: storage bucket readable by the public',
    cwe: 'CWE-732',
    severity: 'high',
    files: TERRAFORM,
    pattern: /acl\s*=\s*"public-read(?:-write)?"|block_public_acls\s*=\s*false|allUsers/,
    description: 'Objects in the bucket are readable by anyone on the internet.',
    remediation: 'Make the bucket private, enable public access blocks, and serve public files through a CDN with signed URLs if needed.',
  },
  {
    id: 'tf-open-admin-port',
    title: 'Terraform: administrative port open to the internet',
    cwe: 'CWE-284',
    severity: 'high',
    files: TERRAFORM,
    pattern: /cidr_blocks\s*=\s*\[\s*"0\.0\.0\.0\/0"\s*\][\s\S]{0,200}?(?:from_port\s*=\s*(?:22|3389|3306|5432))|(?:from_port\s*=\s*(?:22|3389|3306|5432))[\s\S]{0,200}?cidr_blocks\s*=\s*\[\s*"0\.0\.0\.0\/0"/,
    whole: true,
    description: 'SSH, RDP or a database port accepts connections from any address.',
    remediation: 'Restrict ingress to known ranges, or remove it and use Cloudflare Access / Tunnel for administrative access.',
  },
  {
    id: 'k8s-privileged',
    title: 'Kubernetes: privileged or host-namespace pod',
    cwe: 'CWE-250',
    severity: 'high',
    files: K8S,
    pattern: /^\s*(?:privileged:\s*true|hostNetwork:\s*true|hostPID:\s*true|allowPrivilegeEscalation:\s*true)/,
    description: 'The pod can escape to the node.',
    remediation: 'Remove the setting; run with `runAsNonRoot: true`, `allowPrivilegeEscalation: false` and a read-only root filesystem.',
  },
  {
    id: 'wrangler-secret-var',
    title: 'Wrangler: secret stored as a plain var',
    cwe: 'CWE-798',
    severity: 'high',
    files: WRANGLER,
    pattern: /["']?\w*(?:SECRET|PASSWORD|TOKEN|API_KEY|PRIVATE_KEY)\w*["']?\s*[:=]\s*["'][^"'$]{8,}["']/i,
    description: 'A credential is committed in the Worker\'s configuration, where it is visible in the repository and the dashboard.',
    remediation: 'Remove it from vars and set it with `wrangler secret put NAME`, then rotate it.',
  },
  {
    id: 'env-file-committed',
    title: 'Environment file committed to the repository',
    cwe: 'CWE-538',
    severity: 'medium',
    files: /(^|\/)\.env(\.(?!example|sample|template)[\w-]+)?$/,
    pattern: /^\s*[A-Z][A-Z0-9_]*\s*=\s*\S+/m,
    whole: true,
    description: 'A .env file with values is tracked in git; such files usually hold credentials.',
    remediation: 'Delete it from the repository (and history), add `.env*` to .gitignore, and commit a `.env.example` with placeholders.',
  },
];

function lineOf(text: string, index: number): number {
  return text.slice(0, index).split('\n').length;
}

/** Runs every configuration rule over the matching files. */
export function scanConfig(root: string): DefensiveFinding[] {
  const findings: DefensiveFinding[] = [];
  for (const file of walkRepo(root)) {
    const rules = CONFIG_RULES.filter((r) => r.files.test(file));
    if (rules.length === 0) continue;
    const text = readRepoText(root, file);
    if (text === null) continue;
    if (K8S.test(file) && rules.some((r) => r.id === 'k8s-privileged') && !/^\s*(apiVersion|kind):/m.test(text)) {
      // Plain YAML that is not a Kubernetes manifest.
      rules.splice(rules.findIndex((r) => r.id === 'k8s-privileged'), 1);
    }
    for (const rule of rules) {
      let line: number | undefined;
      let excerpt = '';
      if (rule.whole) {
        const match = rule.pattern.exec(text);
        if (rule.absent ? match : !match) continue;
        line = match ? lineOf(text, match.index) : 1;
        excerpt = match ? match[0].split('\n')[0] : '(no USER instruction in the file)';
      } else {
        const lines = text.split('\n');
        const index = lines.findIndex((l) => rule.pattern.test(l));
        if (index < 0) continue;
        line = index + 1;
        excerpt = lines[index];
      }
      const safeExcerpt = rule.cwe === 'CWE-798' ? excerpt.replace(/([:=]\s*["']?)([^"'\s]{4})[^"'\s]*/, '$1$2…[redacted]') : excerpt;
      findings.push({
        id: findingId('config', file, rule.id),
        title: `${rule.title} (${file})`,
        severity: rule.severity,
        category: 'config',
        cwe: [rule.cwe],
        location: { file, line },
        evidence: `${file}:${line}: ${safeExcerpt.trim().slice(0, 240)}`,
        description: rule.description,
        remediation: rule.remediation,
        retest: `Re-run the configuration review: rule ${rule.id} no longer fires for ${file}.`,
        source: 'T3MP3ST configuration review',
        confidence: 'confirmed',
      });
    }
  }
  return findings;
}
