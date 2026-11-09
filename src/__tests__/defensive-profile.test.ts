/**
 * The defensive build's guarantees: the registry holds no removed capability, the scanners find
 * what they claim on a planted fixture, findings never carry secret values, and the API refuses
 * requests without its bearer token.
 */
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { mkdtempSync, mkdirSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { AddressInfo } from 'node:net';
import { presentRemovedCapabilities, registryListing, REMOVED_CAPABILITIES } from '../defensive/registry.js';
import { scanSecretsBuiltin } from '../defensive/secrets.js';
import { scanCode } from '../defensive/sast.js';
import { scanConfig } from '../defensive/iac.js';
import { parseOsvScanner, readPackages } from '../defensive/deps.js';
import { analyzePage, registrableDomain } from '../defensive/web.js';
import { mergeTriage, parseDebrief } from '../defensive/engine.js';
import { buildReport, renderMarkdown } from '../defensive/report.js';
import { createRepoTools, containedPath } from '../arsenal/repo-tools.js';
import { createAssessorServer, parseAssessmentRequest } from '../server.js';
import { ARCHETYPE_PROFILES } from '../operators/index.js';
import { OPERATOR_SYSTEM_PROMPTS } from '../prompts/index.js';

const FAKE_KEY = ['AKIA', 'Z7Q2', 'WXYV', 'ABCD', '1234'].join('');

let repo: string;

beforeAll(() => {
  repo = mkdtempSync(join(tmpdir(), 'defensive-fixture-'));
  mkdirSync(join(repo, 'src'));
  mkdirSync(join(repo, '.github', 'workflows'), { recursive: true });
  writeFileSync(join(repo, 'src', 'config.js'), `module.exports = { awsAccessKeyId: '${FAKE_KEY}', region: 'us-east-1' };\n`);
  writeFileSync(join(repo, 'src', 'users.js'), [
    "const db = require('./db');",
    'async function getUser(req, res) {',
    '  const rows = await db.query(`SELECT * FROM users WHERE id = ${req.query.id}`);',
    '  res.json(rows);',
    '}',
    'module.exports = { getUser };',
    '',
  ].join('\n'));
  writeFileSync(join(repo, 'package-lock.json'), JSON.stringify({
    name: 'fixture', lockfileVersion: 3,
    packages: { '': { name: 'fixture' }, 'node_modules/lodash': { version: '4.17.15' } },
  }));
  writeFileSync(join(repo, 'Dockerfile'), 'FROM node:latest\nCOPY . .\nCMD ["node", "src/users.js"]\n');
  writeFileSync(join(repo, '.github', 'workflows', 'ci.yml'), 'on: issues\njobs:\n  x:\n    runs-on: ubuntu-latest\n    steps:\n      - run: echo "${{ github.event.issue.title }}"\n');
});

afterAll(() => rmSync(repo, { recursive: true, force: true }));

describe('capability registry', () => {
  it('lists no removed capability', () => {
    expect(presentRemovedCapabilities()).toEqual([]);
  });

  it('ships exactly the four defensive operators, none of the offensive ones', () => {
    expect(Object.keys(ARCHETYPE_PROFILES).sort()).toEqual(['analyst', 'coordinator', 'recon', 'scanner']);
    for (const name of ['exploiter', 'infiltrator', 'exfiltrator', 'ghost']) {
      expect(REMOVED_CAPABILITIES).toContain(name);
      expect(Object.keys(OPERATOR_SYSTEM_PROMPTS)).not.toContain(name);
    }
  });

  it('every operator toolkit names only registered tools', () => {
    const names = new Set(registryListing().tools.map((t) => t.name));
    for (const p of Object.values(ARCHETYPE_PROFILES)) for (const t of p.tools) expect(names.has(t), t).toBe(true);
  });

  it('prompts carry no evasion or push-harder doctrine', () => {
    const all = Object.values(OPERATOR_SYSTEM_PROMPTS).join('\n').toLowerCase();
    for (const phrase of ['avoid detection', 'evade', 'stealth', 'push harder', 'traffic blending', 'jitter']) {
      expect(all).not.toContain(phrase);
    }
  });
});

describe('white-box scanners on a planted fixture', () => {
  it('finds the hardcoded AWS key, without its value in the finding', () => {
    const findings = scanSecretsBuiltin(repo);
    const aws = findings.find((f) => f.location?.file === 'src/config.js');
    expect(aws?.severity).toBe('critical');
    expect(JSON.stringify(findings)).not.toContain(FAKE_KEY);
  });

  it('finds the injectable SQL query', () => {
    const { findings } = scanCode(repo);
    const sqli = findings.find((f) => f.cwe?.includes('CWE-89'));
    expect(sqli?.location).toEqual({ file: 'src/users.js', line: 3 });
    expect(sqli?.confidence).toBe('likely');
  });

  it('reads the pinned lodash from the lockfile for the OSV audit', () => {
    expect(readPackages(repo)).toContainEqual({ name: 'lodash', version: '4.17.15', ecosystem: 'npm', manifest: 'package-lock.json' });
  });

  it('parses osv-scanner output into a dependency finding with CVE and fix', () => {
    const out = JSON.stringify({ results: [{ source: { path: `${repo}/package-lock.json` }, packages: [{
      package: { name: 'lodash', version: '4.17.15', ecosystem: 'npm' },
      vulnerabilities: [{ id: 'GHSA-p6mc-m468-83gw', aliases: ['CVE-2020-8203'], summary: 'Prototype Pollution in lodash',
        affected: [{ package: { name: 'lodash' }, ranges: [{ events: [{ introduced: '0' }, { fixed: '4.17.19' }] }] }] }],
      groups: [{ ids: ['GHSA-p6mc-m468-83gw', 'CVE-2020-8203'], max_severity: '7.4' }],
    }] }] });
    const [finding] = parseOsvScanner(out, repo);
    expect(finding.severity).toBe('high');
    expect(finding.cve).toEqual(['CVE-2020-8203']);
    expect(finding.remediation).toContain('4.17.19');
  });

  it('flags the root container, floating base image and workflow script injection', () => {
    const ids = scanConfig(repo).map((f) => f.title);
    expect(ids.some((t) => t.startsWith('Container runs as root'))).toBe(true);
    expect(ids.some((t) => t.startsWith('Base image not pinned'))).toBe(true);
    expect(ids.some((t) => t.startsWith('GitHub Actions: untrusted event data'))).toBe(true);
  });
});

describe('read-only repository tools', () => {
  it('refuse paths and symlinks that escape the repository', () => {
    symlinkSync('/etc', join(repo, 'escape'));
    expect(containedPath(repo, '../../etc/passwd')).toBeNull();
    expect(containedPath(repo, 'escape/hosts')).toBeNull();
    expect(containedPath(repo, 'src/users.js')).toContain('users.js');
    rmSync(join(repo, 'escape'));
  });

  it('redact secret values from file reads', async () => {
    const read = createRepoTools(repo).find((t) => t.name === 'read_file')!;
    const result = await read.handler({ parameters: { path: 'src/config.js' } });
    expect(result.output).not.toContain(FAKE_KEY);
  });
});

describe('passive posture analysis', () => {
  it('reports missing headers and an unproxied site from one response', () => {
    const headers = new Headers({ server: 'nginx/1.18.0', 'x-powered-by': 'Express 4.17.1' });
    const findings = analyzePage({ requestedUrl: 'https://app.example.com', finalUrl: 'https://app.example.com/', status: 200, headers, cookies: ['sid=abc; Path=/'], body: '' });
    const titles = findings.map((f) => f.title);
    expect(titles).toContain('Strict-Transport-Security header missing');
    expect(titles).toContain('Content-Security-Policy header missing');
    expect(titles).toContain('Software versions disclosed in response headers');
    expect(titles).toContain('Cookie "sid" missing Secure, HttpOnly, SameSite');
    expect(titles).toContain('Site is not served through the Cloudflare proxy');
  });

  it('computes registrable domains for two-level suffixes', () => {
    expect(registrableDomain('os.thehunted.com.au')).toBe('thehunted.com.au');
    expect(registrableDomain('a.b.example.com')).toBe('example.com');
  });
});

describe('operator triage and the report', () => {
  it('applies verdicts: confirmed raises confidence, false_positive drops, new findings need review', () => {
    const { findings } = scanCode(repo);
    const sqli = findings.find((f) => f.cwe?.includes('CWE-89'))!;
    const debrief = parseDebrief('Done.\n```json\n' + JSON.stringify({ findings: [
      { title: sqli.title, verdict: 'confirmed', details: 'req.query.id reaches db.query unescaped' },
      { title: 'Missing rate limit on login', severity: 'high', details: 'src/users.js:2 has no throttling', verdict: 'likely' },
    ] }) + '\n```');
    const merged = mergeTriage([sqli], debrief, 'Oracle');
    expect(merged.findings[0].confidence).toBe('confirmed');
    expect(merged.findings[1]).toMatchObject({ confidence: 'needs-review', location: { file: 'src/users.js', line: 2 } });
    expect(mergeTriage([sqli], [{ title: sqli.title, verdict: 'false_positive' }], 'Oracle').findings).toHaveLength(0);
  });

  it('builds a report with Cloudflare controls and a human-sent disclosure draft', () => {
    const report = buildReport({ id: 'r1', findings: [...scanCode(repo).findings, ...scanSecretsBuiltin(repo)], targets: { repo: { url: 'file:///fixture' } }, coverage: [], engineVersion: 'test' });
    expect(report.hardenWithCloudflare.map((h) => h.control)).toContain('WAF Managed Rules');
    expect(report.disclosureDraft).toContain('never sends it');
    expect(renderMarkdown(report)).toContain('## Harden with Cloudflare');
  });

  it('offers no disclosure draft for a site whose ownership is unverified', () => {
    const report = buildReport({ id: 'r2', findings: scanSecretsBuiltin(repo), targets: { site: { url: 'https://shop.acme.io/', verification: 'unverified' } }, coverage: [], engineVersion: 'test' });
    expect(report.disclosureDraft).toBeUndefined();
  });
});

describe('HTTP API', () => {
  const token = 'x'.repeat(40);
  it('requires the bearer token on every route', async () => {
    const server = createAssessorServer({ token, workRoot: tmpdir(), allowLocalTargets: false, allowLocalRepos: false });
    await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
    const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    try {
      expect((await fetch(`${base}/api/health`)).status).toBe(401);
      expect((await fetch(`${base}/api/tools`, { headers: { authorization: 'Bearer wrong' } })).status).toBe(401);
      expect((await fetch(`${base}/api/health`, { headers: { authorization: `Bearer ${token}` } })).status).toBe(200);
    } finally {
      server.close();
    }
  });

  it('refuses to start without a strong token', () => {
    expect(() => createAssessorServer({ token: 'short', workRoot: tmpdir(), allowLocalTargets: false, allowLocalRepos: false })).toThrow();
  });

  it('validates start requests and rejects file:// repos outside fixture mode', () => {
    expect(parseAssessmentRequest({ id: 'abcdefgh', model: '@cf/zai-org/glm-5.3', repo: { url: 'file:///etc' } }, { allowLocalRepos: false })).toMatch(/https/);
    expect(parseAssessmentRequest({ id: 'abcdefgh', model: '@cf/zai-org/glm-5.3' }, { allowLocalRepos: false })).toMatch(/repository, a site/);
    expect(parseAssessmentRequest({ id: 'abcdefgh', model: '@cf/zai-org/glm-5.3', site: { url: 'https://u:p@x.com' } }, { allowLocalRepos: false })).toMatch(/credentials/);
    expect(parseAssessmentRequest({ id: 'abcdefgh', model: '@cf/zai-org/glm-5.3', site: { url: 'https://x.com', verification: 'zone' } }, { allowLocalRepos: false }))
      .toMatchObject({ site: { url: 'https://x.com', verification: 'zone' } });
  });
});
