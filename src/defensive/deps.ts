/**
 * Dependency and supply-chain audit against the OSV database (osv.dev).
 *
 * osv-scanner, when installed, reads every lockfile format it knows. Without it, a built-in
 * reader covers npm (package-lock.json, package.json exact versions) and pip (requirements.txt
 * pins) and queries the OSV API directly. Either way the only network call is to api.osv.dev:
 * package names and versions, nothing from the code itself.
 */

import { join } from 'node:path';
import { findingId, isTestPath, readRepoText, runScanner, walkRepo } from './scan-util.js';
import type { DefensiveFinding, Severity } from './types.js';

export const OSV_API = 'https://api.osv.dev';

interface OsvVulnerability {
  id: string;
  summary?: string;
  details?: string;
  aliases?: string[];
  severity?: Array<{ type: string; score: string }>;
  database_specific?: { severity?: string; cwe_ids?: string[] };
  affected?: Array<{
    package?: { name?: string; ecosystem?: string };
    ranges?: Array<{ events?: Array<{ introduced?: string; fixed?: string }> }>;
  }>;
}

export interface PackageRef {
  name: string;
  version: string;
  ecosystem: 'npm' | 'PyPI' | string;
  manifest: string;
}

/** Severity from an OSV record: the CVSS score when given, else the database's own label. */
export function osvSeverity(vuln: OsvVulnerability, maxSeverity?: string): Severity {
  const score = Number(maxSeverity);
  if (Number.isFinite(score) && score > 0) {
    return score >= 9 ? 'critical' : score >= 7 ? 'high' : score >= 4 ? 'medium' : 'low';
  }
  const label = (vuln.database_specific?.severity ?? '').toUpperCase();
  if (label === 'CRITICAL') return 'critical';
  if (label === 'HIGH') return 'high';
  if (label === 'MODERATE' || label === 'MEDIUM') return 'medium';
  if (label === 'LOW') return 'low';
  return 'medium';
}

function fixedVersion(vuln: OsvVulnerability, name: string): string | undefined {
  for (const affected of vuln.affected ?? []) {
    if (affected.package?.name && affected.package.name !== name) continue;
    for (const range of affected.ranges ?? []) {
      const fixed = range.events?.find((e) => e.fixed)?.fixed;
      if (fixed) return fixed;
    }
  }
  return undefined;
}

export function vulnFinding(pkg: PackageRef, vuln: OsvVulnerability, maxSeverity?: string): DefensiveFinding {
  const cves = [vuln.id, ...(vuln.aliases ?? [])].filter((id) => id.startsWith('CVE-'));
  const fixed = fixedVersion(vuln, pkg.name);
  const severity = osvSeverity(vuln, maxSeverity);
  const dev = isTestPath(pkg.manifest);
  return {
    id: findingId('dep', pkg.ecosystem, pkg.name, pkg.version, vuln.id),
    title: `Vulnerable dependency: ${pkg.name}@${pkg.version} (${cves[0] ?? vuln.id})`,
    severity,
    category: 'dependency',
    cwe: vuln.database_specific?.cwe_ids?.length ? vuln.database_specific.cwe_ids : ['CWE-1395'],
    cve: cves.length ? cves : undefined,
    location: { file: pkg.manifest },
    evidence: `${pkg.manifest} pins ${pkg.ecosystem} package ${pkg.name} at ${pkg.version}, affected by ${vuln.id}${vuln.aliases?.length ? ` (${vuln.aliases.join(', ')})` : ''}.`,
    description: (vuln.summary || vuln.details || `Known vulnerability ${vuln.id}`).slice(0, 600),
    remediation: fixed
      ? `Upgrade ${pkg.name} to ${fixed} or later, regenerate the lockfile, and redeploy.`
      : `No fixed release is recorded for ${pkg.name}; replace the package or mitigate per https://osv.dev/vulnerability/${vuln.id}.`,
    retest: `Re-run the dependency audit: ${vuln.id} is no longer reported for ${pkg.name}.`,
    source: 'OSV dependency audit',
    confidence: dev ? 'needs-review' : 'confirmed',
  };
}

interface OsvScannerOutput {
  results?: Array<{
    source?: { path?: string };
    packages?: Array<{
      package?: { name?: string; version?: string; ecosystem?: string };
      vulnerabilities?: OsvVulnerability[];
      groups?: Array<{ ids?: string[]; max_severity?: string }>;
    }>;
  }>;
}

/** Parses osv-scanner's JSON output into findings (one per package and vulnerability group). */
export function parseOsvScanner(stdout: string, root: string): DefensiveFinding[] {
  let parsed: OsvScannerOutput;
  try {
    parsed = JSON.parse(stdout.slice(stdout.indexOf('{'))) as OsvScannerOutput;
  } catch {
    return [];
  }
  const findings: DefensiveFinding[] = [];
  for (const result of parsed.results ?? []) {
    const manifest = (result.source?.path ?? '').replace(root, '').replace(/^\/+/, '');
    for (const entry of result.packages ?? []) {
      const pkg: PackageRef = {
        name: entry.package?.name ?? 'unknown',
        version: entry.package?.version ?? 'unknown',
        ecosystem: entry.package?.ecosystem ?? 'unknown',
        manifest,
      };
      const vulns = entry.vulnerabilities ?? [];
      const groups = entry.groups?.length ? entry.groups : vulns.map((v) => ({ ids: [v.id], max_severity: undefined }));
      for (const group of groups) {
        const ids = group.ids ?? [];
        const primary = vulns.find((v) => v.id.startsWith('GHSA') && ids.includes(v.id)) ?? vulns.find((v) => ids.includes(v.id));
        if (!primary) continue;
        const aliases = new Set([...(primary.aliases ?? []), ...ids.filter((id) => id !== primary.id)]);
        findings.push(vulnFinding(pkg, { ...primary, aliases: [...aliases] }, group.max_severity));
      }
    }
  }
  return findings;
}

/** Exact-version packages from npm and pip manifests (the built-in reader). */
export function readPackages(root: string): PackageRef[] {
  const out = new Map<string, PackageRef>();
  const add = (ref: PackageRef) => out.set(`${ref.ecosystem}:${ref.name}@${ref.version}`, ref);
  for (const file of walkRepo(root)) {
    const base = file.split('/').pop() ?? '';
    if (base === 'package-lock.json') {
      const text = readRepoText(root, file);
      if (!text) continue;
      try {
        const lock = JSON.parse(text) as {
          packages?: Record<string, { version?: string; link?: boolean }>;
          dependencies?: Record<string, { version?: string }>;
        };
        for (const [path, meta] of Object.entries(lock.packages ?? {})) {
          if (!path || meta.link || !meta.version) continue;
          const name = path.slice(path.lastIndexOf('node_modules/') + 'node_modules/'.length);
          add({ name, version: meta.version, ecosystem: 'npm', manifest: file });
        }
        for (const [name, meta] of Object.entries(lock.dependencies ?? {})) {
          if (meta.version) add({ name, version: meta.version, ecosystem: 'npm', manifest: file });
        }
      } catch {
        /* unparseable lockfile: skipped, the coverage note says so */
      }
    } else if (base === 'package.json') {
      const text = readRepoText(root, file);
      if (!text) continue;
      try {
        const pkg = JSON.parse(text) as { dependencies?: Record<string, string>; devDependencies?: Record<string, string> };
        for (const [name, range] of Object.entries({ ...pkg.dependencies, ...pkg.devDependencies })) {
          const exact = /^=?v?(\d+\.\d+\.\d+(?:[-+][\w.]+)?)$/.exec(range.trim());
          if (exact) add({ name, version: exact[1], ecosystem: 'npm', manifest: file });
        }
      } catch {
        /* skipped */
      }
    } else if (/^requirements.*\.txt$/.test(base)) {
      const text = readRepoText(root, file) ?? '';
      for (const line of text.split('\n')) {
        const pin = /^\s*([A-Za-z0-9_.-]+)(?:\[[^\]]*\])?\s*==\s*([A-Za-z0-9_.+-]+)/.exec(line);
        if (pin) add({ name: pin[1], version: pin[2], ecosystem: 'PyPI', manifest: file });
      }
    }
  }
  return [...out.values()];
}

/** Queries OSV for `packages` (batch for ids, then each vulnerability's record). */
export async function queryOsv(packages: PackageRef[], fetchImpl: typeof fetch = fetch, signal?: AbortSignal): Promise<DefensiveFinding[]> {
  const findings: DefensiveFinding[] = [];
  const records = new Map<string, OsvVulnerability>();
  for (let i = 0; i < packages.length; i += 500) {
    const batch = packages.slice(i, i + 500);
    const response = await fetchImpl(`${OSV_API}/v1/querybatch`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ queries: batch.map((p) => ({ package: { name: p.name, ecosystem: p.ecosystem }, version: p.version })) }),
      signal,
    });
    if (!response.ok) throw new Error(`OSV querybatch returned HTTP ${response.status}`);
    const body = (await response.json()) as { results?: Array<{ vulns?: Array<{ id: string }> }> };
    for (const [index, result] of (body.results ?? []).entries()) {
      for (const { id } of result.vulns ?? []) {
        if (!records.has(id) && records.size < 200) {
          const detail = await fetchImpl(`${OSV_API}/v1/vulns/${encodeURIComponent(id)}`, { signal });
          if (detail.ok) records.set(id, (await detail.json()) as OsvVulnerability);
        }
        const vuln = records.get(id);
        if (vuln) findings.push(vulnFinding(batch[index], vuln));
      }
    }
  }
  return findings;
}

/** Collapses an advisory reported under several ids (GHSA and CVE) into one finding per package. */
function dedupe(findings: DefensiveFinding[]): DefensiveFinding[] {
  const byKey = new Map<string, DefensiveFinding>();
  for (const f of findings) {
    const key = `${f.title.split(' (')[0]}|${(f.cve ?? []).sort().join(',') || f.id}`;
    if (!byKey.has(key)) byKey.set(key, f);
  }
  return [...byKey.values()];
}

/** The dependency audit: osv-scanner when installed, else the built-in reader and the OSV API. */
export async function scanDependencies(
  root: string,
  signal?: AbortSignal,
): Promise<{ findings: DefensiveFinding[]; engine: 'osv-scanner' | 'osv-api'; packages?: number }> {
  const scanner = await runScanner('osv-scanner', ['scan', 'source', '--recursive', '--format', 'json', '--allow-no-lockfiles', root], {
    signal,
    timeoutMs: 300_000,
    cwd: join(root),
  });
  if (!scanner.missing && scanner.stdout.trim().startsWith('{')) {
    return { findings: dedupe(parseOsvScanner(scanner.stdout, root)), engine: 'osv-scanner' };
  }
  const packages = readPackages(root);
  if (packages.length === 0) return { findings: [], engine: 'osv-api', packages: 0 };
  return { findings: dedupe(await queryOsv(packages, fetch, signal)), engine: 'osv-api', packages: packages.length };
}
