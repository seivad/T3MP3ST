/** Shared helpers for the defensive scanners: file walking, text reads, finding ids, tool runs. */

import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import { walkRepo } from '../arsenal/repo-tools.js';

export { walkRepo };

const MAX_SCAN_BYTES = 512 * 1024;

/** A repository file's text, or null for binaries and files over the scan limit. */
export function readRepoText(root: string, file: string): string | null {
  try {
    const full = join(root, file);
    if (statSync(full).size > MAX_SCAN_BYTES) return null;
    const buffer = readFileSync(full);
    if (buffer.subarray(0, 8000).includes(0)) return null;
    return buffer.toString('utf8');
  } catch {
    return null;
  }
}

/** A stable id for a finding, so the same issue keeps its id across reruns. */
export function findingId(...parts: Array<string | number | undefined>): string {
  return createHash('sha256').update(parts.map((p) => String(p ?? '')).join('\u0000')).digest('hex').slice(0, 12);
}

/** Masks all but the first four characters of a secret value. */
export function maskSecret(value: string): string {
  const v = value.trim();
  if (v.length <= 8) return '****';
  return `${v.slice(0, 4)}${'*'.repeat(Math.min(12, v.length - 4))}`;
}

/** Whether a path looks like a test, fixture or example, where findings are often deliberate. */
export function isTestPath(file: string): boolean {
  return /(^|\/)(tests?|__tests__|spec|fixtures?|examples?|samples?|mocks?)(\/|$)|\.(test|spec)\.[a-z]+$/i.test(file);
}

/** Runs a scanner binary, resolving with stdout (its exit code is ignored: scanners exit 1 on findings). */
export function runScanner(
  command: string,
  args: string[],
  options: { cwd?: string; timeoutMs?: number; signal?: AbortSignal; env?: NodeJS.ProcessEnv } = {},
): Promise<{ stdout: string; stderr: string; missing: boolean }> {
  return new Promise((resolve) => {
    execFile(
      command,
      args,
      { cwd: options.cwd, timeout: options.timeoutMs ?? 300_000, signal: options.signal, maxBuffer: 64 * 1024 * 1024, env: options.env ?? process.env },
      (error, stdout, stderr) => {
        const missing = (error as NodeJS.ErrnoException | null)?.code === 'ENOENT';
        resolve({ stdout: String(stdout ?? ''), stderr: String(stderr ?? ''), missing });
      },
    );
  });
}
