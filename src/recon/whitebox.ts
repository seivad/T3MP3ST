/**
 * whitebox — the repository side of the defensive assessment: resolve a repo the operator
 * supplied (a contained local path, or an HTTPS GitHub URL cloned with a one-shot token), then
 * ingest it and pack a security-ordered source view for the Analyst operator.
 *
 *     code-ingest (SELECT)  ->  context-pack (BUDGET)
 *
 * It reads source off disk only. It never probes a network target.
 *
 * SCOPE CAVEAT (inherited from code-ingest): blocks are extracted via web-tree-sitter for
 * Python/JS/TS/Go/Java/C/C++; a language without a bundled grammar is invisible to ranking
 * (the defensive scanners still pattern-match it). Do NOT describe this as "any language".
 *
 * The upstream DecompositionOrchestrator (a planner that split an objective into questions
 * stripped of security context so a worker model would not decline them) is not part of the
 * defensive build.
 */

import {
  ingestRepository,
  createMultiLangIngestConfig,
  packAnalysisUnits,
} from './code-ingest.js';
import { mkdtempSync, realpathSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { homedir, tmpdir } from 'node:os';
import { join as joinPath, isAbsolute, relative, resolve, sep } from 'node:path';

/** Result of turning a repo into a packed, security-ordered source blob. */
export interface RepoSourceContext {
  /** The packed, LLM-facing source text (security-priority order preserved). */
  sourceContext: string;
  /** The raw ingest stats (files/blocks + per-exposure counts). */
  stats: unknown;
  /** How many analysis units made it into the budget. */
  includedUnits: number;
  /** How many analysis units were dropped for budget. */
  droppedUnits: number;
}

/**
 * Thrown when a caller-supplied repoPath fails the containment check. The API
 * layer maps this to a 400 (bad request), never a 500 or a silent read.
 */
export class RepoPathError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'RepoPathError';
  }
}

export class RepoCloneError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'RepoCloneError';
  }
}

export interface ResolvedRepoSource {
  repoPath: string;
  source: 'local' | 'github';
  cleanup(): void;
}

function isGitHubHttpsRepoUrl(input: string): boolean {
  try {
    const url = new URL(input);
    return url.protocol === 'https:' &&
      url.hostname.toLowerCase() === 'github.com' &&
      /^\/[^/]+\/[^/]+(?:\.git)?\/?$/.test(url.pathname);
  } catch {
    return false;
  }
}

function getGitHubRepoToken(): string | undefined {
  return process.env.T3MP3ST_GITHUB_TOKEN?.trim() || process.env.GITHUB_TOKEN?.trim();
}

export function cloneGitHubRepoForAnalysis(repoUrl: string): ResolvedRepoSource {
  if (!isGitHubHttpsRepoUrl(repoUrl)) {
    throw new RepoCloneError('repoUrl must be an https://github.com/<owner>/<repo> URL');
  }

  const token = getGitHubRepoToken();
  if (!token) {
    throw new RepoCloneError('private GitHub repo scans require T3MP3ST_GITHUB_TOKEN or GITHUB_TOKEN');
  }

  const tempRoot = mkdtempSync(joinPath(tmpdir(), 't3mp3st-repo-'));
  const cloneDir = joinPath(tempRoot, 'repo');
  const askPassPath = joinPath(tempRoot, 'git-askpass.sh');
  try {
    writeFileSync(
      askPassPath,
      [
        '#!/bin/sh',
        'case "$1" in',
        "*Username*) printf '%s\\n' 'x-access-token' ;;",
        '*) printf "%s\\n" "$T3MP3ST_GIT_TOKEN" ;;',
        'esac',
        '',
      ].join('\n'),
      { mode: 0o700 },
    );
    execFileSync('git', [
      '-c', 'credential.helper=',
      'clone',
      '--depth', '1',
      '--filter=blob:none',
      repoUrl,
      cloneDir,
    ], {
      stdio: ['ignore', 'ignore', 'pipe'],
      env: {
        ...process.env,
        GIT_ASKPASS: askPassPath,
        GIT_TERMINAL_PROMPT: '0',
        T3MP3ST_GIT_TOKEN: token,
      },
    });

    return {
      repoPath: realpathSync(cloneDir),
      source: 'github',
      cleanup: () => { rmSync(tempRoot, { recursive: true, force: true }); },
    };
  } catch (error) {
    rmSync(tempRoot, { recursive: true, force: true });
    const message = error instanceof Error ? error.message.replaceAll(token, '[REDACTED]') : 'git clone failed';
    throw new RepoCloneError(`GitHub repo clone failed: ${message}`);
  }
}

export function resolveRepoSourceForAnalysis(input: unknown): ResolvedRepoSource {
  if (typeof input === 'string' && isGitHubHttpsRepoUrl(input.trim())) {
    return cloneGitHubRepoForAnalysis(input.trim());
  }
  return {
    repoPath: resolveContainedRepoPath(input),
    source: 'local',
    cleanup: () => { /* local repos are caller-owned; nothing to remove */ },
  };
}

/**
 * B-03 — path containment for the caller-supplied repoPath.
 *
 * The white-box path reads source off disk from an operator-supplied path. On a
 * localhost tool the operator legitimately analyzes any repo THEY own, but an
 * unbounded path is an arbitrary-directory read primitive (repoPath=/etc, another
 * user's home, ~/.ssh) reachable by anything that can reach the API. We therefore:
 *   1. canonicalize with realpath — collapses '..' AND resolves symlinks, so
 *      neither traversal nor a symlink planted inside the root can escape after
 *      the check (we validate the resolved target, not the string),
 *   2. require it to exist AND be a directory,
 *   3. confine it to an allowed ROOT — the operator's home by default, overridable
 *      with T3MP3ST_REPO_ROOT for repos kept elsewhere (/opt, /srv, a volume).
 * Returns the canonical, contained absolute path to hand to the reader.
 */
export function resolveContainedRepoPath(input: unknown): string {
  if (typeof input !== 'string' || !input.trim()) {
    throw new RepoPathError('repoPath is required and must be a non-empty string');
  }
  let root: string;
  try {
    root = realpathSync(resolve(process.env.T3MP3ST_REPO_ROOT || homedir()));
  } catch {
    throw new RepoPathError('configured T3MP3ST_REPO_ROOT does not resolve to an existing path');
  }
  let real: string;
  try {
    real = realpathSync(resolve(input));
  } catch {
    throw new RepoPathError('repoPath does not resolve to an existing path');
  }
  try {
    if (!statSync(real).isDirectory()) {
      throw new RepoPathError('repoPath must be a directory');
    }
  } catch (e) {
    if (e instanceof RepoPathError) throw e;
    // statSync can throw (e.g. a TOCTOU deletion between realpath and here) — normalize
    // to RepoPathError so the API layer returns a clean 400, never an unhandled rejection.
    throw new RepoPathError('repoPath is not accessible');
  }
  // relative(root, real) is '' when equal, starts with '..' (as a whole segment)
  // when real is outside root, or is absolute when they share no root (Windows).
  const rel = relative(root, real);
  if (rel !== '' && (rel === '..' || rel.startsWith(`..${sep}`) || isAbsolute(rel))) {
    throw new RepoPathError(
      `repoPath resolves outside the allowed root (${root}). Set T3MP3ST_REPO_ROOT to analyze a repo kept elsewhere.`,
    );
  }
  return real;
}

/**
 * Ingest a local repo and pack it into a single security-ordered source blob
 * suitable for handing to `TempestCommand.setWhiteboxSource` (or any consumer
 * that wants the highest-priority code first).
 *
 * @param repoPath  Absolute path to a LOCAL repo you own, or a GitHub HTTPS repo URL with token auth.
 * @param tokenBudget  Packing budget in tokens (default 24000).
 */
export function ingestRepoToSourceContext(
  repoPath: string,
  tokenBudget = 24000,
): RepoSourceContext {
  const source = resolveRepoSourceForAnalysis(repoPath);
  try {
    const result = ingestRepository(createMultiLangIngestConfig(source.repoPath));
    const packed = packAnalysisUnits(result.analysisUnits, tokenBudget);
    return {
      sourceContext: packed.text,
      stats: result.stats,
      includedUnits: packed.includedUnits.length,
      droppedUnits: packed.droppedUnits.length,
    };
  } finally {
    source.cleanup();
  }
}
