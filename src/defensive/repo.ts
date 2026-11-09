/**
 * Cloning the operator's repository for review.
 *
 * Any https:// git URL is accepted. A token, when given, is used for this one clone: it reaches
 * git only through the environment of the git process (read back by a GIT_ASKPASS helper that
 * contains no secret itself), is never written to the repository's config or the work directory,
 * and is scrubbed from any error text. The clone runs with hooks, submodules and local-file
 * transports disabled, shallow, and under a timeout.
 */

import { execFile } from 'node:child_process';
import { mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

export class RepoCloneFailed extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'RepoCloneFailed';
  }
}

/**
 * Throws unless `url` is an https git URL without embedded credentials. `file://` is accepted
 * only when the caller allows it (T3MP3ST_ALLOW_LOCAL_REPOS=1, for local fixture runs).
 */
export function validateRepoUrl(url: string, allowFile = false): URL {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new RepoCloneFailed('repository URL is not a valid URL');
  }
  if (allowFile && parsed.protocol === 'file:') return parsed;
  if (parsed.protocol !== 'https:') throw new RepoCloneFailed('repository URL must use https://');
  if (parsed.username || parsed.password) throw new RepoCloneFailed('repository URL must not embed credentials; use the GITHUB_TOKEN secret');
  if (!parsed.hostname.includes('.')) throw new RepoCloneFailed('repository host must be a public hostname');
  return parsed;
}

function run(
  command: string,
  args: string[],
  options: { cwd?: string; env: NodeJS.ProcessEnv; timeoutMs: number; signal?: AbortSignal },
): Promise<string> {
  return new Promise((resolve, reject) => {
    execFile(command, args, { cwd: options.cwd, env: options.env, timeout: options.timeoutMs, signal: options.signal, maxBuffer: 8 * 1024 * 1024 }, (error, stdout, stderr) => {
      if (error) reject(new Error(String(stderr || error.message)));
      else resolve(String(stdout));
    });
  });
}

/**
 * Shallow-clones `url` into `<workDir>/repo` and returns that path and the checked-out commit.
 * The askpass helper is deleted before this returns, whatever the outcome.
 */
export async function cloneRepository(
  url: string,
  workDir: string,
  options: { token?: string; ref?: string; signal?: AbortSignal; timeoutMs?: number; allowFile?: boolean } = {},
): Promise<{ path: string; commit: string }> {
  const parsed = validateRepoUrl(url, options.allowFile);
  mkdirSync(workDir, { recursive: true });
  const target = join(workDir, 'repo');
  const askPass = join(workDir, '.askpass.sh');
  const token = options.token?.trim();
  const env: NodeJS.ProcessEnv = {
    PATH: process.env.PATH,
    HOME: workDir,
    GIT_TERMINAL_PROMPT: '0',
    GIT_CONFIG_NOSYSTEM: '1',
    GIT_CONFIG_GLOBAL: '/dev/null',
    // The runtime's HTTPS-interception CA, when present, is in the system store already.
    ...(process.env.GIT_SSL_CAINFO ? { GIT_SSL_CAINFO: process.env.GIT_SSL_CAINFO } : {}),
  };
  if (token) {
    writeFileSync(askPass, '#!/bin/sh\ncase "$1" in\n*Username*) printf "%s\\n" "x-access-token" ;;\n*) printf "%s\\n" "$ASSESSOR_GIT_TOKEN" ;;\nesac\n', { mode: 0o700 });
    env.GIT_ASKPASS = askPass;
    env.ASSESSOR_GIT_TOKEN = token;
  }
  const args = [
    '-c', 'core.hooksPath=/dev/null',
    '-c', `protocol.file.allow=${parsed.protocol === 'file:' ? 'always' : 'never'}`,
    '-c', 'protocol.ext.allow=never',
    '-c', 'credential.helper=',
    '-c', 'core.symlinks=false',
    'clone', '--depth', '1', '--no-tags', '--single-branch', '--no-recurse-submodules',
    ...(options.ref ? ['--branch', options.ref] : []),
    '--', url, target,
  ];
  try {
    await run('git', args, { env, timeoutMs: options.timeoutMs ?? 180_000, signal: options.signal });
    const commit = (await run('git', ['-C', target, 'rev-parse', 'HEAD'], { env, timeoutMs: 10_000 })).trim();
    return { path: target, commit };
  } catch (error) {
    rmSync(target, { recursive: true, force: true });
    let message = error instanceof Error ? error.message : String(error);
    if (token) message = message.split(token).join('[redacted]');
    throw new RepoCloneFailed(`git clone failed: ${message.trim().slice(0, 500)}`);
  } finally {
    rmSync(askPass, { force: true });
  }
}
