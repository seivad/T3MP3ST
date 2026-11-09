/**
 * The defensive build's HTTP API. It replaces the upstream War Room server (and its generic tool
 * execution, local-agent dispatch, bounty submission and operator-spawn routes).
 *
 * Inside the Cloudflare OS sandbox this listens on 0.0.0.0:3333 because the Durable Object reaches
 * it through the container's own interface (getTcpPort); the container has no public port, so
 * nothing outside the Worker can connect. Every request must also carry the per-container bearer
 * token the Durable Object generated at start (ASSESSOR_API_TOKEN), so even a process inside the
 * container cannot drive it without that token.
 *
 *   GET  /api/health
 *   GET  /api/tools                        the capability registry
 *   POST /api/assessments                  start a run (one at a time)
 *   GET  /api/assessments/:id              state
 *   GET  /api/assessments/:id/events?after=N
 *   GET  /api/assessments/:id/report       { report, markdown } once complete
 *   POST /api/assessments/:id/cancel
 */

import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { timingSafeEqual } from 'node:crypto';
import { initGrammars } from './recon/ts-grammars.js';
import { Assessment, ENGINE_VERSION, runAssessment } from './defensive/engine.js';
import { registryListing } from './defensive/registry.js';
import type { AssessmentRequest } from './defensive/types.js';

const MAX_BODY = 64 * 1024;
const KEEP_RUNS = 20;
const MODEL_ID = /^@cf\/[\w.-]+\/[\w.-]+$|^[\w.-]+(?:\/[\w.:-]+)*$/;

export interface ServerConfig {
  token: string;
  workRoot: string;
  llmBaseUrl?: string;
  allowLocalTargets: boolean;
  allowLocalRepos: boolean;
  timeoutMs?: number;
}

function send(res: ServerResponse, status: number, body: unknown): void {
  const text = JSON.stringify(body);
  res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', 'content-length': Buffer.byteLength(text) });
  res.end(text);
}

function authorized(req: IncomingMessage, token: string): boolean {
  const header = req.headers.authorization ?? '';
  const presented = Buffer.from(header.startsWith('Bearer ') ? header.slice(7) : '');
  const expected = Buffer.from(token);
  return presented.length === expected.length && timingSafeEqual(presented, expected);
}

async function readJson(req: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    size += (chunk as Buffer).length;
    if (size > MAX_BODY) throw new Error('request body too large');
    chunks.push(chunk as Buffer);
  }
  return JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}');
}

/** Validates a start request. Returns the request or an error message. */
export function parseAssessmentRequest(body: unknown, config: Pick<ServerConfig, 'allowLocalRepos'>): AssessmentRequest | string {
  if (!body || typeof body !== 'object') return 'body must be a JSON object';
  const b = body as Record<string, unknown>;
  const id = typeof b.id === 'string' && /^[a-zA-Z0-9-]{8,64}$/.test(b.id) ? b.id : null;
  if (!id) return 'id must be 8-64 letters, digits or dashes';
  const model = typeof b.model === 'string' && MODEL_ID.test(b.model) ? b.model : null;
  if (!model) return 'model is required';
  let repo: AssessmentRequest['repo'];
  if (b.repo !== undefined && b.repo !== null) {
    const r = b.repo as Record<string, unknown>;
    if (typeof r.url !== 'string') return 'repo.url must be a string';
    const scheme = r.url.split(':')[0];
    if (scheme !== 'https' && !(config.allowLocalRepos && scheme === 'file')) return 'repo.url must be an https:// git URL';
    repo = {
      url: r.url,
      token: typeof r.token === 'string' && r.token ? r.token : undefined,
      ref: typeof r.ref === 'string' && /^[\w./-]{1,200}$/.test(r.ref) ? r.ref : undefined,
    };
  }
  let site: AssessmentRequest['site'];
  if (b.site !== undefined && b.site !== null) {
    const s = b.site as Record<string, unknown>;
    if (typeof s.url !== 'string') return 'site.url must be a string';
    try {
      const u = new URL(s.url);
      if (u.protocol !== 'https:' && u.protocol !== 'http:') return 'site.url must be http(s)';
      if (u.username || u.password) return 'site.url must not embed credentials';
    } catch {
      return 'site.url is not a URL';
    }
    const verification = s.verification === 'zone' || s.verification === 'txt' ? s.verification : 'unverified';
    site = { url: s.url, verification };
  }
  if (!repo && !site) return 'give a repository, a site, or both';
  return { id, repo, site, model, useModel: b.useModel !== false };
}

export function createAssessorServer(config: ServerConfig) {
  if (!config.token || config.token.length < 32) throw new Error('ASSESSOR_API_TOKEN must be set (32+ characters)');
  const runs = new Map<string, Assessment>();
  let active: Assessment | null = null;

  return createServer(async (req, res) => {
    try {
      if (!authorized(req, config.token)) return send(res, 401, { error: 'unauthorized' });
      const url = new URL(req.url ?? '/', 'http://assessor');
      const path = url.pathname;

      if (req.method === 'GET' && path === '/api/health') {
        return send(res, 200, { ok: true, version: ENGINE_VERSION, busy: active?.status === 'running' });
      }
      if (req.method === 'GET' && path === '/api/tools') return send(res, 200, registryListing());

      if (req.method === 'POST' && path === '/api/assessments') {
        if (active && (active.status === 'running' || active.status === 'queued')) {
          return send(res, 409, { error: 'an assessment is already running in this sandbox', id: active.request.id });
        }
        const parsed = parseAssessmentRequest(await readJson(req), config);
        if (typeof parsed === 'string') return send(res, 400, { error: parsed });
        if (runs.has(parsed.id)) return send(res, 409, { error: 'id already used' });
        const run = new Assessment(parsed);
        runs.set(parsed.id, run);
        while (runs.size > KEEP_RUNS) runs.delete(runs.keys().next().value as string);
        active = run;
        void runAssessment(run, {
          workRoot: config.workRoot,
          llmBaseUrl: config.llmBaseUrl,
          allowLocalTargets: config.allowLocalTargets,
          allowLocalRepos: config.allowLocalRepos,
          timeoutMs: config.timeoutMs,
        });
        return send(res, 202, run.snapshot());
      }

      const match = /^\/api\/assessments\/([a-zA-Z0-9-]{8,64})(\/events|\/report|\/cancel)?$/.exec(path);
      if (match) {
        const run = runs.get(match[1]);
        if (!run) return send(res, 404, { error: 'unknown assessment' });
        const sub = match[2] ?? '';
        if (req.method === 'GET' && sub === '') return send(res, 200, run.snapshot());
        if (req.method === 'GET' && sub === '/events') {
          const after = Number(url.searchParams.get('after') ?? 0) || 0;
          return send(res, 200, { status: run.status, phase: run.phase, events: run.eventsAfter(after).slice(0, 500), lastSeq: run.snapshot().lastSeq });
        }
        if (req.method === 'GET' && sub === '/report') {
          if (!run.report) return send(res, 404, { error: `no report (status ${run.status})` });
          return send(res, 200, { report: run.report, markdown: run.markdown });
        }
        if (req.method === 'POST' && sub === '/cancel') {
          run.abort.abort(new Error('cancelled by the operator'));
          return send(res, 202, run.snapshot());
        }
      }
      return send(res, 404, { error: 'not found' });
    } catch (error) {
      return send(res, 400, { error: error instanceof Error ? error.message : 'bad request' });
    }
  });
}

/** Starts the API from the environment (the container's entrypoint). */
export async function main(): Promise<void> {
  await initGrammars();
  const config: ServerConfig = {
    token: process.env.ASSESSOR_API_TOKEN ?? '',
    workRoot: process.env.T3MP3ST_WORK_ROOT ?? '/tmp/t3mp3st-work',
    llmBaseUrl: process.env.T3MP3ST_LLM_BASE_URL || undefined,
    allowLocalTargets: process.env.T3MP3ST_ALLOW_LOCAL_TARGETS === '1',
    allowLocalRepos: process.env.T3MP3ST_ALLOW_LOCAL_REPOS === '1',
    timeoutMs: Number(process.env.T3MP3ST_ASSESSMENT_TIMEOUT_MS) || undefined,
  };
  const server = createAssessorServer(config);
  const host = process.env.T3MP3ST_HOST ?? '0.0.0.0';
  const port = Number(process.env.T3MP3ST_PORT ?? 3333);
  server.listen(port, host, () => {
    process.stderr.write(`[t3mp3st] defensive API ${ENGINE_VERSION} listening on ${host}:${port}\n`);
  });
}

if (process.argv[1] && /server\.(js|ts)$/.test(process.argv[1])) {
  void main();
}
