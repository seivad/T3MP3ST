#!/usr/bin/env node
/**
 * The defensive build's CLI.
 *
 *   t3mp3st tools [--json]          print the capability registry (and what was removed)
 *   t3mp3st assess --repo <url> [--site <url>] [--model <id>] [--llm-base-url <url>] [--no-model] [--out <dir>]
 *                                   run one assessment in this process and write report.json/report.md
 *   t3mp3st server                  start the HTTP API (see src/server.ts)
 *
 * Results meant for scripts go to stdout; progress goes to stderr.
 */

import { randomUUID } from 'node:crypto';
import { mkdirSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { initGrammars } from './recon/ts-grammars.js';
import { Assessment, runAssessment } from './defensive/engine.js';
import { presentRemovedCapabilities, registryListing } from './defensive/registry.js';

function flag(args: string[], name: string): string | undefined {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : undefined;
}

async function tools(args: string[]): Promise<number> {
  const listing = registryListing();
  const present = presentRemovedCapabilities(listing);
  if (args.includes('--json')) {
    process.stdout.write(`${JSON.stringify({ ...listing, presentRemoved: present }, null, 2)}\n`);
  } else {
    process.stdout.write(`T3MP3ST defensive build: ${listing.tools.length} tools, ${listing.operators.length} operators\n\nTools:\n`);
    for (const t of listing.tools) process.stdout.write(`  ${t.name.padEnd(20)} ${t.riskTier.padEnd(11)} ${t.category}\n`);
    process.stdout.write('\nOperators:\n');
    for (const o of listing.operators) process.stdout.write(`  ${o.archetype.padEnd(12)} ${o.name} [${o.tools.join(', ') || 'no tools'}]\n`);
    process.stdout.write(`\nNot in this build: ${listing.removed.join(', ')}\n`);
    process.stdout.write(`Removed capabilities present in the registry: ${present.length ? present.join(', ') : 'none'}\n`);
  }
  return present.length ? 1 : 0;
}

async function assess(args: string[]): Promise<number> {
  const repo = flag(args, '--repo');
  const site = flag(args, '--site');
  if (!repo && !site) {
    process.stderr.write('assess needs --repo <https or file URL> and/or --site <url>\n');
    return 2;
  }
  await initGrammars();
  const out = resolve(flag(args, '--out') ?? 'reports');
  const run = new Assessment({
    id: randomUUID(),
    repo: repo ? { url: repo.includes('://') ? repo : `file://${resolve(repo)}`, ref: flag(args, '--ref') } : undefined,
    site: site ? { url: site, verification: 'unverified' } : undefined,
    model: flag(args, '--model') ?? '@cf/zai-org/glm-5.3',
    useModel: !args.includes('--no-model'),
  });
  let printed = 0;
  const timer = setInterval(() => {
    for (const e of run.eventsAfter(printed)) {
      process.stderr.write(`[${e.type}]${e.actor ? ` ${e.actor}:` : ''} ${e.message}\n`);
      printed = e.seq;
    }
  }, 200);
  await runAssessment(run, {
    workRoot: join(out, '.work'),
    llmBaseUrl: flag(args, '--llm-base-url') ?? process.env.T3MP3ST_LLM_BASE_URL,
    allowLocalTargets: process.env.T3MP3ST_ALLOW_LOCAL_TARGETS === '1',
    allowLocalRepos: true,
  });
  clearInterval(timer);
  for (const e of run.eventsAfter(printed)) process.stderr.write(`[${e.type}]${e.actor ? ` ${e.actor}:` : ''} ${e.message}\n`);
  if (!run.report || !run.markdown) {
    process.stderr.write(`assessment ${run.status}: ${run.error ?? ''}\n`);
    return 1;
  }
  mkdirSync(out, { recursive: true });
  writeFileSync(join(out, 'report.json'), JSON.stringify(run.report, null, 2));
  writeFileSync(join(out, 'report.md'), run.markdown);
  process.stdout.write(`${JSON.stringify({ report: join(out, 'report.md'), counts: run.report.summary.counts })}\n`);
  return 0;
}

async function cli(): Promise<number> {
  const [command, ...args] = process.argv.slice(2);
  if (command === 'tools') return tools(args);
  if (command === 'assess') return assess(args);
  if (command === 'server') {
    const { main } = await import('./server.js');
    await main();
    return new Promise<number>(() => undefined);
  }
  process.stderr.write('usage: t3mp3st tools [--json] | assess --repo <url> [--site <url>] | server\n');
  return command ? 2 : 0;
}

cli().then((code) => {
  if (code !== undefined) process.exitCode = code;
});
