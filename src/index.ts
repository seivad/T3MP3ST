/**
 * T3MP3ST, defensive profile.
 *
 * A defensive build of T3MP3ST (https://github.com/elder-plinius/T3MP3ST, AGPL-3.0) for assessing
 * systems you own: white-box code analysis (SAST-style rules, secrets, dependency audit, IaC
 * review) and passive posture checks of your sites, triaged by T3MP3ST operators and reported
 * with remediation and retest criteria. See DEFENSIVE.md for what this build removes and why.
 *
 * @example
 * ```typescript
 * import { Assessment, runAssessment } from 't3mp3st';
 *
 * const run = new Assessment({ id: crypto.randomUUID(), repo: { url: 'https://github.com/you/app' }, model: '@cf/zai-org/glm-5.3' });
 * await runAssessment(run, { workRoot: '/tmp/work', llmBaseUrl: 'http://localhost:8787/v1' });
 * console.log(run.markdown);
 * ```
 */

export * from './types/index.js';
export { config, getApiKey, setApiKey, hasApiKey, getLLMConfig, getConfiguredProviders, AVAILABLE_MODELS } from './config/index.js';
export { LLMBackbone, createLocalBackbone, createMockBackbone } from './llm/index.js';
export { Arsenal, BUILTIN_TOOLS, PASSIVE_CHECKS, UTILITY_TOOLS, scopeViolation, hostFromTargetValue } from './arsenal/index.js';
export type { ArsenalScope } from './arsenal/index.js';
export { createRepoTools, REPO_TOOL_NAMES } from './arsenal/repo-tools.js';
export { AgentLoop, createAgentLoop } from './agent/index.js';
export { OperatorAgent, createOperator, ARCHETYPE_PROFILES } from './operators/index.js';
export { resolveSystemPrompt, DEFENSIVE_DOCTRINE } from './prompts/index.js';
export { EvidenceVault } from './evidence/index.js';
export { gateLiveFinding } from './evidence/gate.js';
export { ingestRepoToSourceContext } from './recon/whitebox.js';
export { Assessment, runAssessment, ENGINE_VERSION, mergeTriage, parseDebrief } from './defensive/engine.js';
export { buildReport, renderMarkdown } from './defensive/report.js';
export { controlsFor, hardenPlan, CONTROLS } from './defensive/cloudflare.js';
export { registryListing, presentRemovedCapabilities, REMOVED_CAPABILITIES } from './defensive/registry.js';
export type * from './defensive/types.js';
