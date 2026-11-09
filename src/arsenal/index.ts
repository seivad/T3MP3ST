/**
 * T3MP3ST Arsenal
 *
 * Tool registry and execution management.
 */

import { EventEmitter } from 'eventemitter3';
import { randomUUID } from 'crypto';
import { promisify } from 'util';
import * as net from 'net';
import * as dns from 'dns';
import * as tls from 'tls';
import { ApprovalController, isGatedRisk, type ApprovalRequest } from './approval.js';
import { bridgeDns, bridgeRdap, bridgeTlsProbe, netBridgeUrl, type TlsProbeResult } from './net-bridge.js';

import type {
  CustomTool,
  ToolContext,
  ToolResult,
  Target,
  LLMToolDefinition,
  RiskTier,
} from '../types/index.js';
import { ToolError, ToolErrorCategory } from '../types/index.js';
import { validateToolArgs, buildJsonSchema, assertSchemaDepth } from '../validation/index.js';

const dnsResolve = promisify(dns.resolve);
const dnsResolve4 = promisify(dns.resolve4);
const dnsResolveMx = promisify(dns.resolveMx);
const dnsResolveTxt = promisify(dns.resolveTxt);
const dnsResolveNs = promisify(dns.resolveNs);

import { CVE_DATABASE } from '../threat-intel/cve-db.js';
import type { CVEEntry } from '../threat-intel/cve-db.js';

// =============================================================================
// TARGET HEADER INJECTION
// =============================================================================

interface TargetHeaderConfig {
  origin: string;
  headers: Headers;
}

const FORBIDDEN_TARGET_HEADERS = new Set([
  'connection', 'content-length', 'host', 'proxy-authenticate', 'proxy-authorization',
  'te', 'trailer', 'transfer-encoding', 'upgrade',
]);

/** Parse an exact-origin binding and its default headers. Invalid configuration fails closed. */
function parseTargetHeaderConfig(): TargetHeaderConfig | null {
  const rawOrigin = process.env.TEMPEST_TARGET_ORIGIN?.trim();
  const rawHeaders = process.env.TEMPEST_TARGET_HEADERS?.trim();
  if (!rawOrigin || !rawHeaders) return null;

  try {
    const target = new URL(rawOrigin);
    if (!['http:', 'https:'].includes(target.protocol)
      || target.username || target.password
      || target.pathname !== '/' || target.search || target.hash) {
      return null;
    }

    const parsed: unknown = JSON.parse(rawHeaders);
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return null;

    const headers = new Headers();
    for (const [name, value] of Object.entries(parsed)) {
      if (typeof value !== 'string' || FORBIDDEN_TARGET_HEADERS.has(name.toLowerCase())) return null;
      headers.set(name, value);
    }
    return headers.keys().next().done ? null : { origin: target.origin, headers };
  } catch {
    return null;
  }
}

function targetHeadersForUrl(url: string | URL, explicit?: RequestInit['headers']): Headers | undefined {
  const merged = new Headers();
  const config = parseTargetHeaderConfig();
  try {
    if (config && new URL(url).origin === config.origin) {
      config.headers.forEach((value, name) => merged.set(name, value));
    }
  } catch {
    // Let fetch or curl report malformed URLs; they simply receive no configured secrets.
  }
  new Headers(explicit).forEach((value, name) => merged.set(name, value));
  return merged.keys().next().done ? undefined : merged;
}

function redactConfiguredSecrets(result: ToolResult): ToolResult {
  const config = parseTargetHeaderConfig();
  const secrets = config ? [...config.headers.values()].filter(Boolean) : [];
  if (secrets.length === 0) return result;

  const redact = (value: unknown): unknown => {
    if (typeof value === 'string') {
      return secrets.reduce((text, secret) => text.split(secret).join('[REDACTED]'), value);
    }
    if (Array.isArray(value)) return value.map(redact);
    if (value && typeof value === 'object') {
      return Object.fromEntries(Object.entries(value).map(([key, nested]) => [key, redact(nested)]));
    }
    return value;
  };
  return redact(result) as ToolResult;
}

const REDIRECT_STATUS = new Set([301, 302, 303, 307, 308]);
const CROSS_ORIGIN_CREDENTIAL_HEADERS = ['authorization', 'cookie', 'cookie2', 'proxy-authorization'];

/** Apply exact-origin headers to every built-in fetch without leaking them across redirects. */
async function targetFetch(url: string | URL, init: RequestInit = {}): Promise<Response> {
  const config = parseTargetHeaderConfig();
  let currentUrl = new URL(url);
  if (!config || currentUrl.origin !== config.origin) return globalThis.fetch(url, init);

  const explicitHeaders = new Headers(init.headers);
  let method = (init.method || 'GET').toUpperCase();
  let body = init.body;

  for (let redirects = 0; redirects <= 20; redirects++) {
    const headers = targetHeadersForUrl(currentUrl, explicitHeaders);
    const response = await globalThis.fetch(currentUrl, { ...init, method, body, headers, redirect: 'manual' });
    const location = response.headers.get('location');
    if (!REDIRECT_STATUS.has(response.status) || !location) return response;
    if (redirects === 20) throw new Error('Target request exceeded 20 redirects');

    const nextUrl = new URL(location, currentUrl);
    if (nextUrl.origin !== currentUrl.origin) {
      config.headers.forEach((_value, name) => explicitHeaders.delete(name));
      CROSS_ORIGIN_CREDENTIAL_HEADERS.forEach(name => explicitHeaders.delete(name));
    }
    if (response.status === 303 || ((response.status === 301 || response.status === 302) && method === 'POST')) {
      method = 'GET';
      body = undefined;
      ['content-encoding', 'content-language', 'content-location', 'content-type'].forEach(name => explicitHeaders.delete(name));
    }
    currentUrl = nextUrl;
  }
  throw new Error('Target request redirect handling failed');
}

// =============================================================================
// EVENTS
// =============================================================================

export interface ArsenalEvents {
  'tool:registered': CustomTool;
  'tool:executed': { tool: CustomTool; result: ToolResult; durationMs: number };
  'tool:error': { tool: CustomTool; error: Error };
}

export interface ToolExecution {
  id: string;
  toolName: string;
  startedAt: number;
  completedAt?: number;
  result?: ToolResult;
  error?: string;
}

// =============================================================================
// ARSENAL
// =============================================================================

// ── Egress scope gate (Phase-0 pack-hunt safety primitive) ──────────────────────────────────
// A HARD allowlist enforced inside Arsenal.execute() BEFORE any handler runs, so an LLM-supplied
// tool target can never reach an out-of-scope host. When no scope is set (library/test mode)
// enforcement is off; the server/mission sets it from the authorized targets so live runs are gated.
// This closes the "a keyless pack operator fires nuclei/nmap/sqlmap at an off-target host" hole:
// the only prior scope check was at the HTTP boundary, keyed to the mission target — the per-tool
// target the model actually supplies was never checked.
export interface ArsenalScope {
  /** exact hosts / registrable domains explicitly authorized (subdomains allowed) */
  allowedHosts: string[];
  /** allow 127.0.0.0/8, localhost, ::1 */
  allowLoopback: boolean;
  /** allow RFC-1918 / link-local / ULA lab ranges */
  allowPrivate: boolean;
}

/** The parameter keys a networked tool reads its target from (dns/web/vuln handlers). */
const SCOPE_TARGET_KEYS = ['url', 'target', 'host', 'hostname', 'domain', 'address', 'ip', 'endpoint', 'base_url', 'rhosts', 'rhost'];

/** Normalize a target-ish value to a bare lowercase host (strip scheme/user/port/path). null if not host-like. */
export function hostFromTargetValue(v: unknown): string | null {
  if (typeof v !== 'string' || !v.trim()) return null;
  let s = v.trim();
  try { if (/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) s = new URL(s).hostname; } catch { /* treat as bare host */ }
  s = s.replace(/^[^@/]*@/, '').replace(/\/.*$/, '').replace(/:\d+$/, '').replace(/^\[|\]$/g, '');
  return s.toLowerCase() || null;
}

function isLoopbackTargetHost(h: string): boolean {
  return h === 'localhost' || h === '::1' || /^127(?:\.\d{1,3}){3}$/.test(h);
}
function isPrivateTargetHost(h: string): boolean {
  return /^10(?:\.\d{1,3}){3}$/.test(h)
    || /^192\.168(?:\.\d{1,3}){2}$/.test(h)
    || /^172\.(1[6-9]|2\d|3[01])(?:\.\d{1,3}){2}$/.test(h)
    || /^169\.254(?:\.\d{1,3}){2}$/.test(h)          // link-local
    || /^(fc|fd)[0-9a-f]{2}:/i.test(h);              // IPv6 ULA
}

/** The narrowest CIDR prefix that keeps a private/loopback host's whole block in scope — a wider
 *  (smaller-number) mask would spill outside it. Used to scope-validate a CIDR TARGET's range. */
function privateBlockMinMask(h: string): number {
  if (/^192\.168\./.test(h) || /^169\.254\./.test(h)) return 16;
  if (/^172\.(1[6-9]|2\d|3[01])\./.test(h)) return 12;
  return 8; // 10/8, 127/8, and (conservatively) IPv6 ULA
}

/** null = in scope (or no host to check); otherwise the out-of-scope host/range that must be blocked. */
export function scopeViolation(scope: ArsenalScope | null, context: ToolContext): string | null {
  if (!scope) return null; // enforcement off until configured
  // FAIL CLOSED on a value that LOOKS like a network target (scheme-relative "//host" or a
  // "scheme://…") but yields no parseable host — that's the bypass ("//evil.com" /
  // "file:///etc/passwd" host-normalize to an empty string and would otherwise slip past the gate).
  // A plain local path ("/code/src") is NOT a network target and has no host, so it's skipped — local
  // file-analysis tools (semgrep/trivy/slither) keep working. (adversarial-review C1)
  const bypassLooking = (v: string): boolean => v.startsWith('//') || v.includes('://');
  const candidates: Array<{ h: string; v: string }> = [];
  const raws: unknown[] = [context.target?.address, ...SCOPE_TARGET_KEYS.map((k) => (context.parameters || {})[k])];
  for (const raw of raws) {
    if (typeof raw !== 'string' || !raw.trim()) continue;
    const v = raw.trim();
    const h = hostFromTargetValue(v);
    if (!h) {
      if (bypassLooking(v)) return v; // network-target-shaped but unparseable → block
      continue; // plain path / non-network value → not a scope target
    }
    candidates.push({ h, v });
  }
  const allow = scope.allowedHosts.map(a => a.toLowerCase());
  for (const { h, v } of candidates) {
    // How is the BASE host admitted — and what CIDR prefix keeps the WHOLE range inside that block?
    // hostFromTargetValue strips the mask, so "10.0.0.0/0" (base 10.0.0.0 private) would otherwise
    // sweep the entire internet past a scope authorizing only that base. Validate the range, not the
    // base. (adversarial-review CIDR mask-strip escape)
    let minMask: number;
    if (scope.allowLoopback && isLoopbackTargetHost(h)) minMask = 8;              // 127/8, ::1
    else if (scope.allowPrivate && isPrivateTargetHost(h)) minMask = privateBlockMinMask(h);
    else if (allow.some(a => a === h || h.endsWith('.' + a))) minMask = 32;        // exact-allowed host → only /32
    else return h; // base host out of scope
    // treat a trailing "/N" as a CIDR mask ONLY on a bare host/ip (no scheme) — not a URL path segment.
    const cidr = !v.includes('://') && v.match(/^[^/]+\/(\d{1,3})$/);
    if (cidr && parseInt(cidr[1], 10) < minMask) return v; // CIDR range extends beyond the authorized block
  }
  return null;
}

/** Best-effort target for an approval request/warning — the first target-like param, else the
 *  context target address. Informational only (the scope gate does the real host math). */
function approvalTargetOf(context: ToolContext): string | undefined {
  const params = context.parameters || {};
  for (const k of SCOPE_TARGET_KEYS) {
    const v = params[k];
    if (typeof v === 'string' && v.trim()) return v.trim();
  }
  return context.target?.address;
}

/** A one-line human-readable summary of a tool call — tool + a few scalar params + target — for the
 *  approval warning and the audit trail. Object/array params are omitted to keep it short + safe. */
function describeToolAction(toolName: string, context: ToolContext): string {
  const summary = Object.entries(context.parameters || {})
    .filter(([, v]) => v !== undefined && v !== null && typeof v !== 'object')
    .slice(0, 4)
    .map(([k, v]) => `${k}=${String(v).slice(0, 48)}`)
    .join(' ');
  const target = approvalTargetOf(context);
  return `${toolName}${summary ? ` (${summary})` : ''}${target ? ` → ${target}` : ''}`;
}

export class Arsenal extends EventEmitter<ArsenalEvents> {
  private tools: Map<string, CustomTool> = new Map();
  /** Authorized egress scope; null = enforcement off (set by the server/mission for live runs). */
  private scope: ArsenalScope | null = null;
  /** Capability approval gate; null = gating off (backward-compat). The engine wires one for live runs. */
  private approval: ApprovalController | null = null;
  private executions: ToolExecution[] = [];

  /**
   * Register a tool
   */
  register(tool: CustomTool): void {
    assertSchemaDepth(tool.parameters ?? []);
    this.tools.set(tool.name, tool);
    this.emit('tool:registered', tool);
  }

  /**
   * Register multiple tools
   */
  registerMany(tools: CustomTool[]): void {
    for (const tool of tools) {
      this.register(tool);
    }
  }

  /**
   * Get a tool by name
   */
  getTool(name: string): CustomTool | undefined {
    return this.tools.get(name);
  }

  /**
   * Get all tools
   */
  getAllTools(): CustomTool[] {
    return Array.from(this.tools.values());
  }

  /**
   * Get tools by category
   */
  getToolsByCategory(category: string): CustomTool[] {
    return this.getAllTools().filter(t => t.category === category);
  }

  /** Set (or clear with null) the authorized egress scope enforced in execute(). */
  setScope(scope: ArsenalScope | null): void { this.scope = scope; }
  getScope(): ArsenalScope | null { return this.scope; }

  /** Set (or clear) the capability-approval gate enforced in execute() for intrusive/dangerous tools. */
  setApprovalController(approval: ApprovalController | null): void { this.approval = approval; }
  getApprovalController(): ApprovalController | null { return this.approval; }

  /**
   * Execute a tool
   */
  async execute(
    toolName: string,
    context: ToolContext
  ): Promise<ToolResult> {
    const tool = this.tools.get(toolName);
    if (!tool) {
      const err = new ToolError(
        ToolErrorCategory.ToolNotFound,
        `Tool "${toolName}" not found`,
        toolName,
      );
      this.emit('tool:error', { tool: { name: toolName } as CustomTool, error: err });
      throw err;
    }

    // Egress scope gate: deny out-of-scope network targets BEFORE the handler runs. A tool call
    // never reaches a host outside the authorized scope, regardless of what the model supplied.
    const blockedHost = scopeViolation(this.scope, context);
    if (blockedHost) {
      const denied: ToolResult = {
        success: false,
        error: `SCOPE DENIED: target '${blockedHost}' is not in the authorized scope — ${toolName} refused before execution. Only authorized / loopback / lab targets are permitted.`,
      };
      this.emit('tool:error', { tool, error: new ToolError(ToolErrorCategory.ScopeDenied, denied.error!, toolName) });
      return denied;
    }

    // Capability approval + spicy-action warning gate: an intrusive/credential/dangerous tool is inert
    // until it has been approved (interactively "approve once, then free", or via the headless
    // pre-authorization allowlist); the hottest actions also fire a loud, audited, non-blocking
    // warning. Safe/active tools pass straight through. No controller wired = gating off (backward-compat).
    if (this.approval && isGatedRisk(tool.riskTier)) {
      const request: ApprovalRequest = {
        tool: toolName,
        risk: tool.riskTier!,
        operator: context.operator,
        target: approvalTargetOf(context),
        action: describeToolAction(toolName, context),
      };
      const decision = await this.approval.gate(request);
      if (!decision.allowed) {
        const denied: ToolResult = { success: false, error: `APPROVAL REQUIRED: ${decision.reason}` };
        this.emit('tool:error', { tool, error: new ToolError(ToolErrorCategory.ScopeDenied, denied.error!, toolName) });
        return denied;
      }
    }

    // Validation gate: validate args against tool's parameter schema before handler runs.
    if (tool.parameters && tool.parameters.length > 0) {
      const validationErrors = validateToolArgs(toolName, context.parameters, tool.parameters);
      if (validationErrors.length > 0) {
        const fieldErrors = validationErrors.map(e => `${e.field}: ${e.message} (expected ${e.expected})`).join('; ');
        const err = new ToolError(
          ToolErrorCategory.ValidationError,
          `Validation failed for "${toolName}": ${fieldErrors}`,
          toolName,
        );
        this.emit('tool:error', { tool, error: err });
        throw err;
      }
    }

    const execution: ToolExecution = {
      id: randomUUID(),
      toolName,
      startedAt: Date.now(),
    };
    this.executions.push(execution);

    const startTime = Date.now();

    try {
      const result = redactConfiguredSecrets(await tool.handler(context));
      const durationMs = Date.now() - startTime;

      execution.completedAt = Date.now();
      execution.result = result;

      this.emit('tool:executed', { tool, result, durationMs });

      return result;
    } catch (error) {
      execution.completedAt = Date.now();
      execution.error = redactConfiguredSecrets({
        success: false,
        error: error instanceof Error ? error.message : String(error),
      }).error;

      // If already a ToolError, re-throw as-is; otherwise wrap as ExecutionError
      if (error instanceof ToolError) {
        this.emit('tool:error', { tool, error });
        throw error;
      }

      const wrappedErr = new ToolError(
        ToolErrorCategory.ExecutionError,
        `Tool "${toolName}" execution failed: ${execution.error}`,
        toolName,
      );
      this.emit('tool:error', { tool, error: wrappedErr });
      throw wrappedErr;
    }
  }

  /**
   * Get execution history
   */
  getExecutions(): ToolExecution[] {
    return [...this.executions];
  }

  /**
   * Get tool categories
   */
  getCategories(): string[] {
    const categories = new Set<string>();
    for (const tool of this.tools.values()) {
      categories.add(tool.category);
    }
    return Array.from(categories);
  }

  /**
   * Convert registered tools to LLM tool definitions for function calling
   */
  getToolDefinitions(categories?: string[], names?: string[]): LLMToolDefinition[] {
    let tools = this.getAllTools();
    // A per-operator NAME allowlist (the archetype's role toolkit) is the precise gate and
    // takes precedence over the coarse category filter; fall back to categories, then to all.
    if (names?.length) {
      tools = tools.filter(t => names.includes(t.name));
    } else if (categories?.length) {
      tools = tools.filter(t => categories.includes(t.category));
    }
    return tools.map(tool => {
      // Use buildJsonSchema() for richer schema generation (enum, items, nested properties)
      const schema = (tool.parameters && tool.parameters.length > 0)
        ? buildJsonSchema(tool.parameters)
        : { type: 'object' as const, properties: {} };

      return {
        name: tool.name,
        description: tool.description,
        parameters: schema as LLMToolDefinition['parameters'],
      };
    });
  }

  /**
   * Unregister a tool
   */
  unregister(name: string): boolean {
    return this.tools.delete(name);
  }

  /**
   * Clear all tools
   */
  clear(): void {
    this.tools.clear();
    this.executions = [];
  }
}

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

export function successResult(output: string, findings?: ToolResult['findings']): ToolResult {
  return {
    success: true,
    output,
    findings,
  };
}

export function failResult(error: string): ToolResult {
  return {
    success: false,
    error,
  };
}

export function createToolContext(
  target?: Target,
  parameters?: Record<string, unknown>
): ToolContext {
  return {
    target,
    parameters: parameters || {},
  };
}

// =============================================================================
// BUILT-IN TOOLS
// =============================================================================

/** Renders the Worker's TLS posture check as an ssl_scan result. */
export function tlsProbeToResult(probe: TlsProbeResult): ToolResult {
  const info: string[] = [];
  const issues: string[] = [];
  info.push(`Edge: ${probe.edge === 'cloudflare' ? 'Cloudflare (TLS terminates at the Cloudflare edge)' : probe.edge}`);
  info.push(`HTTPS: ${probe.httpsOk ? 'trusted certificate' : 'failed'}`);
  if (!probe.httpsOk) issues.push('CRITICAL: HTTPS did not answer with a trusted certificate');
  info.push(`HTTP to HTTPS redirect: ${probe.httpRedirectsToHttps === null ? 'HTTP not served' : probe.httpRedirectsToHttps ? 'yes' : 'no'}`);
  if (probe.httpRedirectsToHttps === false) issues.push('Plain HTTP is served without redirecting to HTTPS');
  info.push(`HSTS: ${probe.hsts ?? 'missing'}`);
  if (!probe.hsts) {
    issues.push('Strict-Transport-Security header missing');
  } else {
    const maxAge = Number(/max-age=(\d+)/i.exec(probe.hsts)?.[1] ?? 0);
    if (maxAge < 15_552_000) issues.push(`HSTS max-age ${maxAge}s is below six months`);
  }
  const cert = probe.certificate;
  if (cert) {
    info.push(`Certificate issuer: ${cert.issuer ?? 'unknown'}`, `Valid to: ${cert.notAfter ?? 'unknown'}`);
    if (cert.san?.length) info.push(`Names: ${cert.san.slice(0, 10).join(', ')}`);
    if (cert.notAfter) {
      const days = Math.floor((new Date(cert.notAfter).getTime() - Date.now()) / 86_400_000);
      if (days < 0) issues.push('CRITICAL: the latest logged certificate has expired');
      else if (days < 21) issues.push(`Certificate expires in ${days} days`);
    }
  }
  info.push(...probe.notes);
  return {
    success: true,
    output: `TLS posture of ${probe.host}:${probe.port}:\n${info.map((i) => `  ${i}`).join('\n')}\n\n` +
      (issues.length ? `Issues:\n${issues.map((i) => `  ${i}`).join('\n')}` : 'No TLS issues found'),
    findings: issues.length ? [{
      title: 'SSL/TLS Configuration Issues',
      severity: issues.some((i) => i.startsWith('CRITICAL')) ? 'critical' : 'medium',
      details: issues.join('; '),
    }] : undefined,
  };
}

/**
 * Passive posture checks: DNS and registration lookups (answered by resolvers and registries, not
 * the target), and plain GET/HEAD requests for a site's public pages, the same requests any
 * visitor's browser makes. This build has no active checks: no port scans, path enumeration,
 * injection probes, exploitation or credential testing.
 */
export const PASSIVE_CHECKS: readonly string[] = [
  'dns_lookup', 'whois_lookup', 'header_analysis', 'technology_detect', 'ssl_scan', 'robots_txt_fetch',
  'csp_analysis', 'cors_check', 'cookie_analysis', 'clickjacking_test',
];

/** Offline helpers: decoders and the local CVE catalogue. They send nothing to a target. */
export const UTILITY_TOOLS: readonly string[] = ['cve_lookup', 'jwt_decode', 'base64_decode', 'url_encode'];

function defensiveTier(name: string): RiskTier {
  return PASSIVE_CHECKS.includes(name) ? 'passive' : 'local_read';
}

const BUILTIN_TOOL_DEFINITIONS: CustomTool[] = [
  // =============================================================================
  // RECONNAISSANCE TOOLS
  // =============================================================================
  {
    name: 'dns_lookup',
    description: 'Perform DNS lookup for a target',
    category: 'recon',
    parameters: [
      { name: 'domain', type: 'string', description: 'Domain to lookup', required: true },
      { name: 'type', type: 'string', description: 'Record type (A, AAAA, MX, TXT, NS)', required: false, default: 'A' },
    ],
    handler: async (context) => {
      const domain = context.parameters.domain as string;
      const recordType = (context.parameters.type as string || 'A').toUpperCase();

      try {
        let records: string[] = [];

        if (netBridgeUrl()) {
          records = await bridgeDns(domain, recordType);
          return { success: true, output: `DNS ${recordType} lookup for ${domain}:\n${records.join('\n') || '(no records)'}` };
        }

        switch (recordType) {
          case 'A':
            records = await dnsResolve4(domain);
            break;
          case 'MX': {
            const mxRecords = await dnsResolveMx(domain);
            records = mxRecords.map(r => `${r.priority} ${r.exchange}`);
            break;
          }
          case 'TXT': {
            const txtRecords = await dnsResolveTxt(domain);
            records = txtRecords.map(r => r.join(''));
            break;
          }
          case 'NS':
            records = await dnsResolveNs(domain);
            break;
          default: {
            // dns.resolve returns an array for most rrtypes, but a single object
            // for SOA (and other structured types) — normalize before joining.
            const raw = await dnsResolve(domain, recordType);
            records = Array.isArray(raw) ? (raw as unknown as string[]) : [JSON.stringify(raw)];
          }
        }

        return {
          success: true,
          output: `DNS ${recordType} lookup for ${domain}:\n${records.join('\n')}`,
        };
      } catch (error) {
        return {
          success: false,
          error: `DNS lookup failed: ${error instanceof Error ? error.message : String(error)}`,
        };
      }
    },
  },
  {
    name: 'whois_lookup',
    description: 'Perform WHOIS lookup for a domain (real WHOIS query)',
    category: 'recon',
    parameters: [
      { name: 'domain', type: 'string', description: 'Domain to lookup', required: true },
    ],
    handler: async (context) => {
      const domain = context.parameters.domain as string;

      if (netBridgeUrl()) {
        try {
          const { lines } = await bridgeRdap(domain);
          return { success: true, output: `Registration data for ${domain} (RDAP):\n\n${lines.join('\n')}` };
        } catch (error) {
          return { success: false, error: `RDAP lookup failed: ${error instanceof Error ? error.message : String(error)}` };
        }
      }

      // Determine WHOIS server based on TLD
      const tld = domain.split('.').pop()?.toLowerCase() || '';
      const whoisServers: Record<string, string> = {
        'com': 'whois.verisign-grs.com',
        'net': 'whois.verisign-grs.com',
        'org': 'whois.pir.org',
        'io': 'whois.nic.io',
        'co': 'whois.nic.co',
        'info': 'whois.afilias.net',
        'biz': 'whois.biz',
        'me': 'whois.nic.me',
        'dev': 'whois.nic.google',
        'app': 'whois.nic.google',
        'uk': 'whois.nic.uk',
        'de': 'whois.denic.de',
        'fr': 'whois.nic.fr',
        'eu': 'whois.eu',
        'nl': 'whois.domain-registry.nl',
        'au': 'whois.auda.org.au',
      };

      const whoisServer = whoisServers[tld] || `whois.nic.${tld}`;

      return new Promise((resolve) => {
        const socket = new net.Socket();
        let data = '';

        socket.setTimeout(10000);

        socket.on('connect', () => {
          socket.write(`${domain}\r\n`);
        });

        socket.on('data', (chunk) => {
          data += chunk.toString();
        });

        socket.on('close', () => {
          if (data.length === 0) {
            resolve({
              success: false,
              error: `No WHOIS data received for ${domain}`,
            });
            return;
          }

          // Extract key fields from WHOIS response
          const lines = data.split('\n');
          const extracted: string[] = [];
          const importantFields = [
            'domain name', 'registrar', 'creation date', 'updated date',
            'expiration date', 'registry expiry', 'registrant',
            'name server', 'status', 'dnssec', 'registrar abuse',
          ];

          for (const line of lines) {
            const lineLower = line.toLowerCase();
            if (importantFields.some(field => lineLower.includes(field))) {
              extracted.push(line.trim());
            }
          }

          // Truncate if too long
          const output = extracted.length > 0
            ? extracted.slice(0, 20).join('\n')
            : data.slice(0, 2000);

          resolve({
            success: true,
            output: `WHOIS for ${domain} (via ${whoisServer}):\n\n${output}${extracted.length > 20 ? '\n... (truncated)' : ''}`,
          });
        });

        socket.on('error', (err) => {
          resolve({
            success: false,
            error: `WHOIS lookup failed: ${err.message}`,
          });
        });

        socket.on('timeout', () => {
          socket.destroy();
          resolve({
            success: false,
            error: `WHOIS lookup timed out for ${domain}`,
          });
        });

        socket.connect(43, whoisServer);
      });
    },
  },
  {
    name: 'header_analysis',
    description: 'Analyze security headers of a URL',
    category: 'web',
    parameters: [
      { name: 'url', type: 'string', description: 'URL to analyze', required: true },
    ],
    handler: async (context) => {
      const url = context.parameters.url as string;
      const securityHeaders = [
        'Strict-Transport-Security', 'Content-Security-Policy', 'X-Frame-Options',
        'X-Content-Type-Options', 'X-XSS-Protection', 'Referrer-Policy',
        'Permissions-Policy', 'Cross-Origin-Opener-Policy', 'Cross-Origin-Resource-Policy',
      ];
      try {
        const response = await targetFetch(url, {
          method: 'HEAD',
          signal: AbortSignal.timeout(10000),
        });
        const analysis = securityHeaders.map(h => {
          const value = response.headers.get(h);
          return `${h}: ${value ? `✓ ${value}` : '✗ Missing'}`;
        });
        return {
          success: true,
          output: `Security Header Analysis for ${url}:\n${analysis.join('\n')}`,
        };
      } catch (error) {
        return { success: false, error: `Failed: ${error instanceof Error ? error.message : String(error)}` };
      }
    },
  },
  {
    name: 'technology_detect',
    description: 'Detect technologies used by a website (real analysis)',
    category: 'web',
    parameters: [
      { name: 'url', type: 'string', description: 'URL to analyze', required: true },
    ],
    handler: async (context) => {
      const url = context.parameters.url as string;

      try {
        const response = await targetFetch(url, {
          signal: AbortSignal.timeout(10000),
        });

        const headers = Object.fromEntries(response.headers.entries());
        const body = await response.text();
        const detected: { tech: string; evidence: string }[] = [];

        // Server detection from headers
        if (headers['server']) {
          detected.push({ tech: headers['server'], evidence: 'Server header' });
        }
        if (headers['x-powered-by']) {
          detected.push({ tech: headers['x-powered-by'], evidence: 'X-Powered-By header' });
        }

        // CDN/Proxy detection
        if (headers['cf-ray']) detected.push({ tech: 'Cloudflare', evidence: 'CF-Ray header' });
        if (headers['x-amz-cf-id']) detected.push({ tech: 'AWS CloudFront', evidence: 'x-amz-cf-id header' });
        if (headers['x-vercel-id']) detected.push({ tech: 'Vercel', evidence: 'x-vercel-id header' });
        if (headers['x-netlify-id']) detected.push({ tech: 'Netlify', evidence: 'x-netlify-id header' });

        // Framework detection from HTML
        if (body.includes('wp-content') || body.includes('wp-includes')) {
          detected.push({ tech: 'WordPress', evidence: 'wp-content/wp-includes paths' });
        }
        if (body.includes('_next/static') || body.includes('__NEXT_DATA__')) {
          detected.push({ tech: 'Next.js', evidence: '_next paths or __NEXT_DATA__' });
        }
        if (body.includes('/_nuxt/')) {
          detected.push({ tech: 'Nuxt.js', evidence: '_nuxt paths' });
        }
        if (body.includes('ng-version') || body.includes('ng-app')) {
          detected.push({ tech: 'Angular', evidence: 'ng-version/ng-app attributes' });
        }
        if (body.includes('data-reactroot') || body.includes('__REACT_DEVTOOLS')) {
          detected.push({ tech: 'React', evidence: 'React markers in HTML' });
        }
        if (body.includes('data-v-') || body.includes('Vue.js')) {
          detected.push({ tech: 'Vue.js', evidence: 'Vue.js markers' });
        }
        if (body.includes('jquery') || body.includes('jQuery')) {
          detected.push({ tech: 'jQuery', evidence: 'jQuery references' });
        }
        if (body.includes('bootstrap')) {
          detected.push({ tech: 'Bootstrap', evidence: 'Bootstrap CSS/JS' });
        }
        if (body.includes('tailwind')) {
          detected.push({ tech: 'Tailwind CSS', evidence: 'Tailwind references' });
        }

        // CMS detection
        if (body.includes('Drupal') || body.includes('drupal.js')) {
          detected.push({ tech: 'Drupal', evidence: 'Drupal markers' });
        }
        if (body.includes('Joomla') || body.includes('/media/jui/')) {
          detected.push({ tech: 'Joomla', evidence: 'Joomla markers' });
        }
        if (body.includes('Shopify') || body.includes('cdn.shopify.com')) {
          detected.push({ tech: 'Shopify', evidence: 'Shopify CDN' });
        }

        // Meta generator tag
        const generatorMatch = body.match(/<meta[^>]*name=["']generator["'][^>]*content=["']([^"']+)["']/i);
        if (generatorMatch) {
          detected.push({ tech: generatorMatch[1], evidence: 'Meta generator tag' });
        }

        if (detected.length === 0) {
          return {
            success: true,
            output: `Technology detection for ${url}:\nNo technologies detected from headers or content.`,
          };
        }

        const output = detected.map(d => `• ${d.tech} (${d.evidence})`).join('\n');
        return {
          success: true,
          output: `Technology detection for ${url}:\n${output}`,
          findings: [{
            title: 'Technologies Detected',
            severity: 'info',
            details: `Detected ${detected.length} technologies: ${detected.map(d => d.tech).join(', ')}`,
          }],
        };
      } catch (error) {
        return {
          success: false,
          error: `Technology detection failed: ${error instanceof Error ? error.message : String(error)}`,
        };
      }
    },
  },

  // =============================================================================
  // VULNERABILITY SCANNING TOOLS
  // =============================================================================
  {
    name: 'ssl_scan',
    description: 'Analyze SSL/TLS configuration (real connection analysis)',
    category: 'vuln',
    parameters: [
      { name: 'host', type: 'string', description: 'Host to scan', required: true },
      { name: 'port', type: 'number', description: 'Port number', required: false, default: 443 },
    ],
    handler: async (context) => {
      const host = context.parameters.host as string;
      const port = (context.parameters.port as number) || 443;

      if (netBridgeUrl()) {
        try {
          return tlsProbeToResult(await bridgeTlsProbe(host, port));
        } catch (error) {
          return { success: false, error: `TLS probe failed: ${error instanceof Error ? error.message : String(error)}` };
        }
      }

      return new Promise((resolve) => {
        const issues: string[] = [];
        const info: string[] = [];

        const socket = tls.connect({
          host,
          port,
          rejectUnauthorized: false, // Allow self-signed for scanning
          timeout: 10000,
        }, () => {
          try {
            // Get certificate info
            const cert = socket.getPeerCertificate();
            const protocol = socket.getProtocol();
            const cipher = socket.getCipher();

            info.push(`Protocol: ${protocol || 'Unknown'}`);
            info.push(`Cipher: ${cipher?.name || 'Unknown'} (${cipher?.version || 'Unknown'})`);

            if (cert && Object.keys(cert).length > 0) {
              info.push(`Subject: ${cert.subject?.CN || 'Unknown'}`);
              info.push(`Issuer: ${cert.issuer?.CN || 'Unknown'}`);
              info.push(`Valid From: ${cert.valid_from || 'Unknown'}`);
              info.push(`Valid To: ${cert.valid_to || 'Unknown'}`);

              // Check for issues
              if (cert.valid_to) {
                const expiryDate = new Date(cert.valid_to);
                const now = new Date();
                const daysUntilExpiry = Math.floor((expiryDate.getTime() - now.getTime()) / (1000 * 60 * 60 * 24));

                if (daysUntilExpiry < 0) {
                  issues.push('⚠ CRITICAL: Certificate has expired!');
                } else if (daysUntilExpiry < 30) {
                  issues.push(`⚠ Certificate expires in ${daysUntilExpiry} days`);
                }
              }

              // Check for weak key
              if (cert.bits && cert.bits < 2048) {
                issues.push(`⚠ Weak key size: ${cert.bits} bits (recommend 2048+)`);
              }

              // Check for self-signed
              if (cert.subject?.CN === cert.issuer?.CN) {
                issues.push('⚠ Self-signed certificate detected');
              }
            }

            // Check protocol version
            if (protocol === 'TLSv1' || protocol === 'TLSv1.1') {
              issues.push(`⚠ Outdated protocol: ${protocol} (should use TLSv1.2+)`);
            }

            // Check cipher strength
            if (cipher?.name) {
              const weakCiphers = ['RC4', 'DES', '3DES', 'MD5', 'NULL', 'EXPORT', 'anon'];
              for (const weak of weakCiphers) {
                if (cipher.name.toUpperCase().includes(weak)) {
                  issues.push(`⚠ Weak cipher detected: ${cipher.name}`);
                  break;
                }
              }
            }

            socket.end();

            const output = `SSL/TLS scan of ${host}:${port}:\n\n` +
              `Connection Info:\n${info.map(i => `  ${i}`).join('\n')}\n\n` +
              (issues.length > 0
                ? `Issues Found:\n${issues.map(i => `  ${i}`).join('\n')}`
                : '✓ No critical issues found');

            resolve({
              success: true,
              output,
              findings: issues.length > 0 ? [{
                title: 'SSL/TLS Configuration Issues',
                severity: issues.some(i => i.includes('CRITICAL') || i.includes('expired')) ? 'critical' : 'medium',
                details: issues.join('; '),
              }] : undefined,
            });
          } catch (err) {
            socket.end();
            resolve({
              success: false,
              error: `SSL analysis failed: ${err instanceof Error ? err.message : String(err)}`,
            });
          }
        });

        socket.on('error', (err: Error) => {
          resolve({
            success: false,
            error: `SSL connection failed: ${err.message}`,
          });
        });

        socket.on('timeout', () => {
          socket.destroy();
          resolve({
            success: false,
            error: `SSL connection timed out to ${host}:${port}`,
          });
        });
      });
    },
  },

  // =============================================================================
  // UTILITY TOOLS
  // =============================================================================
  {
    name: 'base64_decode',
    description: 'Decode base64 encoded data',
    category: 'util',
    parameters: [
      { name: 'data', type: 'string', description: 'Base64 data to decode', required: true },
    ],
    handler: async (context) => {
      const data = context.parameters.data as string;
      try {
        const decoded = Buffer.from(data, 'base64').toString('utf-8');
        return { success: true, output: `Decoded: ${decoded}` };
      } catch {
        return { success: false, error: 'Invalid base64 data' };
      }
    },
  },
  {
    name: 'jwt_decode',
    description: 'Decode and analyze a JWT token',
    category: 'util',
    parameters: [
      { name: 'token', type: 'string', description: 'JWT token to analyze', required: true },
    ],
    handler: async (context) => {
      const token = context.parameters.token as string;
      const parts = token.split('.');
      if (parts.length !== 3) {
        return { success: false, error: 'Invalid JWT format' };
      }
      try {
        const b64urlDecode = (s: string) => Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString();
        const header = JSON.parse(b64urlDecode(parts[0]));
        const payload = JSON.parse(b64urlDecode(parts[1]));
        const issues: string[] = [];
        if (header.alg === 'none') issues.push('⚠ Algorithm is "none" - VULNERABLE');
        if (header.alg === 'HS256') issues.push('⚠ HS256 may be vulnerable to key confusion');
        if (payload.exp && payload.exp < Date.now() / 1000) issues.push('⚠ Token is expired');
        return {
          success: true,
          output: `JWT Analysis:
Header: ${JSON.stringify(header, null, 2)}
Payload: ${JSON.stringify(payload, null, 2)}
${issues.length ? `Issues:\n${issues.join('\n')}` : '✓ No obvious issues'}`,
        };
      } catch {
        return { success: false, error: 'Failed to decode JWT' };
      }
    },
  },

  // =============================================================================
  // ADDITIONAL RECONNAISSANCE TOOLS
  // =============================================================================
  {
    name: 'robots_txt_fetch',
    description: 'Fetch and parse robots.txt, extract disallowed paths and sitemaps',
    category: 'recon',
    parameters: [
      { name: 'url', type: 'string', description: 'Base URL of the target (e.g., https://example.com)', required: true },
    ],
    handler: async (context) => {
      const baseUrl = (context.parameters.url as string).replace(/\/+$/, '');

      try {
        const robotsUrl = `${baseUrl}/robots.txt`;
        const response = await targetFetch(robotsUrl, {
          signal: AbortSignal.timeout(10000),
        });

        if (response.status === 404) {
          return {
            success: true,
            output: `robots.txt not found at ${robotsUrl} (404)`,
          };
        }

        if (!response.ok) {
          return {
            success: false,
            error: `Failed to fetch robots.txt: HTTP ${response.status}`,
          };
        }

        const body = await response.text();
        const lines = body.split('\n');

        const disallowed: string[] = [];
        const allowed: string[] = [];
        const sitemaps: string[] = [];
        let currentUserAgent = '';

        for (const line of lines) {
          const trimmed = line.trim();
          if (trimmed.startsWith('#') || trimmed === '') continue;

          const colonIndex = trimmed.indexOf(':');
          if (colonIndex === -1) continue;

          const directive = trimmed.slice(0, colonIndex).trim().toLowerCase();
          const value = trimmed.slice(colonIndex + 1).trim();

          switch (directive) {
            case 'user-agent':
              currentUserAgent = value;
              break;
            case 'disallow':
              if (value) disallowed.push(`[${currentUserAgent}] ${value}`);
              break;
            case 'allow':
              if (value) allowed.push(`[${currentUserAgent}] ${value}`);
              break;
            case 'sitemap':
              if (value) sitemaps.push(value);
              break;
          }
        }

        const sections: string[] = [];
        sections.push(`robots.txt for ${baseUrl}:`);
        if (disallowed.length > 0) {
          sections.push(`\nDisallowed Paths (${disallowed.length}):\n${disallowed.map(d => `  ${d}`).join('\n')}`);
        }
        if (allowed.length > 0) {
          sections.push(`\nExplicitly Allowed Paths (${allowed.length}):\n${allowed.map(a => `  ${a}`).join('\n')}`);
        }
        if (sitemaps.length > 0) {
          sections.push(`\nSitemaps (${sitemaps.length}):\n${sitemaps.map(s => `  ${s}`).join('\n')}`);
        }
        if (disallowed.length === 0 && allowed.length === 0 && sitemaps.length === 0) {
          sections.push('\nNo useful directives found in robots.txt');
        }

        const sensitivePatterns = ['/admin', '/backup', '/config', '/private', '/secret', '/internal', '/api', '/debug', '/test', '/.git', '/.env', '/wp-admin', '/phpmyadmin'];
        const sensitiveFinds = disallowed.filter(d => sensitivePatterns.some(p => d.toLowerCase().includes(p)));

        return {
          success: true,
          output: sections.join('\n'),
          findings: sensitiveFinds.length > 0 ? [{
            title: 'Sensitive Paths in robots.txt',
            severity: 'medium' as const,
            details: `robots.txt reveals potentially sensitive paths: ${sensitiveFinds.map(f => f.split('] ')[1]).join(', ')}`,
          }] : undefined,
        };
      } catch (error) {
        return {
          success: false,
          error: `Failed to fetch robots.txt: ${error instanceof Error ? error.message : String(error)}`,
        };
      }
    },
  },

  // =============================================================================
  // ADDITIONAL WEB TESTING TOOLS
  // =============================================================================
  {
    name: 'csp_analysis',
    description: 'Analyze Content-Security-Policy header for weaknesses and misconfigurations',
    category: 'web',
    parameters: [
      { name: 'url', type: 'string', description: 'URL to analyze', required: true },
    ],
    handler: async (context) => {
      const url = context.parameters.url as string;

      try {
        const response = await targetFetch(url, {
          method: 'GET',
          signal: AbortSignal.timeout(10000),
        });

        const csp = response.headers.get('content-security-policy');
        const cspReportOnly = response.headers.get('content-security-policy-report-only');

        if (!csp && !cspReportOnly) {
          return {
            success: true,
            output: `CSP Analysis for ${url}:\nNo Content-Security-Policy header found!`,
            findings: [{
              title: 'Missing Content-Security-Policy Header',
              severity: 'medium' as const,
              details: 'No CSP header is set. This makes the site more vulnerable to XSS and data injection attacks.',
            }],
          };
        }

        const policyToAnalyze = csp || cspReportOnly || '';
        const isReportOnly = !csp && !!cspReportOnly;
        const directives = policyToAnalyze.split(';').map(d => d.trim()).filter(d => d);
        const issues: string[] = [];
        const info: string[] = [];

        if (isReportOnly) {
          issues.push('Policy is report-only (not enforced)');
        }

        const directiveMap: Record<string, string> = {};
        for (const directive of directives) {
          const parts = directive.split(/\s+/);
          const name = parts[0];
          const values = parts.slice(1).join(' ');
          directiveMap[name] = values;
          info.push(`  ${name}: ${values}`);
        }

        // Check for unsafe directives
        if (policyToAnalyze.includes("'unsafe-inline'")) {
          issues.push("'unsafe-inline' allows inline scripts/styles, weakening XSS protection");
        }
        if (policyToAnalyze.includes("'unsafe-eval'")) {
          issues.push("'unsafe-eval' allows eval(), Function(), etc. - high XSS risk");
        }
        if (policyToAnalyze.includes('*')) {
          issues.push('Wildcard (*) source allows loading from any origin');
        }
        if (policyToAnalyze.includes('data:')) {
          issues.push("'data:' URI scheme can be used for XSS bypasses");
        }
        if (policyToAnalyze.includes('blob:')) {
          issues.push("'blob:' URI scheme can be abused for script execution");
        }

        // Check for missing critical directives
        const criticalDirectives = ['default-src', 'script-src', 'style-src', 'img-src', 'object-src', 'frame-ancestors'];
        const missing = criticalDirectives.filter(d => !directiveMap[d] && (d !== 'script-src' || !directiveMap['default-src']));
        if (missing.length > 0) {
          issues.push(`Missing directives: ${missing.join(', ')}`);
        }

        // Check if object-src is not 'none'
        if (directiveMap['object-src'] && directiveMap['object-src'] !== "'none'") {
          issues.push("object-src should be 'none' to prevent Flash/Java plugin exploitation");
        }

        // Check for base-uri
        if (!directiveMap['base-uri']) {
          issues.push("Missing base-uri directive (allows base tag injection)");
        }

        // Check for form-action
        if (!directiveMap['form-action']) {
          issues.push("Missing form-action directive (forms can submit to any origin)");
        }

        const severity = issues.length === 0 ? 'info' : (issues.some(i => i.includes('unsafe-inline') || i.includes('unsafe-eval') || i.includes('Wildcard')) ? 'high' : 'medium');

        const output = `CSP Analysis for ${url}:\n${isReportOnly ? '(Report-Only Mode)\n' : ''}\nDirectives:\n${info.join('\n')}\n\n${issues.length > 0 ? `Issues Found (${issues.length}):\n${issues.map(i => `  - ${i}`).join('\n')}` : 'No major issues found'}`;

        return {
          success: true,
          output,
          findings: issues.length > 0 ? [{
            title: 'CSP Configuration Issues',
            severity: severity as 'info' | 'low' | 'medium' | 'high' | 'critical',
            details: issues.join('; '),
          }] : undefined,
        };
      } catch (error) {
        return {
          success: false,
          error: `CSP analysis failed: ${error instanceof Error ? error.message : String(error)}`,
        };
      }
    },
  },

  // =============================================================================
  // ADDITIONAL VULNERABILITY SCANNING TOOLS
  // =============================================================================
  {
    name: 'cors_check',
    description: 'Test CORS configuration with various Origin headers',
    category: 'vuln',
    parameters: [
      { name: 'url', type: 'string', description: 'URL to test', required: true },
    ],
    handler: async (context) => {
      const url = context.parameters.url as string;

      // Parse the target origin for comparison
      let targetOrigin: URL;
      try {
        targetOrigin = new URL(url);
      } catch {
        return { success: false, error: `Invalid URL: ${url}` };
      }

      const testOrigins = [
        { origin: 'https://evil.com', name: 'Arbitrary origin' },
        { origin: `https://sub.${targetOrigin.hostname}`, name: 'Subdomain' },
        { origin: `https://${targetOrigin.hostname}.evil.com`, name: 'Domain suffix attack' },
        { origin: 'null', name: 'Null origin' },
        { origin: `https://evil${targetOrigin.hostname}`, name: 'Prefix attack' },
        { origin: targetOrigin.origin, name: 'Same origin (baseline)' },
      ];

      const results: { origin: string; name: string; acao: string | null; acac: string | null; vulnerable: boolean; issue: string }[] = [];
      const vulnerabilities: string[] = [];

      for (const test of testOrigins) {
        try {
          const response = await targetFetch(url, {
            method: 'GET',
            headers: { 'Origin': test.origin },
            signal: AbortSignal.timeout(5000),
          });

          const acao = response.headers.get('access-control-allow-origin');
          const acac = response.headers.get('access-control-allow-credentials');

          let vulnerable = false;
          let issue = 'No CORS headers returned';

          if (acao) {
            if (acao === '*') {
              issue = 'Wildcard ACAO (*)';
              if (acac === 'true') {
                vulnerable = true;
                issue = 'Wildcard ACAO with credentials - CRITICAL';
              }
            } else if (acao === test.origin && test.name !== 'Same origin (baseline)') {
              issue = `Origin reflected: ${acao}`;
              vulnerable = true;
              if (acac === 'true') {
                issue += ' WITH credentials - CRITICAL';
              }
            } else if (acao === 'null' && test.origin === 'null') {
              vulnerable = true;
              issue = 'Null origin accepted';
            } else {
              issue = `ACAO: ${acao}`;
            }
          }

          results.push({ origin: test.origin, name: test.name, acao, acac, vulnerable, issue });
          if (vulnerable) {
            vulnerabilities.push(`${test.name}: ${issue}`);
          }

          // Consume response body
          await response.text().catch(() => {});
        } catch {
          results.push({ origin: test.origin, name: test.name, acao: null, acac: null, vulnerable: false, issue: 'Request failed' });
        }
      }

      const output = results.map(r =>
        `  [${r.name}] Origin: ${r.origin}\n    -> ${r.issue}${r.acac ? ` | Credentials: ${r.acac}` : ''}`
      ).join('\n');

      return {
        success: true,
        output: `CORS Configuration Check for ${url}:\n${output}`,
        findings: vulnerabilities.length > 0 ? [{
          title: 'CORS Misconfiguration',
          severity: vulnerabilities.some(v => v.includes('CRITICAL')) ? 'critical' as const : 'high' as const,
          details: vulnerabilities.join('; '),
        }] : undefined,
      };
    },
  },
  {
    name: 'cookie_analysis',
    description: 'Fetch a URL and analyze Set-Cookie headers for security flags',
    category: 'vuln',
    parameters: [
      { name: 'url', type: 'string', description: 'URL to analyze', required: true },
    ],
    handler: async (context) => {
      const url = context.parameters.url as string;

      try {
        const response = await targetFetch(url, {
          signal: AbortSignal.timeout(10000),
          redirect: 'manual', // Don't follow redirects to capture Set-Cookie
        });

        // Get all Set-Cookie headers
        const setCookieHeaders = response.headers.getSetCookie ? response.headers.getSetCookie() : [];
        // Fallback: try raw header
        const rawSetCookie = response.headers.get('set-cookie');

        const cookies: string[] = [...setCookieHeaders];
        if (cookies.length === 0 && rawSetCookie) {
          // Some environments return all cookies in a single header
          cookies.push(...rawSetCookie.split(/,(?=[^;]*=)/));
        }

        if (cookies.length === 0) {
          return {
            success: true,
            output: `Cookie Analysis for ${url}:\nNo Set-Cookie headers found in the response.`,
          };
        }

        const issues: string[] = [];
        const cookieAnalysis: string[] = [];

        for (const cookie of cookies) {
          const parts = cookie.split(';').map(p => p.trim());
          const nameValue = parts[0];
          const cookieName = nameValue.split('=')[0].trim();
          const flags = parts.slice(1).map(f => f.toLowerCase());

          const hasHttpOnly = flags.some(f => f === 'httponly');
          const hasSecure = flags.some(f => f === 'secure');
          const hasSameSite = flags.some(f => f.startsWith('samesite'));
          const sameSiteValue = flags.find(f => f.startsWith('samesite'))?.split('=')[1]?.trim() || 'not set';
          const pathValue = flags.find(f => f.startsWith('path'))?.split('=')[1]?.trim() || '/';
          const hasDomain = flags.some(f => f.startsWith('domain'));
          const domainValue = flags.find(f => f.startsWith('domain'))?.split('=')[1]?.trim() || '';
          const hasExpires = flags.some(f => f.startsWith('expires') || f.startsWith('max-age'));

          const cookieIssues: string[] = [];
          if (!hasHttpOnly) cookieIssues.push('Missing HttpOnly');
          if (!hasSecure) cookieIssues.push('Missing Secure');
          if (!hasSameSite) cookieIssues.push('Missing SameSite');
          if (sameSiteValue === 'none' && !hasSecure) cookieIssues.push('SameSite=None without Secure');
          if (sameSiteValue === 'none') cookieIssues.push('SameSite=None (allows cross-site)');

          // Check for session-like cookie names without security flags
          const sessionLike = /sess|token|auth|jwt|sid|id/i.test(cookieName);
          if (sessionLike && !hasHttpOnly) {
            cookieIssues.push('Session cookie without HttpOnly - vulnerable to XSS theft');
          }

          cookieAnalysis.push(
            `  Cookie: ${cookieName}\n` +
            `    HttpOnly: ${hasHttpOnly ? 'Yes' : 'NO'}\n` +
            `    Secure: ${hasSecure ? 'Yes' : 'NO'}\n` +
            `    SameSite: ${sameSiteValue}\n` +
            `    Path: ${pathValue}\n` +
            `    Domain: ${hasDomain ? domainValue : '(not set)'}\n` +
            `    Persistent: ${hasExpires ? 'Yes' : 'No (session)'}\n` +
            `    Issues: ${cookieIssues.length > 0 ? cookieIssues.join(', ') : 'None'}`
          );

          issues.push(...cookieIssues.map(i => `[${cookieName}] ${i}`));
        }

        return {
          success: true,
          output: `Cookie Analysis for ${url}:\nFound ${cookies.length} cookie(s):\n\n${cookieAnalysis.join('\n\n')}`,
          findings: issues.length > 0 ? [{
            title: 'Cookie Security Issues',
            severity: issues.some(i => i.includes('Session cookie') || i.includes('Missing HttpOnly')) ? 'high' as const : 'medium' as const,
            details: issues.join('; '),
          }] : undefined,
        };
      } catch (error) {
        return {
          success: false,
          error: `Cookie analysis failed: ${error instanceof Error ? error.message : String(error)}`,
        };
      }
    },
  },
  {
    name: 'clickjacking_test',
    description: 'Check if a URL is protected against clickjacking (X-Frame-Options and CSP frame-ancestors)',
    category: 'vuln',
    parameters: [
      { name: 'url', type: 'string', description: 'URL to test', required: true },
    ],
    handler: async (context) => {
      const url = context.parameters.url as string;

      try {
        const response = await targetFetch(url, {
          method: 'GET',
          signal: AbortSignal.timeout(10000),
        });

        const xfo = response.headers.get('x-frame-options');
        const csp = response.headers.get('content-security-policy');

        const issues: string[] = [];
        const info: string[] = [];

        // Analyze X-Frame-Options
        if (xfo) {
          const xfoUpper = xfo.toUpperCase().trim();
          info.push(`X-Frame-Options: ${xfo}`);
          if (xfoUpper === 'DENY') {
            info.push('  -> Framing completely denied (strong)');
          } else if (xfoUpper === 'SAMEORIGIN') {
            info.push('  -> Framing allowed from same origin only (good)');
          } else if (xfoUpper.startsWith('ALLOW-FROM')) {
            info.push(`  -> Framing allowed from specific origin (note: ALLOW-FROM is deprecated and not supported by modern browsers)`);
            issues.push('X-Frame-Options ALLOW-FROM is deprecated; use CSP frame-ancestors instead');
          } else {
            issues.push(`Invalid X-Frame-Options value: ${xfo}`);
          }
        } else {
          issues.push('X-Frame-Options header is missing');
        }

        // Analyze CSP frame-ancestors
        let hasFrameAncestors = false;
        if (csp) {
          const frameAncestorsMatch = csp.match(/frame-ancestors\s+([^;]+)/i);
          if (frameAncestorsMatch) {
            hasFrameAncestors = true;
            const value = frameAncestorsMatch[1].trim();
            info.push(`CSP frame-ancestors: ${value}`);
            if (value === "'none'") {
              info.push('  -> Framing completely denied via CSP (strong)');
            } else if (value === "'self'") {
              info.push('  -> Framing allowed from same origin via CSP (good)');
            } else {
              info.push(`  -> Custom frame-ancestors policy: ${value}`);
              if (value.includes('*')) {
                issues.push('CSP frame-ancestors contains wildcard - weakens clickjacking protection');
              }
            }
          }
        }

        if (!hasFrameAncestors && !xfo) {
          issues.push('No clickjacking protection found (neither X-Frame-Options nor CSP frame-ancestors)');
        } else if (!hasFrameAncestors) {
          info.push('CSP frame-ancestors: Not set (relying on X-Frame-Options only)');
        }

        const output = `Clickjacking Protection Test for ${url}:\n\n${info.join('\n')}\n\n${issues.length > 0 ? `Issues (${issues.length}):\n${issues.map(i => `  - ${i}`).join('\n')}` : 'Site appears protected against clickjacking'}`;

        return {
          success: true,
          output,
          findings: issues.length > 0 ? [{
            title: 'Clickjacking Protection Issues',
            severity: issues.some(i => i.includes('No clickjacking protection')) ? 'medium' as const : 'low' as const,
            details: issues.join('; '),
          }] : undefined,
        };
      } catch (error) {
        return {
          success: false,
          error: `Clickjacking test failed: ${error instanceof Error ? error.message : String(error)}`,
        };
      }
    },
  },

  // =============================================================================
  // ADDITIONAL UTILITY TOOLS
  // =============================================================================
  {
    name: 'cve_lookup',
    description: 'Look up CVEs by ID or keyword — live NVD (CVSS/vector/published) + EPSS exploit probability, local DB fallback',
    category: 'util',
    parameters: [
      { name: 'query', type: 'string', description: 'CVE ID (e.g. CVE-2024-4577) or keyword (e.g. log4j)', required: true },
    ],
    handler: async (context) => {
      const query = (context.parameters.query as string).trim();
      const q = query.toLowerCase();
      const cveIdMatch = /^CVE-\d{4}-\d{4,}$/i.exec(q);

      // ── Live enrichment for a full CVE ID: NVD CVSS + EPSS probability ──
      if (cveIdMatch) {
        const cveId = cveIdMatch[0].toUpperCase();
        const parts: string[] = [];
        let cvssBase: number | null = null;
        let severity: string | null = null;
        let found = false;
        try {
          const nvd = await targetFetch(`https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${cveId}`, {
            signal: AbortSignal.timeout(15000),
            headers: { 'user-agent': 'T3MP3ST/1.0' },
          });
          const j = (await nvd.json()) as { resultsPerPage?: number; vulnerabilities?: { cve: { id: string; descriptions?: { lang: string; value: string }[]; published?: string; metrics?: Record<string, unknown[]> } }[] };
          const v = j.vulnerabilities?.[0]?.cve;
          if (v) {
            found = true;
            parts.push(`CVE: ${v.id}`);
            const desc = v.descriptions?.find((d) => d.lang === 'en')?.value ?? '';
            if (desc) parts.push(`Description: ${desc.slice(0, 400)}`);
            if (v.published) parts.push(`Published: ${v.published.slice(0, 10)}`);
            const metrics = v.metrics ?? {};
            const cvssV4 = metrics.cvssMetricV40?.[0] as { cvssData?: { baseScore?: number; baseSeverity?: string; vectorString?: string } } | undefined;
            const cvssV31 = metrics.cvssMetricV31?.[0] as { cvssData?: { baseScore?: number; baseSeverity?: string; vectorString?: string } } | undefined;
            const cvssV3 = metrics.cvssMetricV30?.[0] as { cvssData?: { baseScore?: number; baseSeverity?: string; vectorString?: string } } | undefined;
            const pick = cvssV4 ?? cvssV31 ?? cvssV3;
            if (pick?.cvssData) {
              cvssBase = pick.cvssData.baseScore ?? null;
              severity = pick.cvssData.baseSeverity ?? null;
              parts.push(`CVSS: ${cvssBase} (${severity})`);
              if (pick.cvssData.vectorString) parts.push(`Vector: ${pick.cvssData.vectorString}`);
            }
          }
        } catch { /* NVD unreachable — fall through to EPSS + local */ }

        try {
          const epss = await targetFetch(`https://api.first.org/data/v1/epss?cve=${cveId}`, { signal: AbortSignal.timeout(10000) });
          const ej = (await epss.json()) as { data?: { epss?: string; percentile?: string }[] };
          const e = ej.data?.[0];
          if (e?.epss !== undefined) {
            const pct = (parseFloat(e.epss) * 100).toFixed(1);
            const ptile = e.percentile ? (parseFloat(e.percentile) * 100).toFixed(1) : '?';
            parts.push(`EPSS exploit probability: ${pct}% (percentile ${ptile})`);
          }
        } catch { /* EPSS unreachable */ }

        if (found || parts.length > 0) {
          const risk = cvssBase !== null && cvssBase >= 9.0 ? 'critical'
            : cvssBase !== null && cvssBase >= 7.0 ? 'high'
            : cvssBase !== null && cvssBase >= 4.0 ? 'medium' : 'info';
          const high = risk === 'critical' || risk === 'high';
          return {
            success: true,
            output: parts.join('\n'),
            findings: [{
              title: `CVE Intelligence: ${cveId}`,
              severity: (high ? 'high' : 'info') as 'high' | 'info',
              details: parts.join(' | ').slice(0, 400),
              ...(cveIdMatch ? { cve: [cveId] } : {}),
            }],
          };
        }
        // NVD+EPSS both failed — fall back to local DB
      }

      const matches: CVEEntry[] = CVE_DATABASE.filter(cve =>
        cve.id.toLowerCase().includes(q) ||
        cve.description.toLowerCase().includes(q)
      );

      if (matches.length === 0) {
        return {
          success: true,
          output: `CVE Lookup for "${query}":\nNo matching CVEs found (live NVD/EPSS unavailable or no local match; ${CVE_DATABASE.length} local entries).`,
        };
      }

      const output = matches.map(cve =>
        `  ${cve.id} (CVSS: ${cve.cvss})\n    ${cve.description}`
      ).join('\n\n');

      return {
        success: true,
        output: `CVE Lookup for "${query}":\nFound ${matches.length} matching CVE(s):\n\n${output}`,
        findings: matches.filter(m => m.cvss >= 9.0).length > 0 ? [{
          title: 'Critical CVEs Found',
          severity: 'critical' as const,
          details: `Found ${matches.filter(m => m.cvss >= 9.0).length} critical CVEs (CVSS >= 9.0): ${matches.filter(m => m.cvss >= 9.0).map(m => m.id).join(', ')}`,
        }] : undefined,
      };
    },
  },
  {
    name: 'url_encode',
    description: 'URL encode or decode data',
    category: 'util',
    parameters: [
      { name: 'data', type: 'string', description: 'Data to encode or decode', required: true },
      { name: 'mode', type: 'string', description: 'Mode: "encode" or "decode"', required: false, default: 'encode' },
      { name: 'component', type: 'boolean', description: 'Use encodeURIComponent (true) or encodeURI (false)', required: false, default: true },
    ],
    handler: async (context) => {
      const data = context.parameters.data as string;
      const mode = (context.parameters.mode as string || 'encode').toLowerCase();
      const component = context.parameters.component !== false;

      try {
        let result: string;

        if (mode === 'decode') {
          result = component ? decodeURIComponent(data) : decodeURI(data);
        } else {
          result = component ? encodeURIComponent(data) : encodeURI(data);
        }

        return {
          success: true,
          output: `URL ${mode === 'decode' ? 'Decode' : 'Encode'} (${component ? 'component' : 'full URI'}):\nInput:  ${data}\nOutput: ${result}`,
        };
      } catch (error) {
        return {
          success: false,
          error: `URL ${mode} failed: ${error instanceof Error ? error.message : String(error)}`,
        };
      }
    },
  },
];

/** Every built-in tool of the defensive profile, each stamped with its risk tier. */
export const BUILTIN_TOOLS: CustomTool[] = BUILTIN_TOOL_DEFINITIONS.map((tool) => ({
  ...tool,
  riskTier: defensiveTier(tool.name),
}));
