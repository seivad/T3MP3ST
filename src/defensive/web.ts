/**
 * Passive posture checks of the operator's site.
 *
 * Requests sent to the site: one GET of the entered page (redirects followed), and GETs of
 * /robots.txt and /.well-known/security.txt. DNS and registration data come from resolvers and
 * registries, and TLS posture from HTTPS/HTTP GETs and Certificate Transparency (through the
 * Worker's network bridge in the sandbox). Nothing else is sent: no path enumeration, no
 * payloads, no port scans.
 */

import type { Arsenal } from '../arsenal/index.js';
import type { ToolResult } from '../types/index.js';
import { findingId } from './scan-util.js';
import type { DefensiveFinding, Severity } from './types.js';

export const USER_AGENT = 'T3MP3ST-Defensive/1.0 (Cloudflare OS Security Assessor; passive posture check)';

export interface WebContext {
  arsenal: Arsenal;
  signal?: AbortSignal;
  /** Called around every tool call so progress streams to the UI. */
  onTool?: (name: string, args: Record<string, unknown>, result: ToolResult) => void;
  fetchImpl?: typeof fetch;
}

interface PageObservation {
  requestedUrl: string;
  finalUrl: string;
  status: number;
  headers: Headers;
  cookies: string[];
  body: string;
}

/** The one GET of the page every header and cookie check reads. */
export async function fetchPage(url: string, fetchImpl: typeof fetch = fetch, signal?: AbortSignal): Promise<PageObservation> {
  const response = await fetchImpl(url, {
    method: 'GET',
    redirect: 'follow',
    headers: { 'user-agent': USER_AGENT, accept: 'text/html,application/xhtml+xml;q=0.9,*/*;q=0.8' },
    signal: signal ? AbortSignal.any([signal, AbortSignal.timeout(20_000)]) : AbortSignal.timeout(20_000),
  });
  const reader = response.body?.getReader();
  let body = '';
  if (reader) {
    const decoder = new TextDecoder();
    while (body.length < 300_000) {
      const { done, value } = await reader.read();
      if (done) break;
      body += decoder.decode(value, { stream: true });
    }
    await reader.cancel().catch(() => undefined);
  }
  const cookies = typeof response.headers.getSetCookie === 'function' ? response.headers.getSetCookie() : [];
  return { requestedUrl: url, finalUrl: response.url || url, status: response.status, headers: response.headers, cookies, body };
}

function finding(
  site: string,
  key: string,
  title: string,
  severity: Severity,
  category: DefensiveFinding['category'],
  evidence: string,
  description: string,
  remediation: string,
  retest: string,
  cwe?: string,
): DefensiveFinding {
  return {
    id: findingId('web', site, key),
    title,
    severity,
    category,
    cwe: cwe ? [cwe] : undefined,
    location: { url: site },
    evidence,
    description,
    remediation,
    retest,
    source: 'T3MP3ST passive posture',
    confidence: 'confirmed',
  };
}

/** Header, cookie and content checks over one page observation. Pure: unit-tested directly. */
export function analyzePage(page: PageObservation): DefensiveFinding[] {
  const out: DefensiveFinding[] = [];
  const site = page.finalUrl;
  const h = (name: string) => page.headers.get(name);
  const https = site.startsWith('https://');

  const hsts = h('strict-transport-security');
  if (https && !hsts) {
    out.push(finding(site, 'hsts-missing', 'Strict-Transport-Security header missing', 'medium', 'web',
      'Response has no Strict-Transport-Security header.',
      'Without HSTS a browser can be downgraded to plain HTTP on a hostile network before the redirect to HTTPS.',
      'Send `Strict-Transport-Security: max-age=31536000; includeSubDomains` (add `preload` once every subdomain serves HTTPS).',
      'The response carries Strict-Transport-Security with max-age of at least 31536000.', 'CWE-319'));
  }

  const csp = h('content-security-policy');
  if (!csp) {
    out.push(finding(site, 'csp-missing', 'Content-Security-Policy header missing', 'medium', 'web',
      'Response has no Content-Security-Policy header.',
      'A CSP is the main browser-side defense that limits the damage of any XSS bug.',
      "Start with `Content-Security-Policy: default-src 'self'; object-src 'none'; frame-ancestors 'self'; base-uri 'self'` in report-only mode, then enforce.",
      'The response carries an enforced Content-Security-Policy without unsafe-inline or wildcard script sources.', 'CWE-1021'));
  } else if (/script-src[^;]*('unsafe-inline'|'unsafe-eval'|\*(?![\w.]))|default-src[^;]*('unsafe-inline'|\*(?![\w.]))/.test(csp)) {
    out.push(finding(site, 'csp-weak', 'Content-Security-Policy allows inline or wildcard scripts', 'low', 'web',
      `Content-Security-Policy: ${csp.slice(0, 300)}`,
      'unsafe-inline, unsafe-eval or a wildcard in script sources lets injected script run, which defeats most of the policy.',
      'Replace unsafe-inline with nonces or hashes and list script hosts explicitly.',
      'The policy has no unsafe-inline, unsafe-eval or wildcard in script-src/default-src.', 'CWE-1021'));
  }

  if ((h('x-content-type-options') ?? '').toLowerCase() !== 'nosniff') {
    out.push(finding(site, 'nosniff-missing', 'X-Content-Type-Options: nosniff missing', 'low', 'web',
      `X-Content-Type-Options: ${h('x-content-type-options') ?? '(absent)'}`,
      'Browsers may MIME-sniff responses and execute uploaded or user content as script.',
      'Send `X-Content-Type-Options: nosniff` on every response.',
      'Every response carries X-Content-Type-Options: nosniff.', 'CWE-693'));
  }

  if (!h('x-frame-options') && !/frame-ancestors/i.test(csp ?? '')) {
    out.push(finding(site, 'framing', 'Clickjacking protection missing', 'medium', 'web',
      'Neither X-Frame-Options nor a CSP frame-ancestors directive is present.',
      'Any site can embed these pages in a frame and trick users into clicking.',
      "Send `Content-Security-Policy: frame-ancestors 'self'` (and `X-Frame-Options: SAMEORIGIN` for old browsers).",
      'The response carries frame-ancestors or X-Frame-Options.', 'CWE-1021'));
  }

  if (!h('referrer-policy')) {
    out.push(finding(site, 'referrer', 'Referrer-Policy header missing', 'low', 'web',
      'Response has no Referrer-Policy header.',
      'Full URLs, including tokens in query strings, can leak to third-party sites in the Referer header.',
      'Send `Referrer-Policy: strict-origin-when-cross-origin`.',
      'The response carries a Referrer-Policy header.', 'CWE-200'));
  }

  if (!h('permissions-policy')) {
    out.push(finding(site, 'permissions', 'Permissions-Policy header missing', 'info', 'web',
      'Response has no Permissions-Policy header.',
      'Browser features (camera, geolocation, payment) are not restricted for this origin and embedded frames.',
      'Send a Permissions-Policy that disables unused features, e.g. `camera=(), microphone=(), geolocation=()`.',
      'The response carries a Permissions-Policy header.'));
  }

  const banner = [h('server'), h('x-powered-by'), h('x-aspnet-version'), h('x-generator')].filter((v): v is string => !!v && /\d/.test(v));
  if (banner.length) {
    out.push(finding(site, 'banner', 'Software versions disclosed in response headers', 'low', 'web',
      banner.map((b) => `• ${b}`).join('\n'),
      'Exact product versions help an attacker match known CVEs to this site.',
      'Remove or genericize Server/X-Powered-By headers at the origin, or strip them at the edge.',
      'Responses no longer include version numbers in Server or X-Powered-By.', 'CWE-200'));
  }

  for (const cookie of page.cookies) {
    const name = cookie.split('=')[0].trim();
    const lower = cookie.toLowerCase();
    const missing = [
      https && !/;\s*secure/.test(lower) ? 'Secure' : null,
      !/;\s*httponly/.test(lower) ? 'HttpOnly' : null,
      !/;\s*samesite=/.test(lower) ? 'SameSite' : null,
    ].filter(Boolean);
    if (missing.length) {
      const session = /sess|auth|token|sid|jwt|login/i.test(name);
      out.push(finding(site, `cookie-${name}`, `Cookie "${name}" missing ${missing.join(', ')}`, session ? 'medium' : 'low', 'web',
        `Set-Cookie: ${name}=…; ${cookie.split(';').slice(1).map((s) => s.trim()).join('; ') || '(no attributes)'}`,
        'Cookies without Secure can travel over HTTP, without HttpOnly are readable by injected script, and without SameSite are sent on cross-site requests (CSRF).',
        `Set the cookie with \`Secure; HttpOnly; SameSite=Lax\` (or Strict for session cookies).`,
        `Set-Cookie for ${name} carries Secure, HttpOnly and SameSite.`, 'CWE-614'));
    }
  }

  const acao = h('access-control-allow-origin');
  if (acao === '*' && (h('access-control-allow-credentials') ?? '').toLowerCase() === 'true') {
    out.push(finding(site, 'cors', 'CORS allows any origin with credentials', 'high', 'web',
      'Access-Control-Allow-Origin: *\nAccess-Control-Allow-Credentials: true',
      'Any website can make authenticated requests and read the responses.',
      'Return Access-Control-Allow-Origin only for an allow list of origins, and never with credentials for a wildcard.',
      'Responses no longer combine a wildcard origin with credentials.', 'CWE-942'));
  }

  if (https) {
    const mixed = [...page.body.matchAll(/<(?:script|link|iframe|img)[^>]+(?:src|href)=["'](http:\/\/[^"']+)["']/gi)].map((m) => m[1]).slice(0, 5);
    if (mixed.length) {
      out.push(finding(site, 'mixed', 'Mixed content: page loads resources over HTTP', 'low', 'web',
        mixed.join('\n'),
        'Resources fetched over HTTP on an HTTPS page can be tampered with in transit.',
        'Serve every resource over HTTPS (enable Automatic HTTPS Rewrites at the edge as a stopgap).',
        'The page references no http:// scripts, styles, frames or images.', 'CWE-319'));
    }
  }

  const proxied = !!h('cf-ray') || (h('server') ?? '').toLowerCase() === 'cloudflare';
  if (!proxied) {
    out.push(finding(site, 'edge', 'Site is not served through the Cloudflare proxy', 'medium', 'web',
      `No cf-ray header; Server: ${h('server') ?? '(absent)'}`,
      'Traffic reaches the origin directly, so edge protections (WAF managed rules, DDoS mitigation, bot management, rate limiting) cannot apply.',
      'Proxy the hostname through Cloudflare (orange-cloud the DNS record) and lock the origin to Cloudflare IPs or a Cloudflare Tunnel.',
      'Responses carry a cf-ray header and the origin refuses direct connections.'));
  }
  return out;
}

/** The registrable domain of a hostname, with the common two-label public suffixes handled. */
export function registrableDomain(host: string): string {
  const labels = host.toLowerCase().split('.').filter(Boolean);
  if (labels.length <= 2) return labels.join('.');
  const two = labels.slice(-2).join('.');
  const twoLevelSuffixes = /^(?:com|net|org|gov|edu|co|ac|id|or|ne)\.(?:au|uk|nz|jp|za|br|in|kr|sg|hk|tw|mx|ar|tr|il)$/;
  return twoLevelSuffixes.test(two) ? labels.slice(-3).join('.') : two;
}

async function tool(ctx: WebContext, name: string, args: Record<string, unknown>): Promise<ToolResult> {
  let result: ToolResult;
  try {
    result = await ctx.arsenal.execute(name, { parameters: args, operator: 'posture' });
  } catch (error) {
    result = { success: false, error: error instanceof Error ? error.message : String(error) };
  }
  ctx.onTool?.(name, args, result);
  return result;
}

/** DNS-level checks: CAA, SPF and DMARC on the registrable domain. */
export async function checkDns(host: string, ctx: WebContext): Promise<DefensiveFinding[]> {
  const out: DefensiveFinding[] = [];
  const domain = registrableDomain(host);
  const site = `dns:${domain}`;
  const records = async (name: string, type: string) => {
    const result = await tool(ctx, 'dns_lookup', { domain: name, type });
    if (!result.success) return null;
    return (result.output ?? '').split('\n').slice(1).map((l) => l.trim()).filter((l) => l && l !== '(no records)');
  };
  await records(host, 'A');
  const caa = await records(domain, 'CAA');
  if (caa && caa.length === 0) {
    out.push(finding(site, 'caa', `No CAA record for ${domain}`, 'low', 'dns',
      `DNS CAA ${domain}: no records`,
      'Any certificate authority may issue certificates for the domain.',
      `Add CAA records naming only the CAs you use (e.g. \`${domain}. CAA 0 issue "letsencrypt.org"\` and the CAs Cloudflare uses for your edge certificates).`,
      `dig CAA ${domain} returns your CA allow list.`, 'CWE-295'));
  }
  const txt = await records(domain, 'TXT');
  const mx = await records(domain, 'MX');
  if (txt && !txt.some((r) => /v=spf1/i.test(r))) {
    out.push(finding(site, 'spf', `No SPF record for ${domain}`, mx && mx.length ? 'medium' : 'low', 'dns',
      `DNS TXT ${domain}: ${txt.length ? txt.slice(0, 3).join(' | ') : 'no records'}`,
      'Without SPF, receivers cannot tell which servers may send mail as this domain, which makes spoofing easier.',
      mx && mx.length ? 'Publish an SPF record listing your mail senders, ending in `-all` or `~all`.' : `The domain sends no mail: publish \`v=spf1 -all\`.`,
      `dig TXT ${domain} shows a v=spf1 record.`, 'CWE-290'));
  }
  const dmarc = await records(`_dmarc.${domain}`, 'TXT');
  const policy = dmarc?.find((r) => /v=DMARC1/i.test(r));
  if (dmarc && (!policy || /p=none/i.test(policy))) {
    out.push(finding(site, 'dmarc', policy ? `DMARC policy for ${domain} is p=none` : `No DMARC record for ${domain}`, 'medium', 'dns',
      `DNS TXT _dmarc.${domain}: ${policy ?? 'no DMARC record'}`,
      'Mail spoofing this domain is delivered: there is no DMARC enforcement.',
      `Publish \`v=DMARC1; p=quarantine; rua=mailto:…\` and move to p=reject once reports are clean (Cloudflare DMARC Management helps).`,
      `dig TXT _dmarc.${domain} shows p=quarantine or p=reject.`, 'CWE-290'));
  }
  return out;
}

/** Every passive check of `url`. Network failures become coverage notes, never crashes. */
export async function runPassivePosture(url: string, ctx: WebContext): Promise<{
  findings: DefensiveFinding[];
  coverage: Array<{ check: string; status: 'ran' | 'skipped' | 'failed'; note?: string }>;
  technology?: string;
}> {
  const findings: DefensiveFinding[] = [];
  const coverage: Array<{ check: string; status: 'ran' | 'skipped' | 'failed'; note?: string }> = [];
  const host = new URL(url).hostname;
  const fetchImpl = ctx.fetchImpl ?? fetch;

  try {
    const page = await fetchPage(url, fetchImpl, ctx.signal);
    ctx.onTool?.('page_fetch', { url }, { success: true, output: `GET ${url} → ${page.status} (${page.finalUrl})` });
    findings.push(...analyzePage(page));
    coverage.push({ check: 'Security headers, cookies, CORS, mixed content', status: 'ran' });
  } catch (error) {
    coverage.push({ check: 'Security headers, cookies, CORS, mixed content', status: 'failed', note: error instanceof Error ? error.message : String(error) });
  }

  const tech = await tool(ctx, 'technology_detect', { url });
  coverage.push({ check: 'Technology fingerprint', status: tech.success ? 'ran' : 'failed', note: tech.success ? undefined : tech.error });

  const robots = await tool(ctx, 'robots_txt_fetch', { url: new URL(url).origin });
  coverage.push({ check: 'robots.txt', status: robots.success ? 'ran' : 'failed', note: robots.success ? undefined : robots.error });
  for (const f of robots.findings ?? []) {
    findings.push(finding(url, 'robots', f.title, 'info', 'web', f.details, 'robots.txt is public; listing private paths there advertises them.', 'Protect sensitive paths with authentication (Cloudflare Access) instead of hiding them in robots.txt.', 'robots.txt lists no sensitive paths, and those paths require authentication.', 'CWE-200'));
  }

  try {
    const securityTxt = await fetchImpl(new URL('/.well-known/security.txt', url), { headers: { 'user-agent': USER_AGENT }, signal: AbortSignal.timeout(10_000) });
    const text = securityTxt.ok ? await securityTxt.text() : '';
    ctx.onTool?.('security_txt', { url }, { success: true, output: `GET /.well-known/security.txt → ${securityTxt.status}` });
    if (!/^\s*Contact:/im.test(text)) {
      findings.push(finding(url, 'security-txt', 'No security.txt contact published', 'info', 'web',
        `GET /.well-known/security.txt → ${securityTxt.status}`,
        'Researchers who find a vulnerability have no published way to report it (RFC 9116).',
        'Publish /.well-known/security.txt with Contact and Expires fields (Cloudflare can serve it for you).',
        '/.well-known/security.txt returns a Contact field.'));
    }
    coverage.push({ check: 'security.txt', status: 'ran' });
  } catch (error) {
    coverage.push({ check: 'security.txt', status: 'failed', note: error instanceof Error ? error.message : String(error) });
  }

  const tls = await tool(ctx, 'ssl_scan', { host, port: 443 });
  coverage.push({ check: 'TLS posture', status: tls.success ? 'ran' : 'failed', note: tls.success ? undefined : tls.error });
  for (const f of tls.findings ?? []) {
    findings.push(finding(url, 'tls', f.title, f.severity, 'tls', `${f.details}\n\n${(tls.output ?? '').slice(0, 800)}`,
      'Weak transport security exposes users to interception or downgrade.',
      'Serve HTTPS only with a valid certificate, redirect HTTP to HTTPS, set HSTS, and require TLS 1.2+ (TLS 1.3 preferred).',
      'The TLS check reports no issues.', 'CWE-326'));
  }

  try {
    findings.push(...(await checkDns(host, ctx)));
    coverage.push({ check: 'DNS (CAA, SPF, DMARC)', status: 'ran' });
  } catch (error) {
    coverage.push({ check: 'DNS (CAA, SPF, DMARC)', status: 'failed', note: error instanceof Error ? error.message : String(error) });
  }

  const whois = await tool(ctx, 'whois_lookup', { domain: registrableDomain(host) });
  coverage.push({ check: 'Registration data (RDAP/WHOIS)', status: whois.success ? 'ran' : 'failed', note: whois.success ? undefined : whois.error });
  const expiry = /(?:expir\w*|registry expiry date)[^0-9]*(\d{4}-\d{2}-\d{2})/i.exec(whois.output ?? '')?.[1];
  if (expiry) {
    const days = Math.floor((Date.parse(expiry) - Date.now()) / 86_400_000);
    if (days >= 0 && days < 45) {
      findings.push(finding(url, 'domain-expiry', `Domain registration expires in ${days} days`, 'medium', 'dns',
        `Registry expiry date: ${expiry}`,
        'An expired domain can be registered by someone else, who then receives your traffic and email.',
        'Renew the domain and enable auto-renew (and registrar lock).', 'Registration data shows an expiry more than a year away.'));
    }
  }

  return { findings, coverage, technology: tech.success ? tech.output : undefined };
}
