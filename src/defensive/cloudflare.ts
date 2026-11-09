/**
 * "Harden with Cloudflare": maps each finding to the Cloudflare controls that mitigate it, with
 * the concrete setting and a documentation link. Edge controls reduce exposure while the code
 * fix ships; they never replace it, and the report says so.
 */

import type { CloudflareControl, DefensiveFinding } from './types.js';

const DOCS = 'https://developers.cloudflare.com';

export const CONTROLS = {
  wafManaged: {
    control: 'WAF Managed Rules',
    action: 'Deploy the Cloudflare Managed Ruleset and the OWASP Core Ruleset (Security > WAF > Managed rules) in block mode.',
    docs: `${DOCS}/waf/managed-rules/`,
  },
  wafAttackScore: {
    control: 'WAF attack score',
    action: 'Add a custom rule blocking requests with cf.waf.score.sqli / cf.waf.score.xss / cf.waf.score.rce below 20.',
    docs: `${DOCS}/waf/detections/attack-score/`,
  },
  transformHeaders: {
    control: 'Security headers via Transform Rules',
    action: 'Add a Response Header Transform Rule that sets the missing security headers (HSTS, CSP, X-Content-Type-Options, frame-ancestors, Referrer-Policy) on every response.',
    docs: `${DOCS}/rules/transform/response-header-modification/`,
  },
  removeHeaders: {
    control: 'Strip version banners via Transform Rules',
    action: 'Add a Response Header Transform Rule that removes Server version details and X-Powered-By.',
    docs: `${DOCS}/rules/transform/response-header-modification/`,
  },
  tlsSettings: {
    control: 'SSL/TLS settings',
    action: 'Set encryption mode to Full (strict), Minimum TLS Version 1.2, enable TLS 1.3, Always Use HTTPS and HSTS (SSL/TLS > Edge Certificates).',
    docs: `${DOCS}/ssl/edge-certificates/additional-options/`,
  },
  httpsRewrites: {
    control: 'Automatic HTTPS Rewrites',
    action: 'Enable Automatic HTTPS Rewrites to fix mixed-content links at the edge.',
    docs: `${DOCS}/ssl/edge-certificates/additional-options/automatic-https-rewrites/`,
  },
  botManagement: {
    control: 'Bot Management / Super Bot Fight Mode',
    action: 'Challenge or block definitely-automated traffic on login, signup and API endpoints.',
    docs: `${DOCS}/bots/`,
  },
  rateLimiting: {
    control: 'Rate limiting rules',
    action: 'Add a rate limiting rule on authentication and expensive endpoints (for example 10 requests/minute per IP on /login).',
    docs: `${DOCS}/waf/rate-limiting-rules/`,
  },
  access: {
    control: 'Cloudflare Access',
    action: 'Put administrative and internal paths behind Cloudflare Access so only your identity provider\'s users reach them.',
    docs: `${DOCS}/cloudflare-one/applications/configure-apps/self-hosted-public-app/`,
  },
  tunnel: {
    control: 'Proxy + Cloudflare Tunnel',
    action: 'Proxy the hostname (orange cloud) and connect the origin with Cloudflare Tunnel so it accepts no direct traffic.',
    docs: `${DOCS}/cloudflare-one/connections/connect-networks/`,
  },
  dmarc: {
    control: 'Email security DNS (DMARC Management)',
    action: 'Use DMARC Management to publish SPF/DKIM/DMARC and move the policy to quarantine, then reject.',
    docs: `${DOCS}/dmarc-management/`,
  },
  dnssec: {
    control: 'DNS records and DNSSEC',
    action: 'Add CAA records for your issuing CAs and enable DNSSEC (DNS > Settings).',
    docs: `${DOCS}/dns/dnssec/`,
  },
  secretsStore: {
    control: 'Workers Secrets / Secrets Store',
    action: 'Store credentials as Worker secrets (`wrangler secret put`) or in Secrets Store, never in code or vars.',
    docs: `${DOCS}/workers/configuration/secrets/`,
  },
  pageShield: {
    control: 'Page Shield',
    action: 'Monitor and restrict the third-party scripts your pages load (client-side supply chain).',
    docs: `${DOCS}/page-shield/`,
  },
  leakedCredentials: {
    control: 'Leaked credentials detection',
    action: 'Enable leaked credentials detection so logins with known-breached passwords are flagged to your origin.',
    docs: `${DOCS}/waf/detections/leaked-credentials/`,
  },
} satisfies Record<string, CloudflareControl>;

/** The Cloudflare controls that mitigate `finding`, most specific first. */
export function controlsFor(finding: DefensiveFinding): CloudflareControl[] {
  const cwe = finding.cwe ?? [];
  const has = (...ids: string[]) => ids.some((id) => cwe.includes(id));
  const t = finding.title.toLowerCase();
  const out: CloudflareControl[] = [];
  if (has('CWE-89', 'CWE-78', 'CWE-95', 'CWE-22', 'CWE-502', 'CWE-918')) out.push(CONTROLS.wafManaged, CONTROLS.wafAttackScore);
  if (has('CWE-79')) out.push(CONTROLS.wafManaged, CONTROLS.wafAttackScore, CONTROLS.transformHeaders);
  if (finding.category === 'dependency') out.push(CONTROLS.wafManaged);
  if (/javascript|client-side|script/.test(t) && finding.category === 'dependency') out.push(CONTROLS.pageShield);
  if (finding.category === 'secret' || t.includes('secret') && finding.category === 'config') out.push(CONTROLS.secretsStore);
  if (/strict-transport|content-security|nosniff|clickjacking|referrer-policy|permissions-policy|cookie/.test(t)) out.push(CONTROLS.transformHeaders);
  if (/versions disclosed/.test(t)) out.push(CONTROLS.removeHeaders);
  if (finding.category === 'tls' || /strict-transport/.test(t)) out.push(CONTROLS.tlsSettings);
  if (/mixed content/.test(t)) out.push(CONTROLS.httpsRewrites);
  if (/not served through the cloudflare proxy|administrative port|database port/.test(t)) out.push(CONTROLS.tunnel, CONTROLS.access);
  if (/robots\.txt|admin|debug/.test(t)) out.push(CONTROLS.access);
  if (/spf|dmarc/.test(t)) out.push(CONTROLS.dmarc);
  if (/caa|dnssec/.test(t)) out.push(CONTROLS.dnssec);
  if (has('CWE-287', 'CWE-307', 'CWE-347') || /login|auth/.test(t)) out.push(CONTROLS.rateLimiting, CONTROLS.botManagement, CONTROLS.leakedCredentials);
  if (has('CWE-942')) out.push(CONTROLS.transformHeaders);
  return [...new Map(out.map((c) => [c.control, c])).values()];
}

/** The report's Harden-with-Cloudflare section: each control once, with the findings it covers. */
export function hardenPlan(findings: DefensiveFinding[]): Array<CloudflareControl & { findings: string[] }> {
  const byControl = new Map<string, CloudflareControl & { findings: string[] }>();
  for (const f of findings) {
    for (const c of f.cloudflare ?? controlsFor(f)) {
      const entry = byControl.get(c.control) ?? { ...c, findings: [] };
      entry.findings.push(f.id);
      byControl.set(c.control, entry);
    }
  }
  return [...byControl.values()].sort((a, b) => b.findings.length - a.findings.length);
}
