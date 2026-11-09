/**
 * The network bridge: how network tools reach the outside when T3MP3ST runs in a sandbox whose
 * container has no internet of its own.
 *
 * In the Cloudflare OS Security Assessor, the container starts with internet access off and every
 * HTTP(S) request it makes is intercepted by the Worker that owns it. Raw sockets (DNS over UDP,
 * WHOIS on port 43, TLS handshakes for certificate inspection) cannot leave
 * the container at all. When T3MP3ST_NET_BRIDGE is set, the tools that need them make an HTTP
 * request to that URL instead, and the Worker answers after its own scope check: DNS over HTTPS,
 * RDAP for registration data, and a TLS posture check built from HTTPS GETs and Certificate
 * Transparency.
 *
 * Unset (a local run), the tools use Node's own dns/net/tls modules as upstream T3MP3ST does.
 */

/** The bridge base URL, or null when tools should use native networking. */
export function netBridgeUrl(): string | null {
  const raw = process.env.T3MP3ST_NET_BRIDGE?.trim();
  if (!raw) return null;
  try {
    const url = new URL(raw);
    return url.protocol === 'http:' || url.protocol === 'https:' ? url.href.replace(/\/+$/, '') : null;
  } catch {
    return null;
  }
}

async function callBridge<T>(path: string, params: Record<string, string>, timeoutMs = 20_000): Promise<T> {
  const base = netBridgeUrl();
  if (!base) throw new Error('network bridge is not configured');
  const url = new URL(`${base}/${path}`);
  for (const [key, value] of Object.entries(params)) url.searchParams.set(key, value);
  const response = await fetch(url, { signal: AbortSignal.timeout(timeoutMs) });
  const body = (await response.json().catch(() => ({}))) as T & { error?: string };
  if (!response.ok) {
    throw new Error(body.error || `network bridge returned HTTP ${response.status}`);
  }
  return body;
}

/** DNS records of `type` for `name`, resolved by the Worker over DNS-over-HTTPS. */
export async function bridgeDns(name: string, type: string): Promise<string[]> {
  const body = await callBridge<{ records: string[] }>('dns', { name, type });
  return body.records ?? [];
}

/** Registration data for a domain, from RDAP. */
export async function bridgeRdap(domain: string): Promise<{ lines: string[] }> {
  return callBridge<{ lines: string[] }>('rdap', { domain });
}

export interface TlsProbeResult {
  host: string;
  port: number;
  /** Whether the host resolves to Cloudflare's network (its TLS is terminated at the edge). */
  edge: 'cloudflare' | 'origin' | 'unknown';
  /** Whether HTTPS answered with a certificate the Worker's TLS stack trusts. */
  httpsOk: boolean;
  /** Whether plain HTTP redirects to HTTPS (null when port 80 did not answer). */
  httpRedirectsToHttps: boolean | null;
  /** The Strict-Transport-Security header, if any. */
  hsts: string | null;
  certificate?: { subject?: string; issuer?: string; notBefore?: string; notAfter?: string; san?: string[] };
  notes: string[];
}

/** A TLS posture check run by the Worker: HTTPS and HTTP GETs, HSTS, and the CT-logged certificate. */
export async function bridgeTlsProbe(host: string, port: number): Promise<TlsProbeResult> {
  return callBridge<TlsProbeResult>('tls', { host, port: String(port) }, 30_000);
}
