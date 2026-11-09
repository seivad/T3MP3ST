/**
 * The defensive build's capability registry: every tool and operator it ships, and the upstream
 * capabilities it does not. `t3mp3st tools` prints it and the image check asserts on it.
 */

import { BUILTIN_TOOLS } from '../arsenal/index.js';
import { REPO_TOOL_NAMES } from '../arsenal/repo-tools.js';
import { ARCHETYPE_PROFILES } from '../operators/index.js';

/** Upstream T3MP3ST capabilities that are not in this build, by name. */
export const REMOVED_CAPABILITIES = [
  // operators
  'exploiter', 'infiltrator', 'exfiltrator', 'ghost',
  // credential attacks and extraction
  'password_spray', 'hash_crack', 'griffin', 'cerberus',
  // exploitation / post-exploitation drivers
  'metasploit', 'msfconsole', 'hydra', 'pacu', 'sqlmap_tool', 'post_ex', 'exploit_chain',
  // active checks (out of this build: passive posture only)
  'port_scan', 'dir_bruteforce', 'xss_scan', 'sqli_scan', 'nmap_scan', 'nuclei_scan', 'ffuf_fuzz',
  'subdomain_enum', 'lfi_test', 'ssti_test', 'open_redirect_test', 'http_methods_test', 'api_endpoint_discovery',
  'idor_probe', 'browser_probe', 'http_request', 'curl_request', 'version_detect', 'network_trace',
  // evasion / OSINT on people / model-refusal probing
  'opsec', 'socks_proxy', 'traffic_blending', 'username_search', 'telegram_lookup', 'refusal_frontier', 'decomposition_orchestrator',
] as const;

export interface RegistryListing {
  build: 'defensive';
  tools: Array<{ name: string; category: string; riskTier: string; description: string }>;
  operators: Array<{ archetype: string; name: string; tools: string[] }>;
  removed: readonly string[];
}

export function registryListing(): RegistryListing {
  return {
    build: 'defensive',
    tools: [
      ...BUILTIN_TOOLS.map((t) => ({ name: t.name, category: t.category, riskTier: t.riskTier ?? 'unknown', description: t.description })),
      ...REPO_TOOL_NAMES.map((name) => ({ name, category: 'code', riskTier: 'local_read', description: 'Read-only access to the repository under review' })),
    ],
    operators: Object.entries(ARCHETYPE_PROFILES).map(([archetype, p]) => ({ archetype, name: p.name, tools: [...p.tools] })),
    removed: REMOVED_CAPABILITIES,
  };
}

/** Names from REMOVED_CAPABILITIES that are present in the registry (must be empty). */
export function presentRemovedCapabilities(listing: RegistryListing = registryListing()): string[] {
  const present = new Set([...listing.tools.map((t) => t.name.toLowerCase()), ...listing.operators.map((o) => o.archetype.toLowerCase())]);
  return REMOVED_CAPABILITIES.filter((name) => present.has(name));
}
