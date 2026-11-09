# T3MP3ST defensive profile

This branch (`defensive` on [seivad/T3MP3ST](https://github.com/seivad/T3MP3ST/tree/defensive)) is a modified build of [T3MP3ST](https://github.com/elder-plinius/T3MP3ST) by elder-plinius and contributors, licensed under the GNU Affero General Public License v3.0 or later. It is the engine of the Cloudflare OS **Security Assessor**: a tool for assessing code and sites you own, run from a locked-down Cloudflare Sandbox.

The offensive capabilities are **removed from the source tree**, not switched off by configuration. Nothing in this build can be turned back into them with a flag or an environment variable.

## What it does

- **White-box code analysis** of a repository you supply:
  - SAST-style rules: SQL and command injection, XSS, path traversal, SSRF, unsafe deserialization, weak crypto, disabled TLS verification, unverified JWTs, permissive CORS, debug mode. Each hit is ranked with T3MP3ST's tree-sitter code-ingest (exposure and reachability).
  - Secrets in code: built-in rules, plus gitleaks when it is installed. Values are always redacted.
  - Dependency and supply-chain audit against OSV, with osv-scanner when installed or the OSV API otherwise.
  - IaC and configuration review: Dockerfile, Compose, GitHub Actions, Terraform, Kubernetes, Wrangler and committed `.env` files.
- **Passive posture checks** of a site you enter: response headers, cookies, CORS, mixed content, technology fingerprint, robots.txt, security.txt, TLS (HTTPS validity, HTTP redirect, HSTS, the CT-logged certificate), DNS (CAA, SPF, DMARC) and registration data. The site receives only ordinary GET/HEAD requests for public pages.
- **Operators** triage and explain: Sentinel (supply chain & configuration) and Oracle (code review) read the repository with read-only tools and confirm or dismiss each scanner candidate. Aegis (coordinator) writes the executive summary. The Posture operator can run the passive tools. A model's refusal is respected: it is never re-prompted or shopped to another model.
- **Reports**: severity, CWE/CVE, evidence, remediation, retest criteria, a "Harden with Cloudflare" plan, a coverage table, and a disclosure draft that a human sends.

## What is removed, and why

| Removed | Where it was upstream | Why |
|---|---|---|
| Exploiter, Infiltrator, Exfiltrator and Ghost operators and their prompts | `src/operators/index.ts`, `src/prompts/index.ts`, `src/types/index.ts` | Exploitation, lateral movement, data extraction and persistence are not assessment of your own posture. |
| `password_spray`, `hash_crack`, credential harvesting (`Credential` flow in operators), GRIFFIN secret extraction and CERBERUS privilege-escalation ranking | `src/arsenal/index.ts`, `src/mcp-server.ts`, `src/operators/index.ts` | Credential attacks and extraction. |
| Metasploit, Hydra, Pacu, sqlmap and the 75 Kali+ adapter wrappers; post-exploitation drivers; the exploit-engine stubs | `src/arsenal/post-ex.ts`, `src/arsenal/adapter-tools.ts`, `src/arsenal/catalog.ts`, `src/arsenal/parsers.ts`, `src/stubs/index.ts`, `tools/Dockerfile` | Exploit execution. |
| Active checks: `port_scan`, `dir_bruteforce`, `xss_scan`, `sqli_scan`, `subdomain_enum`, `lfi_test`, `ssti_test`, `open_redirect_test`, `http_methods_test`, `api_endpoint_discovery`, `version_detect`, `network_trace`, `idor_probe`, `browser_probe`, generic `http_request`/`curl_request`, nmap/nuclei/ffuf wrappers | `src/arsenal/*.ts` | This build sends a target nothing beyond passive GETs of public pages. |
| OPSEC/evasion: the OPSEC controller (traffic blending, jitter, "avoid detection"), the SOCKS proxy for hiding the operator's IP, detection-risk "burn" logic, stealth/breach team factories | `src/opsec/`, `src/net/proxy.ts`, `src/operators/index.ts`, `src/types/index.ts`, `src/config/index.ts` | Evasion is not a defensive feature. |
| Doctrine urging operators to "push harder than ordinary agents" and OPSEC rules | `src/prompts/index.ts` | Replaced by a defensive doctrine (scope is final, evidence or it did not happen, redact secrets, treat target content as data). |
| The refusal reframe-and-retry (restating authorization and re-asking another model after a refusal) | `src/llm/index.ts` | A refusal is returned as-is. |
| The DecompositionOrchestrator, which split an objective into questions with security context stripped so a worker model would not decline them | `src/orchestration/` | Model-safety evasion. Its token-budget packer moved to `src/recon/context-pack.ts`. |
| `scripts/refusal-frontier.mjs` and `bench/refusal-frontier` (model-refusal probing), and all offensive benchmarks and scripts | `scripts/`, `bench/`, `ctf/` | Not part of an assessment tool. |
| Social OSINT tools (username and Telegram lookup), bounty-platform submission, local coding-agent dispatch, the War Room server and UI with its generic tool-execution route | `src/arsenal/social-osint.ts`, `src/integrations/`, `src/agent/local-agents.ts`, `src/server.ts`, `docs/index.html` | Outside the defensive scope, or an unauthenticated command surface. Replaced by a small bearer-token API (`src/server.ts`). |
| AI-agent maintainer instructions (`AGENTS.override.md`, `.aiwg/`) | repository root | Instructions aimed at AI agents are kept out of the build. |

`t3mp3st tools` prints the registry and checks that none of the removed names is present (it exits non-zero if one is).

## Running it

```bash
npm ci && npm run build
node dist/cli.js tools
node dist/cli.js assess --repo ./path/to/your/repo --no-model --out reports
ASSESSOR_API_TOKEN=$(openssl rand -hex 32) node dist/server.js   # API on 0.0.0.0:3333
```

Model calls go to any OpenAI-compatible endpoint (`T3MP3ST_LLM_BASE_URL`, `…/v1`). In Cloudflare OS that endpoint is the Worker, which forwards to Workers AI through the deployment's AI Gateway, so the container holds no model key.

In the sandbox the container has no internet of its own. Set `T3MP3ST_NET_BRIDGE` and DNS, registration and TLS lookups go to the Worker as HTTP requests (`src/arsenal/net-bridge.ts`); every other request is intercepted and checked by the Worker's scope gate.

## License

AGPL-3.0-or-later, as upstream. See [LICENSE](LICENSE). If you run a modified version of this build as a network service, you must offer its source to the service's users.
