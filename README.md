# T3MP3ST, defensive profile

A defensive build of [T3MP3ST](https://github.com/elder-plinius/T3MP3ST) for assessing systems **you own**: white-box analysis of your repositories (SAST-style rules, secrets, dependency audit, IaC review) and passive posture checks of your sites, triaged by T3MP3ST operators and written up with remediation, retest criteria and a "Harden with Cloudflare" plan.

It is the engine of the Cloudflare OS **Security Assessor** (`packages/security-assessor` in a Cloudflare OS deployment), which runs it in a locked-down Cloudflare Sandbox behind Cloudflare Access.

**Read [DEFENSIVE.md](DEFENSIVE.md)** for what it does, what was removed from upstream and why. The exploitation, credential-attack, exfiltration, evasion and active-scanning capabilities of upstream T3MP3ST are deleted from this branch, not disabled.

```bash
npm ci && npm run build
node dist/cli.js tools                                   # the capability registry
node dist/cli.js assess --repo ./my-app --no-model       # deterministic scanners only
node dist/cli.js assess --repo ./my-app --llm-base-url http://localhost:11434/v1 --model qwen2.5-coder
npm test
```

## License

GNU Affero General Public License v3.0 or later, as upstream ([LICENSE](LICENSE)). Copyright the T3MP3ST contributors; modifications in this branch by the Cloudflare OS Security Assessor maintainers. Upstream source: https://github.com/elder-plinius/T3MP3ST. This branch: https://github.com/seivad/T3MP3ST/tree/defensive.
