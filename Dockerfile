# T3MP3ST defensive profile: the assessment API (port 3333) with git, gitleaks and osv-scanner.
# No exploitation or scanning tools are installed, and nothing needs raw sockets.
#
#   docker build --platform linux/amd64 -t t3mp3st-defensive .
#   docker run --rm -e ASSESSOR_API_TOKEN=$(openssl rand -hex 32) -p 127.0.0.1:3333:3333 t3mp3st-defensive

FROM node:24.22.2-trixie-slim@sha256:0820eaa85e07d0490446dd01d14707e17e6108a36988cf374899cd057eb3812d AS build
WORKDIR /src
COPY package.json package-lock.json tsconfig.json tsconfig.build.json ./
RUN npm ci --ignore-scripts --no-audit --no-fund
COPY src ./src
RUN npm run build && npm prune --omit=dev --ignore-scripts

FROM node:24.22.2-trixie-slim@sha256:0820eaa85e07d0490446dd01d14707e17e6108a36988cf374899cd057eb3812d

ARG TARGETARCH
ARG GITLEAKS_VERSION=8.30.1
ARG GITLEAKS_SHA256_AMD64=551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb
ARG GITLEAKS_SHA256_ARM64=e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080
ARG OSV_SCANNER_VERSION=2.7.0
ARG OSV_SCANNER_SHA256_AMD64=160c6253e2922e9e0a6a9771c5c4c40a4b3c6090b34a3cdd5e80c96cc2e4218b
ARG OSV_SCANNER_SHA256_ARM64=4061ef4c021ed3c47f203b818f337e351336cc5cd67c0274fc36bd1dfc728dd7

RUN apt-get update \
	&& apt-get install -y --no-install-recommends ca-certificates curl git \
	&& rm -rf /var/lib/apt/lists/*

# Pinned scanners, each verified against its release checksum before it is installed.
RUN set -eu; \
	case "${TARGETARCH:-amd64}" in \
		amd64) gl_arch=x64; gl_sum=$GITLEAKS_SHA256_AMD64; osv_arch=amd64; osv_sum=$OSV_SCANNER_SHA256_AMD64 ;; \
		arm64) gl_arch=arm64; gl_sum=$GITLEAKS_SHA256_ARM64; osv_arch=arm64; osv_sum=$OSV_SCANNER_SHA256_ARM64 ;; \
		*) echo "unsupported architecture $TARGETARCH" >&2; exit 1 ;; \
	esac; \
	curl -fsSL -o /tmp/gitleaks.tgz "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_${gl_arch}.tar.gz"; \
	echo "${gl_sum}  /tmp/gitleaks.tgz" | sha256sum -c -; \
	tar -xzf /tmp/gitleaks.tgz -C /usr/local/bin gitleaks; \
	curl -fsSL -o /usr/local/bin/osv-scanner "https://github.com/google/osv-scanner/releases/download/v${OSV_SCANNER_VERSION}/osv-scanner_linux_${osv_arch}"; \
	echo "${osv_sum}  /usr/local/bin/osv-scanner" | sha256sum -c -; \
	chmod 0755 /usr/local/bin/gitleaks /usr/local/bin/osv-scanner; \
	rm -f /tmp/gitleaks.tgz; \
	gitleaks version; osv-scanner --version

COPY --from=build /src/package.json /opt/t3mp3st/package.json
COPY --from=build /src/node_modules /opt/t3mp3st/node_modules
COPY --from=build /src/dist /opt/t3mp3st/dist
COPY docker/entrypoint.sh /usr/local/bin/t3mp3st-entrypoint
RUN ln -s /opt/t3mp3st/dist/cli.js /usr/local/bin/t3mp3st && chmod 0755 /opt/t3mp3st/dist/cli.js

ENV NODE_ENV=production \
	T3MP3ST_HOST=0.0.0.0 \
	T3MP3ST_PORT=3333 \
	T3MP3ST_WORK_ROOT=/work

EXPOSE 3333
ENTRYPOINT ["/usr/local/bin/t3mp3st-entrypoint"]
