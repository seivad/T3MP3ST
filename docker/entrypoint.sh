#!/bin/sh
# Starts the defensive API as the unprivileged `node` user.
#
# In a Cloudflare Sandbox the runtime intercepts outbound HTTPS with an ephemeral CA it writes to
# /etc/cloudflare/certs after the container starts. With T3MP3ST_WAIT_FOR_CA=1 (set by the
# Durable Object) this waits for it and adds it to the system store (git, osv-scanner) before
# anything makes a request; Node reads it through NODE_EXTRA_CA_CERTS.
set -eu

ca=/etc/cloudflare/certs/cloudflare-containers-ca.crt
if [ "${T3MP3ST_WAIT_FOR_CA:-0}" = "1" ]; then
	tries=0
	while [ ! -s "$ca" ]; do
		tries=$((tries + 1))
		if [ "$tries" -gt 300 ]; then
			echo "entrypoint: $ca did not appear; outbound HTTPS will fail" >&2
			break
		fi
		sleep 0.1
	done
	if [ -s "$ca" ]; then
		cp "$ca" /usr/local/share/ca-certificates/cloudflare-containers-ca.crt
		update-ca-certificates >/dev/null 2>&1 || true
		export NODE_EXTRA_CA_CERTS="$ca"
	fi
fi

mkdir -p "${T3MP3ST_WORK_ROOT:-/work}"
chown node:node "${T3MP3ST_WORK_ROOT:-/work}"
exec setpriv --reuid=node --regid=node --init-groups --no-new-privs -- node /opt/t3mp3st/dist/server.js
