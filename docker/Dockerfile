# Isolated security-audit harness for grokbot-headless.
# Clones upstream FRESH inside the image — do not treat the host checkout alone as the audit subject.
# Does NOT deploy to Pi/Mac. Does NOT enable routing / reverse-tunnel dialer.
#
# Stages:
#   audit-base     — Node 22 + git/rg/jq tooling
#   audit-upstream — clones https://github.com/andreanjos/grokbot-headless.git into /src/upstream
#   audit-compat   — host-mounted fork + official package for check --local / unit tests
#
# Build context: repository root (parent of docker/).

FROM node:22-bookworm-slim AS audit-base

RUN apt-get update \
  && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    git \
    ripgrep \
    jq \
    binutils \
    xz-utils \
    python3 \
    findutils \
    file \
  && rm -rf /var/lib/apt/lists/*

WORKDIR /src

# ---------------------------------------------------------------------------
# Stage: clone upstream at build time (immutable audit subject)
# ---------------------------------------------------------------------------
FROM audit-base AS audit-upstream

ARG UPSTREAM_REPO=https://github.com/andreanjos/grokbot-headless.git
ARG UPSTREAM_REF=main

RUN mkdir -p /src/upstream /out/reports \
  && git clone --depth 50 --branch "${UPSTREAM_REF}" "${UPSTREAM_REPO}" /src/upstream \
  && git -C /src/upstream rev-parse HEAD > /src/upstream.COMMIT \
  && git -C /src/upstream log -1 --format='%H %ci %s' > /src/upstream.LOG \
  && echo "Cloned upstream $(cat /src/upstream.COMMIT)"

WORKDIR /src/upstream

# Default: print clone identity then sleep so compose/run can exec audit scripts.
# Override command to run static analysis.
CMD ["bash", "-lc", "echo UPSTREAM=$(cat /src/upstream.COMMIT); cat /src/upstream.LOG; ls -la /src/upstream; exec sleep infinity"]

# ---------------------------------------------------------------------------
# Stage: compat / unit-test harness (optional bind-mount of host fork)
# ---------------------------------------------------------------------------
FROM audit-base AS audit-compat

WORKDIR /opt/grokbot-headless

# Fallback COPY when not bind-mounted; compose normally mounts the host fork.
COPY grok-bot-headless.mjs package.json ./
COPY bin ./bin
COPY test ./test
COPY install.sh uninstall.sh grok-bot-headless.service README.md SECURITY.md LICENSE ./

ENV GROK_BOT_HEADLESS_CONFIG_DIR=/data/config \
    SAND_DATA_ROOT=/data/share \
    NODE_ENV=production

RUN mkdir -p /data/config /data/share /opt/grok-bot-official /out/reports \
  && chmod 0700 /data/config /data/share

VOLUME ["/data", "/opt/grok-bot-official", "/opt/grokbot-headless", "/out"]

CMD ["node", "--test", "test/controller.test.mjs", "test/cli.test.mjs"]
