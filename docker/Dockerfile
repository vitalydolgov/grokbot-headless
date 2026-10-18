# Audit / version-compat harness for grokbot-headless.
# Does NOT deploy to Pi/Mac. Does NOT enable routing / reverse-tunnel dialer.
# Build context: repository root (parent of docker/).
FROM node:22-bookworm-slim

RUN apt-get update \
  && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    binutils \
    xz-utils \
    python3 \
  && rm -rf /var/lib/apt/lists/*

# systemd user sessions are not practical in a default container; run the
# controller in the foreground (grok-bot-headless run) for audit smoke tests.
WORKDIR /opt/grokbot-headless

# Repo is normally bind-mounted over this path; COPY is a fallback for image builds.
COPY grok-bot-headless.mjs package.json ./
COPY bin ./bin
COPY test ./test
COPY install.sh uninstall.sh grok-bot-headless.service README.md SECURITY.md LICENSE ./

ENV GROK_BOT_HEADLESS_CONFIG_DIR=/data/config \
    SAND_DATA_ROOT=/data/share \
    NODE_ENV=production

RUN mkdir -p /data/config /data/share /opt/grok-bot-official \
  && chmod 0700 /data/config /data/share

VOLUME ["/data", "/opt/grok-bot-official", "/opt/grokbot-headless"]

# Default: unit tests only (no OAuth, no official package required).
CMD ["node", "--test", "test/controller.test.mjs", "test/cli.test.mjs"]
