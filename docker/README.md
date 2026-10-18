# Docker audit harness (no deploy, no routing)

Purpose:
1. **audit-upstream** — clone `andreanjos/grokbot-headless` **fresh inside the image** at `/src/upstream` and run static security analysis (do not trust only the host checkout).
2. **audit-compat** — unit tests / `check --local` against the host fork + official package (prefer a Docker volume, not a long-lived host research dump).

This is **not** a Pi/Mac deploy path and does **not** implement Settings → Route traffic / reverse-tunnel dialer.

## Requirements

- Docker Engine (`sudo docker`; Compose v2 plugin optional — examples use `docker build` / `docker run`)
- Network to GitHub for the upstream clone at **build** time
- Optional: official Grok Bot Linux package tree in a Docker volume (e.g. `grokbot-official-0.71.2`)

## Build and inspect upstream clone

From the repository root:

```bash
sudo docker build --target audit-upstream \
  -t grokbot-headless-audit-upstream:local \
  -f docker/Dockerfile .

sudo docker run --rm grokbot-headless-audit-upstream:local \
  bash -lc 'cat /src/upstream.COMMIT /src/upstream.LOG; ls -la /src/upstream'
```

Static audit (writes `/workspace/gorod-reports/grokbot-headless-security-audit.md`):

```bash
sudo docker run --rm \
  -v /workspace/gorod-reports:/out/reports:rw \
  -v "$PWD":/src/fork:ro \
  -e AUDIT_REPORT_DIR=/out/reports \
  grokbot-headless-audit-upstream:local \
  bash /src/fork/docker/audit-static.sh
```

## Compat / unit tests (fork + official package)

```bash
sudo docker build --target audit-compat \
  -t grokbot-headless-audit-compat:local \
  -f docker/Dockerfile .

sudo docker run --rm \
  -v "$PWD":/opt/grokbot-headless:rw \
  -v grokbot-official-0.71.2:/opt/grok-bot-official:ro \
  -e GROK_BOT_BINARY=/opt/grok-bot-official/grok-bot \
  -e GROK_BOT_DAEMON_SCRIPT=/opt/grok-bot-official/resources/app.asar/dist/local-exec-daemon/main.cjs \
  grokbot-headless-audit-compat:local
```

`docker-compose.yml` is provided for environments that have the Compose plugin; on this box use `docker build` / `docker run` as above.

## What this deliberately skips

- Installing packages on a Raspberry Pi or Mac
- Live OAuth login (prefer static analysis)
- Routing / `sand-egress-tunnel` / ports 8790–8791 dialer
