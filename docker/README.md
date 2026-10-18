# Docker audit harness (no deploy, no routing)

Purpose: run **grokbot-headless** unit tests and `check --local` against an official
Linux package tree inside a Linux container. This is **not** a Pi/Mac deploy path
and does **not** implement Settings → Route traffic / reverse-tunnel dialer.

## Requirements

- Docker Engine + Compose v2 on the machine that builds
- This repository
- Optional: unpacked `grok-bot_*.deb` under `/workspace/grokbot-headless-research/`

systemd user units are **not** used here; run the CLI in the foreground.

## Build and test

From the repository root:

```bash
docker compose -f docker/docker-compose.yml build
docker compose -f docker/docker-compose.yml run --rm audit
```

## Local compatibility against an unpacked .deb

```bash
docker compose -f docker/docker-compose.yml run --rm audit \
  node grok-bot-headless.mjs check --local
```

Mounts expect `grokbot-headless-research/deb-amd64/data/opt/Grok Bot` (or edit the
compose volume). For arm64, point the volume at `deb-arm64/...` instead (binaries
will not execute on an amd64 Docker host; `check --local` still validates asar layout).

## What this deliberately skips

- Installing packages on a Raspberry Pi or Mac
- OAuth login against a live account (unless you inject credentials yourself)
- Routing / `sand-egress-tunnel` / ports 8790–8791 dialer
