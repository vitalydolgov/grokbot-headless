# Security

Do not put OAuth tokens, daemon credentials, machine files, or full service logs in a public issue.

Report a security problem through GitHub private vulnerability reporting for this repository. If that option is unavailable, contact the repository owner through the private contact method shown on the GitHub profile.

Before you share logs, remove authorization headers, OAuth values, credential fields, machine IDs, email addresses, and local file contents.

## Operator warnings

- The `always` policy permits remote commands without individual approval. Use it only on a host and account that you intend to expose to Grok Bot. Prefer `ask`.
- OAuth and daemon credentials are stored as plaintext JSON under `~/.config/grok-bot-headless` and `~/.local/share/grok-bot-headless` (mode `0600` files, `0700` dirs). Protect the Linux account, home directory, backups, and any process that can read that user.
- Environment overrides (`GROK_BOT_BINARY`, `GROK_BOT_DAEMON_SCRIPT`, `GROK_BOT_NODE_BINARY` / `SAND_NODE_BINARY`, `SAND_BACKEND_URL`, `SAND_AUTH_CLIENT_ID`, `SAND_DATA_ROOT`) are trusted as local configuration. A compromised user session can redirect the controller at a malicious binary, asar, Node runtime, or API endpoint.
- This project is an unofficial management layer around the proprietary Grok Bot `local-exec-daemon`. It does not implement desktop Auto-review UI; remote tool policy is whatever you register with `policy` plus backend ceilings.
- `check --local` only verifies package layout / daemon entry structural presence. It is not an authentication or policy audit.
- Uninstall without `--purge` leaves credentials on disk by design.

## Review note

A third-party security review of this tree (auth, credentials, install/systemd, network, IPC, policy defaults, path handling) was performed 2026-10-19 for a local fork update. Findings and residual risks for operators are summarized in the companion report outside this repo when available; upstream maintainers should treat any such review as advisory, not a certification.

## Reverse tunnel / CONNECT dialer

- The headless reverse-tunnel client reuses account OAuth to call `EnsureSandBox` for `gatewayUrl` / `gatewayToken` (or operator-supplied `GROK_BOT_TUNNEL_*`). Tokens are not printed by `status`.
- Only **one** dialer should hold the box tunnel. Default attach is `if-free`; `--claim` contests ownership and can displace another computer (including a Mac with Settings → Route traffic enabled). Coordinate operators before claiming.
- Private/link-local destinations are refused by default (`allowPrivateTargets: false`). Do not enable `--allow-private` unless you understand SSRF/lateral-movement risk from box-originated CONNECTs.
- This path does **not** weaken local-exec Auto-review or execution policy. Prefer `policy ask`.
- Unit tests use a **fake** WS peer only; do not point CI at a live box.
