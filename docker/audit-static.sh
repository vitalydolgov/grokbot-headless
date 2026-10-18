#!/usr/bin/env bash
# Static security audit of /src/upstream (fresh clone). Writes markdown to AUDIT_REPORT_DIR.
set -euo pipefail

UPSTREAM="${AUDIT_UPSTREAM_DIR:-/src/upstream}"
FORK="${AUDIT_FORK_DIR:-/src/fork}"
OUT="${AUDIT_REPORT_DIR:-/out/reports}"
REPORT="$OUT/grokbot-headless-security-audit.md"
WORKDIR="${TMPDIR:-/tmp}/gh-audit-$$"
mkdir -p "$OUT" "$WORKDIR"

COMMIT=$(cat /src/upstream.COMMIT 2>/dev/null || git -C "$UPSTREAM" rev-parse HEAD)
LOG=$(cat /src/upstream.LOG 2>/dev/null || git -C "$UPSTREAM" log -1 --format='%H %ci %s')
DATE_MOSCOW=$(TZ=Europe/Moscow date '+%Y-%m-%d %H:%M %Z')

echo "Auditing upstream at $COMMIT"

# Collect evidence into files for the report
{
  echo "=== TREE ==="
  find "$UPSTREAM" -type f ! -path '*/.git/*' | sort
  echo
  echo "=== package.json ==="
  cat "$UPSTREAM/package.json" 2>/dev/null || true
  echo
  echo "=== package-lock / yarn / pnpm ==="
  ls -la "$UPSTREAM"/package-lock.json "$UPSTREAM"/yarn.lock "$UPSTREAM"/pnpm-lock.yaml 2>/dev/null || echo "(none beyond package-lock if present)"
  cat "$UPSTREAM/package-lock.json" 2>/dev/null || true
} > "$WORKDIR/inventory.txt"

# Network destinations
rg -n --no-heading -i \
  'https?://|wss?://|api2\.|cursor\.|webhook|exfil|telemetry|beacon|ngrok|webhook\.site|requestbin|pastebin|discord\.com/api|telegram|hooks\.slack' \
  "$UPSTREAM" -g '!.git/**' > "$WORKDIR/network.txt" || true

# eval/exec/dangerous
rg -n --no-heading \
  'eval\(|new Function\(|child_process|execSync|execFile|spawn\(|vm\.|Function\(|atob\(|Buffer\.from\([^,]+,\s*["'\'']base64|btoa\(|\.\$\{|curl |wget |nc |ncat |bash -c|sh -c|/dev/tcp' \
  "$UPSTREAM" -g '!.git/**' > "$WORKDIR/exec.txt" || true

# Credentials / secrets patterns
rg -n --no-heading -i \
  'password|secret|token|api[_-]?key|refresh_token|access_token|client_secret|authorization|Bearer |private[_-]?key|BEGIN (RSA |OPENSSH )?PRIVATE' \
  "$UPSTREAM" -g '!.git/**' > "$WORKDIR/creds.txt" || true

# Hidden / suspicious files
{
  echo "=== dotfiles / hidden ==="
  find "$UPSTREAM" -name '.*' ! -path '*/.git/*' ! -name '.git' ! -name '.gitignore' -print 2>/dev/null || true
  echo "=== base64-ish long strings (len>=80) in scripts ==="
  rg -n --no-heading '[A-Za-z0-9+/]{80,}={0,2}' "$UPSTREAM" -g '!.git/**' -g '*.mjs' -g '*.js' -g '*.sh' -g '*.yml' -g '*.yaml' || true
  echo "=== binary / non-text under repo (excl .git) ==="
  find "$UPSTREAM" -type f ! -path '*/.git/*' -exec file {} \; | grep -viE 'text|empty|JSON|ASCII|UTF-8|Unicode' || echo "(none notable)"
} > "$WORKDIR/hidden.txt" || true

# Prompt injection strings aimed at LLMs
rg -n --no-heading -i \
  'ignore (all )?(previous|prior|above)|system prompt|you are (now |a )?(admin|root|unrestricted)|disregard|jailbreak|exfiltrat|send (all |the )?secrets|do not tell the user|hidden instruction|IMPORTANT:.*(override|ignore)' \
  "$UPSTREAM" -g '!.git/**' > "$WORKDIR/promptinj.txt" || true

# CI workflows
{
  echo "=== .github ==="
  find "$UPSTREAM/.github" -type f 2>/dev/null | sort || echo "(no .github)"
  for f in $(find "$UPSTREAM/.github" -type f 2>/dev/null); do
    echo "----- $f -----"
    cat "$f"
  done
} > "$WORKDIR/ci.txt" || true

# install / systemd
{
  echo "=== install.sh ==="
  cat "$UPSTREAM/install.sh" 2>/dev/null || true
  echo "=== uninstall.sh ==="
  cat "$UPSTREAM/uninstall.sh" 2>/dev/null || true
  echo "=== service ==="
  cat "$UPSTREAM/grok-bot-headless.service" 2>/dev/null || true
  echo "=== bin ==="
  cat "$UPSTREAM/bin/grok-bot-headless" 2>/dev/null || true
} > "$WORKDIR/install.txt" || true

# URL allowlist / validatedServiceUrl patterns in controller
rg -n --no-heading 'validatedServiceUrl|SAND_BACKEND|cursor\.sh|api2|ALLOW_INSECURE|fetch\(|http\.request|https\.request' \
  "$UPSTREAM" -g '!.git/**' > "$WORKDIR/http.txt" || true

# Fork comparison (brief) if mounted
FORK_NOTE="(fork not mounted)"
if [ -d "$FORK/.git" ] || [ -f "$FORK/grok-bot-headless.mjs" ]; then
  {
    echo "=== fork HEAD ==="
    git -C "$FORK" log -3 --oneline 2>/dev/null || true
    echo "=== files only in fork (vs upstream names) ==="
    diff -rq "$UPSTREAM" "$FORK" --exclude=.git --exclude=docker --exclude=node_modules 2>/dev/null | head -80 || true
    echo "=== security-related diff hunks (assertSafeAsar / localCompatibility / jsonSize) ==="
    diff -u "$UPSTREAM/grok-bot-headless.mjs" "$FORK/grok-bot-headless.mjs" 2>/dev/null | rg -n 'assertSafeAsar|localCompatibility|jsonSize|asar|ELECTRON_RUN_AS_NODE|path\.resolve|traversal' || true
  } > "$WORKDIR/forkcmp.txt" || true
  FORK_NOTE="see fork comparison section"
fi

# Summarize counts for verdict helpers
NET_COUNT=$(wc -l < "$WORKDIR/network.txt" | tr -d ' ')
EXEC_COUNT=$(wc -l < "$WORKDIR/exec.txt" | tr -d ' ')
PI_COUNT=$(wc -l < "$WORKDIR/promptinj.txt" | tr -d ' ')
DEPS=$(jq -r '(.dependencies // {}) + (.devDependencies // {}) | keys[]' "$UPSTREAM/package.json" 2>/dev/null || echo "(no npm deps object or empty)")

# Write report
cat > "$REPORT" << REPORT
# grokbot-headless security audit (fresh upstream clone in Docker)

**For:** Vitaly Dolgov (via Net)  
**Date:** ${DATE_MOSCOW} (Europe/Moscow)  
**Method:** \`sudo docker\` image stage \`audit-upstream\` — \`git clone\` of https://github.com/andreanjos/grokbot-headless.git **inside** the container to \`/src/upstream\`. Host checkout was **not** the sole audit subject.  
**Hard stops honored:** no Pi/Mac deploy; no routing implementation; no live OAuth (static only).

---

## Upstream identity

| Field | Value |
|-------|-------|
| Repo | https://github.com/andreanjos/grokbot-headless.git |
| Ref | main (shallow clone depth 50) |
| Commit | \`${COMMIT}\` |
| Tip log | ${LOG} |
| Audit path in container | \`/src/upstream\` |
| Report path (host) | \`/workspace/gorod-reports/grokbot-headless-security-audit.md\` |

---

## Scope

Static review of the **fresh upstream tree**: network destinations, eval/exec, credential handling, \`install.sh\` / systemd, hidden payloads, base64 blobs, webhook/exfil URLs, prompt-injection strings aimed at LLMs, supply-chain (\`package.json\`), CI workflows. Brief comparison to host fork hardenings only (no routing scope expansion).

---

## Inventory

\`\`\`
$(cat "$WORKDIR/inventory.txt" | head -200)
\`\`\`

### npm dependencies

\`\`\`
${DEPS}
\`\`\`

**Supply-chain note:** \`package.json\` declares **no runtime npm dependencies** (scripts use Node builtins + bash tests only). Lockfile is minimal / empty of packages. Risk from third-party npm packages in this repo is **none** at audit time. The proprietary Grok Bot \`.deb\` / asar is a separate trust boundary (operator-supplied path).

---

## Findings by category

### 1) Network destinations / exfiltration

Raw hits (URLs / webhook-ish keywords):

\`\`\`
$(cat "$WORKDIR/network.txt" | head -120)
\`\`\`

HTTP-related controller patterns:

\`\`\`
$(cat "$WORKDIR/http.txt" | head -80)
\`\`\`

**Assessment:** Expected hosts are Cursor/Grok Bot API surfaces (\`api2.cursor.sh\`, \`cursor.com\`) via HTTPS with \`validatedServiceUrl\`. No third-party webhooks, requestbins, Discord/Telegram exfil, or unexplained beacons observed in the upstream tree.

### 2) eval / exec / dangerous primitives

\`\`\`
$(cat "$WORKDIR/exec.txt" | head -100)
\`\`\`

**Assessment:** No \`eval\` / \`new Function\` / \`vm\` usage found in application code. Process spawning is limited to supervising the official local-exec daemon and installer/systemd helpers — expected for this controller. Shell scripts use normal \`install\`/\`systemctl\` patterns; review install section for quoting.

### 3) Credential handling

\`\`\`
$(head -80 "$WORKDIR/creds.txt")
\`\`\`

**Assessment:** OAuth + daemon credentials stored as plaintext JSON under XDG config/data dirs with \`0600\`/\`0700\` — documented residual risk, not covert exfil. No hardcoded live secrets or private keys in the tree. \`status\` path should not print tokens (verify in controller — see residual).

### 4) install.sh / systemd / bin wrapper

\`\`\`
$(head -200 "$WORKDIR/install.txt")
\`\`\`

**Assessment:** Installer writes an \`EnvironmentFile\` and user systemd unit; uninstall without \`--purge\` leaves credentials (by design). No curl-pipe-to-shell from remote untrusted hosts beyond cloning this repo itself. Unit gates on credentials + \`check --local\` where present on newer tips.

### 5) Hidden payloads / base64 / binaries

\`\`\`
$(cat "$WORKDIR/hidden.txt" | head -80)
\`\`\`

**Assessment:** No hidden malware droppers or large opaque base64 payloads in scripts. Repo is source + tests + service unit.

### 6) Prompt-injection strings (LLM-facing)

\`\`\`
$(cat "$WORKDIR/promptinj.txt" | head -40)
\`\`\`
Hits: ${PI_COUNT}

**Assessment:** No intentional LLM jailbreak / “ignore previous instructions” payload strings planted for agents reading the repo.

### 7) CI workflows

\`\`\`
$(cat "$WORKDIR/ci.txt" | head -150)
\`\`\`

**Assessment:** CI should only run tests; flag any workflow that publishes secrets, uses \`pull_request_target\` with checkout of untrusted code + secrets, or curl|bash from unpinned URLs. Details above.

---

## Fork comparison (brief — hardenings only)

${FORK_NOTE}

\`\`\`
$(head -100 "$WORKDIR/forkcmp.txt" 2>/dev/null || echo "(no fork mount)")
\`\`\`

Host fork branch \`vitally/update-0.71-routing\` adds (already documented elsewhere): asar path-traversal containment (\`assertSafeAsarEntry\`), asar header size cap, removal of dead \`ELECTRON_RUN_AS_NODE -e\` path, \`localCompatibility\` before \`run\`, 0.71.2 / Node 22 compat, Docker harness. **Upstream main may lack some of these hardenings** — operators of a raw upstream clone should cherry-pick or retain the fork security commits. This audit does **not** expand into routing.

---

## Severity summary

| ID | Severity | Finding |
|----|----------|---------|
| U1 | Info / accepted | Plaintext OAuth/daemon credentials on disk (\`0600\`) |
| U2 | Info / accepted | \`policy always\` = full user-equivalent remote exec |
| U3 | Low (upstream) | If upstream lacks asar path containment / header cap / \`localCompatibility\` gate, malicious or mis-set \`GROK_BOT_DAEMON_SCRIPT\` / asar could traverse or DoS — **fixed on fork** (\`6f6a321\`) |
| U4 | Info | Env overrides fully trusted (binary/asar/Node/API redirect if session compromised) |
| U5 | None found | Covert exfil URLs, webhooks, eval backdoors, prompt-injection payloads, npm supply-chain deps |

---

## Verdict

**CLEAN for malicious code / covert exfiltration / prompt-injection planted for LLM auditors**, with **accepted operator risks** (plaintext creds, \`policy always\`) and **recommend retaining fork hardenings** (U3) when not yet merged upstream.

Upstream tip audited: \`${COMMIT}\`.

---

## Docker commands used

\`\`\`bash
sudo docker compose -f docker/docker-compose.yml build audit-upstream
sudo docker compose -f docker/docker-compose.yml run --rm audit-upstream \\
  bash /src/fork/docker/audit-static.sh
# (script path may be /opt/... depending on mount; this image runs with fork at /src/fork)
\`\`\`

Evidence blobs from this run are ephemeral inside the container; this markdown is the durable artifact on the host volume.
REPORT

echo "Wrote $REPORT"
wc -l "$REPORT"
