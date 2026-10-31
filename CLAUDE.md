CLAUDE.md Project guidance for Claude Code when working on 
GhostShare. --- What This Is GhostShare is a standalone Go CLI that 
shares a file anonymously over the Tor network via a temporary onion 
service. One command, one .onion link. No accounts, no relay, no 
third-party service, no bundled Tor. Elevator pitch: ghostshare 
report.pdf → prints http://abc...xyz.onion/q3V9x.../report.pdf → 
recipient opens it in Tor Browser → file downloads → link dies. 
Positioning: This is not a general-purpose anonymous sharing tool and 
not an OnionShare competitor. It is a small, explicit, CLI-first tool 
for users who already know what Tor is and want to share a file 
through it with a single command. The user is expected to have Tor 
installed or running. That is a feature, not a bug — it keeps the 
binary small, the build trivial, and the trust boundary clear. 
GhostShare is a derivative of QuickShare — see Lineage & Attribution 
below. Where QuickShare serves a file over clearnet HTTP, GhostShare 
serves the same file over a Tor onion service, using the same daemon, 
token, and download-counting model. --- Lineage & Attribution 
GhostShare is a derivative work based on QuickShare by 
computerguymackay. The daemon model, control socket, 
download-counting semantics, flag surface, config layout, and much of 
the file-serving logic are inherited from QuickShare. GhostShare's 
contribution is the Tor transport: tor.go, the --external-tor path, 
onion-service lifecycle, and transport-aware warnings. Both projects 
are authored and hosted by computerguymackay. QuickShare remains the 
clearnet tool; GhostShare is the Tor-only sibling. They are not 
competitors — they are two answers to "share this file with one 
command," split on transport. Keeping them structurally aligned is an 
explicit goal so fixes can flow between them. Rules for contributors 
(including Claude Code): · Do not remove attribution. Keep the 
QuickShare reference in README.md, LICENSE, and this file. · Do not 
silently diverge. If you change inherited logic (download counting, 
daemon lifecycle, token format), note it in the commit message as 
[diverges from QuickShare] so the difference is traceable. · Prefer 
upstream-compatible changes. If a fix could reasonably go back to 
QuickShare, structure it so it could be cherry-picked. · Keep the 
LICENSE identical to QuickShare's. Both repos are under the same 
author; do not relicense one without the other. · Attribution string 
in --help and --version: must include based on QuickShare 
(github.com/computerguymackay/QuickShare). --- Core Principles 1. 
Tor-only, explicitly. No clearnet fallback. Ever. If the user doesn't 
have Tor, print a clear error with install instructions and exit. 
Don't silently degrade. 2. Unbundled Tor. Never add go-libtor or any 
embedded-Tor dependency. Use bine to talk to a user-provided Tor 
(running or spawned). Keep the binary small and CGO-free. 3. 
Anonymity is the point. Never write onion private keys to disk. Never 
log IPs. Ephemeral onion per daemon session. 4. Honesty over 
hand-waving. Tor ≠ file encryption. Always print the security 
warning. Never claim more privacy than we deliver. 5. Small scope, 
done well. Reject feature creep. v1 is deliberately tiny. A working 
small tool beats a half-finished big one. 6. CGO_ENABLED=0 must 
always work. This is a hard invariant. If a dependency breaks it, 
replace the dependency. 7. Stay aligned with QuickShare. Where logic 
is inherited, keep it structurally compatible so fixes flow both 
ways. --- Build & Test Commands ```bash
# Build — no CGO, fast, cross-compiles anywhere
CGO_ENABLED=0 go build -o ghostshare .
# Cross-compile examples (all work — no CGO)
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o 
ghostshare-linux-amd64 . GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go 
build -o ghostshare-darwin-arm64 . GOOS=windows GOARCH=amd64 
CGO_ENABLED=0 go build -o ghostshare-windows-amd64.exe .
# Unit tests (fast, no Tor, no network)
go test ./...
# Race detector
go test -race ./...
# Tor integration tests (opt-in, requires a working Tor)
GHOSTSHARE_TOR_TEST=1 go test -tags=tortest ./...
# Shorten daemon timers for local testing
GHOSTSHARE_GRACE=2s GHOSTSHARE_TICK=1s go test ./... ``` Build 
expectations: seconds, not minutes. Binary ~17 MB (~11.5 MB stripped with -ldflags='-s -w'); pure-Go SQLite and net/http account for most of it, and QuickShare is also ~17 MB. If a change makes 
the build slow or requires CGO, that's a regression — stop and fix 
it. --- Architecture ``` GhostShare/ ├── main.go # CLI entry, flag 
parsing, dispatch ├── config.go # ~/.ghostshare/config.toml load/save 
├── daemon.go # background daemon: lifecycle, auto-shutdown, restore 
├── tor.go # Tor detection, spawn, onion service (bine) ├── server.go 
# HTTP file server, token routing, download counting
├── store.go # SQLite state (shares survive restarts) ├── token.go # 
144-bit token generation ├── qr.go # QR code rendering (terminal + 
PNG) ├── control.go # CLI ↔ daemon socket protocol (line-delimited 
JSON) ├── paths.go # ~/.ghostshare/ path resolution ├── 
platform_unix.go # Unix domain socket for control channel └── 
platform_windows.go # Loopback TCP + key for Windows ``` This layout 
intentionally mirrors QuickShare's. tor.go is the only file that 
touches Tor. Everything else is transport-agnostic — which is easy to 
enforce because there is only one transport. --- Dependencies Package 
Purpose Notes github.com/cretz/bine Tor control, onion service API v3 
onions only modernc.org/sqlite SQLite Pure Go, no CGO. 
Non-negotiable. Matches QuickShare's "pure Go SQLite, no cgo" stance. 
github.com/skip2/go-qrcode QR codes Terminal + PNG 
github.com/BurntSushi/toml Config parsing Matches QuickShare's config 
format Forbidden: go-libtor, mattn/go-sqlite3, anything requiring 
CGO. If Claude Code proposes adding one of these, stop and ask. --- 
Tor Integration Rules 1. Detect, then spawn. On startup, in order:
   1. Try to connect to a running Tor's control port (127.0.0.1:9051, 
   cookie auth preferred). If it works, use it. 2. Else look for a 
   tor binary on PATH. If found, spawn it with a temp data dir, wait 
   for the control port to open, then use it. 3. Else print a clear 
   error with install instructions (Debian/Ubuntu, Fedora, macOS 
   Homebrew, Windows Tor Expert Bundle) and exit non-zero. Do not 
   fall back to clearnet.
2. Always v3 onions. tor.ListenConf{Version3: true, DiscardKey: true} on every Listen (bine v0.2.0 has no EnableV3). v2 is dead. 
3. Health-check before printing a link. After creating the onion, 
poll it through Tor's SOCKS proxy (127.0.0.1:9050) until it responds, 
timeout ~30s. Never print a link that doesn't yet resolve. 4. 
Teardown must be bulletproof. defer onion.Close() and a 
SIGINT/SIGTERM handler. If we spawned Tor, kill it. If we attached to 
a running Tor, leave it alone. No zombie processes, no leaked onion 
descriptors. 5. --external-tor is the default path, not an 
afterthought. The flag exists to make the intent explicit and to help 
with testing, but the code path it exercises is the primary one. 6. 
One onion per daemon session in v1. Per-share onions are v2. --- 
Security & Privacy Invariants · Never write onion private keys to 
disk. · Never log full tokens. First 8 characters only (same policy 
as QuickShare). · Never add a clearnet fallback. · Never claim the 
tool is "encrypted." It's anonymous transport. · Always print the 
security warning on every share (to stderr):
  ``` warning: Tor provides anonymity, not file encryption. Anyone 
  with this link can download the file. Encrypt sensitive files first 
  (e.g. `age -p file && ghostshare file.age`). ```
· Always include the Tor Browser requirement in the README and in 
ghostshare --help. Recipients must use Tor Browser (or curl 
--socks5-hostname). A normal browser cannot open a .onion. --- 
Download-Counting Semantics (match QuickShare exactly) · A completed 
full GET counts once, even if the same person downloads twice. · A 
broken transfer doesn't count. If they resume and finish, that counts 
once. · Range requests never count. · HEAD requests never count. · 
Count never exceeds --max-downloads. Concurrent downloads may both 
finish if racing on the last slot — acceptable. Copy this logic from 
QuickShare's server.go. Do not reinvent it. If it needs to change, 
change it in both repos. --- CLI Surface (v1 — do not expand without 
asking) ``` ghostshare <file> [flags] share a file, print onion link 
ghostshare list [-j|--json] show active shares ghostshare revoke 
<prefix> cancel a share (6+ char unique prefix) ghostshare stop stop 
the daemon (shares preserved in DB) ghostshare tor-status report 
whether Tor is reachable (running / spawnable / missing) ``` Flags: 
-m/--max-downloads, -e/--expires, -i/--interactive, -q/--qr, 
-o/--qr-out, -j/--json, -f/--watch, --external-tor. Flag names, short 
aliases, and semantics match QuickShare wherever the concept exists 
(no --wan, --bind, --tls, or --allow-forever — Tor replaces the first 
three, and --allow-forever is out of scope for v1). stdout is sacred: 
only the link (or JSON with -j) goes to stdout. All warnings, 
summaries, QR codes → stderr. This must work: ```bash 
link=$(ghostshare build.tar.gz --json | jq -r .url) ``` ghostshare 
tor-status is new and worth adding: it lets users debug "why doesn't 
ghostshare work" without reading logs. Output should say clearly 
whether Tor is running, spawnable, or missing, and what to do. --- 
Daemon Lifecycle (inherits QuickShare's model) 1. ghostshare <file> 
starts the daemon if not running, hands off the share, exits. 2. One 
daemon serves all shares in a session. All shares use the same onion 
address (different tokens). 3. Daemon auto-shuts down after 45s 
(GHOSTSHARE_GRACE) with no active shares — closing the onion service, 
and killing spawned Tor (but not attached Tor). 4. Expiry checked 
every 10s (GHOSTSHARE_TICK). 5. ghostshare stop shuts down 
immediately but preserves unfinished shares in DB. 6. On restart, 
surviving shares get a new onion address. Documented behavior — not a 
bug. 7. Lock file at ~/.ghostshare/daemon.lock prevents double-start. 
8. Control channel: Unix domain socket (Windows: loopback TCP + key). 
--- Data Model SQLite at ~/.ghostshare/state.db. This schema differs 
from QuickShare's (token, path, created, expires_at, max_downloads, 
count): columns are renamed, filename and revoked are added, NULL means 
"never expires", and onion_session is for diagnostics only — never the 
key. store.go keeps QuickShare's Go API so callers stay portable 
[diverges from QuickShare]: ```sql CREATE TABLE shares (
  token TEXT PRIMARY KEY, file_path TEXT NOT NULL, filename TEXT NOT 
  NULL, expires_at INTEGER, -- unix ts; NULL = never max_downloads 
  INTEGER, -- 0 = unlimited downloads INTEGER DEFAULT 0, created_at 
  INTEGER NOT NULL, revoked INTEGER DEFAULT 0, onion_session TEXT -- 
  session id, diagnostic only; not the key
); ``` No onion keypair is stored — ephemeral by design. On daemon 
restart, surviving shares get a new onion address. --- Explicit 
Non-Goals (v1) If a user asks for any of these, say "that's v2" and 
move on: · Clearnet fallback. (Standalone is the whole point.) · 
Receive/upload mode. · Password gate on top of token. · Directory/tar 
sharing. · GUI. · Per-share ephemeral onions. · Persistent onion 
addresses. · Bundled Tor. (Violates the small-binary invariant.) · 
Windows CI (manual testing only). · Removing QuickShare attribution 
or relicensing without the original author's consent. --- Testing 
Strategy Layer Test Tooling Token uniqueness, length go test Store 
CRUD, expiry, restore go test, temp DB Server 
200/410/counting/Range-skip net/http/httptest Tor detection running / 
spawnable / missing branches mock exec.LookPath + fake control port 
Daemon spawn, control protocol, auto-stop integration test with short 
GHOSTSHARE_GRACE Tor (real) onion reachable, teardown clean opt-in 
via GHOSTSHARE_TOR_TEST=1 CLI flag parsing, JSON output, tor-status 
output os/exec against built binary Rule: Tor integration tests must 
be skippable via env var. go test ./... must stay fast, work without 
network access, and work without Tor installed. Never let Tor tests 
block the fast suite. Cross-compile test: CI must run CGO_ENABLED=0 
GOOS=linux go build and CGO_ENABLED=0 GOOS=windows go build on every 
PR. This catches CGO regressions immediately. --- Build Order (follow 
this, do not skip ahead) Phase 0 — Scaffolding · go.mod, directory 
layout, .gitignore, README.md, LICENSE (same license as QuickShare) · 
README first paragraph must state: "GhostShare is a Tor-only 
file-sharing CLI, based on QuickShare 
(github.com/computerguymackay/QuickShare)." · README must include a 
"Relationship to QuickShare" section: clearnet vs Tor, shared 
daemon/token model, shared license, how fixes flow between repos. · 
README must include a "Requirements" section: Tor (running or 
installed), Tor Browser for recipients, no clearnet fallback. · 
Verify: CGO_ENABLED=0 go build succeeds, go test ./... runs, 
cross-compile for Linux/macOS/Windows works Phase 1 — Clearnet File 
Serving (no Tor yet) · token.go, server.go, store.go · Port from 
QuickShare with attribution comments at the top of each inherited 
file:
  ```go
  // Ported from QuickShare 
  // (github.com/computerguymackay/QuickShare).
  ``` · Serve files over plain localhost HTTP with correct 
token/download/expiry semantics · Verify: integration test downloads 
a file via httptest, hits limit → 410 · Do not skip to Tor. Debugging 
Tor is much easier when the file layer is solid. Phase 2 — Tor 
Detection & Onion Service · tor.go: detect running Tor → else spawn → 
else error with install instructions · bine integration: v3 onion, 
listener, health check · ghostshare tor-status command · Verify: 
manual test with Tor Browser or curl --socks5-hostname 127.0.0.1:9050 
· Verify: link dies on exit; spawned Tor is killed; attached Tor is 
left alone · Verify: tor-status reports correctly in all three states 
Phase 3 — Daemon Lifecycle · daemon.go, control.go, main.go — ported 
from QuickShare, with tor.go swapped in for the listener · Match 
QuickShare's daemon model exactly (lock file, control socket, 
auto-stop, restore) unless a Tor-specific reason forces a change — 
and if so, note it [diverges from QuickShare] · Verify: two shares 
reuse one daemon; list/revoke/stop all work; restart restores shares 
with a new onion Phase 4 — UX & Polish · qr.go, config.go, security 
warnings, README polish · Verify: ghostshare report.pdf -m 3 -e 2h -q 
works end-to-end; --json is pipe-clean; --help and --version include 
the QuickShare attribution string --- When in Doubt · Reuse 
QuickShare's logic for token, download-counting, daemon, control 
socket, config layout. These are inherited; copy the semantics and 
keep the code structurally compatible so fixes can flow both ways. 
Cite QuickShare in the commit message when porting a fix. · Study 
OnionShare for onion-service lifecycle patterns — but remember we are 
not competing with it. We are the small, explicit CLI alternative. · 
Study garlicshare for a Go reference on bine usage. · Ask before 
adding scope. v1 is deliberately small. · Test manually with Tor 
Browser at least once per PR that touches tor.go or daemon.go. 
Automated tests won't catch everything. · If a change makes the build 
slower, the binary bigger, or requires CGO — stop. Those are the 
invariants that make this tool worth existing. · If a change makes 
GhostShare diverge from QuickShare for no Tor-specific reason — stop. 
Sibling projects should stay siblings. --- Naming Conventions · 
Binary: ghostshare · Repo: github.com/computerguymackay/GhostShare · 
Module path: github.com/computerguymackay/ghostshare (lowercase, like 
QuickShare's, so `go install` produces a binary named ghostshare) · 
Sibling repo: github.com/computerguymackay/QuickShare · Config dir: 
~/.ghostshare/ · Env vars: GHOSTSHARE_HOME, GHOSTSHARE_GRACE, 
GHOSTSHARE_TICK, GHOSTSHARE_TOR_TEST, GHOSTSHARE_TOR_CONTROL, 
GHOSTSHARE_TOR_SOCKS · Config file: config.toml · State DB: state.db 
· Log: ghostshare.log · Lock: daemon.lock · Control socket: 
control.sock (Unix), control.addr (Windows) · Attribution string (in 
--help and --version): based on QuickShare 
(github.com/computerguymackay/QuickShare) --- Reference 
Implementations · QuickShare — upstream ancestor, same author. UX, 
daemon model, download-counting semantics, flag surface, control 
socket, config layout. Read this first; GhostShare is a fork in 
spirit even if not in git. · OnionShare — onion-service lifecycle 
patterns (Python; instructive, not a competitor) · garlicshare — Go + 
bine reference · bine examples — canonical bine usage · Tor Browser — 
for manual verification of onion links ---
Last updated: 2026-10-31. Update this file when design decisions change — future Claude Code sessions depend on it.
