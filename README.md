# ghostshare

GhostShare is a Tor-only file-sharing CLI, based on QuickShare (github.com/computerguymackay/QuickShare). One command shares a file through its own temporary Tor onion service and prints one `.onion` link. The link stops working after a set number of downloads or a set time, and its onion address disappears from Tor. No accounts, no relay, no third-party service, and no bundled Tor.

```console
$ ghostshare report.pdf
publishing a new onion service for this file (this can take a minute)…
warning: Tor provides anonymity, not file encryption. Anyone with this link can download the file. Encrypt sensitive files first (e.g. `age -p file && ghostshare file.age`).
sharing report.pdf (2.1 MiB) · 1 download, expires 2026-11-01 14:02 UTC
the recipient must open this link in Tor Browser
http://abc...xyz.onion/q3V9x.../report.pdf
```

The recipient opens the link in Tor Browser, the file downloads, and the link dies.

GhostShare is a small tool for people who already use Tor and want to share a file through it with one command. It is not a general-purpose anonymity suite.

## Requirements

- **Tor, running or installed.** GhostShare first tries a running Tor's control port (`127.0.0.1:9051`). If none is running, it starts `tor` from your `PATH` and stops it again when it's done. If neither works, it prints install instructions and exits.
- **Tor Browser for recipients** (or `curl --socks5-hostname 127.0.0.1:9050 <link>`). A normal browser cannot open a `.onion` link. On phones: Tor Browser for Android, or Onion Browser on iOS.
- **No clearnet fallback.** If Tor is unavailable, GhostShare refuses to share. It never serves a file over the open internet.

Installing Tor:

| System | Command |
| --- | --- |
| Debian/Ubuntu | `sudo apt install tor` |
| Fedora | `sudo dnf install tor` |
| macOS | `brew install tor` |
| Windows | download the [Tor Expert Bundle](https://www.torproject.org/download/tor/) and put `tor.exe` on your `PATH` |

## Install

```sh
CGO_ENABLED=0 go install github.com/computerguymackay/ghostshare@latest
# or, from a checkout:
git clone https://github.com/computerguymackay/GhostShare.git && cd GhostShare
CGO_ENABLED=0 go build -o ghostshare . && sudo mv ghostshare /usr/local/bin/
```

It builds as a single static binary: pure Go, no cgo, no bundled Tor.

Check that GhostShare can find Tor:

```console
$ ghostshare tor-status
Tor: spawnable
  no usable Tor on control port 127.0.0.1:9051 (dial tcp 127.0.0.1:9051: connect: connection refused).
  found /usr/bin/tor: ghostshare will start it when sharing and stop it on exit.
```

`tor-status` reports one of three states: **running** (GhostShare uses that Tor and leaves it running), **spawnable** (GhostShare starts `tor` itself and stops it afterwards), or **missing** (with install instructions).

## Usage

```text
ghostshare <file> [flags]     share a file and print its .onion link
ghostshare list [-j|--json]   show active shares and their current links
ghostshare revoke <prefix>    cancel a share (a unique prefix of 6+ characters is enough)
ghostshare stop               stop the daemon (unfinished shares are kept)
ghostshare tor-status         report whether Tor is running, spawnable, or missing
```

| Flag | Meaning |
| --- | --- |
| `-m`, `--max-downloads N` | downloads allowed (default 1; 0 = unlimited, needs `--expires`) |
| `-e`, `--expires DURATION` | e.g. `30m`, `24h`, `7d` (default `24h`; 0 = never, needs `--max-downloads`) |
| `-i`, `--interactive` | prompt for the options |
| `-q`, `--qr` | show the link as a QR code (on stderr) |
| `-o`, `--qr-out PATH` | save the QR code as a PNG |
| `-j`, `--json` | print `{url, token, expires_at, max_downloads}` instead of the bare link |
| `-f`, `--watch` | follow the daemon log after sharing |
| `--external-tor` | only use an already-running Tor; never start one |

Short flags take one or two dashes (`-m` and `--m` are the same). Combined short flags like `-iq` are not supported; write `-i -q`.

Only the link (or the JSON) goes to stdout. Warnings, summaries and QR codes go to stderr, so this works:

```sh
link=$(ghostshare build.tar.gz --json | jq -r .url)
```

### How shares end

A share always ends: setting both `--max-downloads 0` and `--expires 0` is refused.

A completed download counts once. A broken download doesn't count, and finishing it later counts once. Resumed downloads (Range requests) and HEAD requests never count. If two people finish downloading at the same moment on the last slot, both may succeed.

When a share ends (download limit, expiry, `revoke`, or the file is deleted), its onion service is removed from Tor at once. Tor Browser then reports that the site can't be found. Downloads already in progress may finish.

### One onion per file

Every share gets its own `.onion` address and its own token, so two recipients can't tell that their files came from the same person, and a token only works on its own address. The cost is time: each share waits for its own onion service to be published and reachable, which usually takes 10–60 seconds. No link is printed until the onion answers through Tor.

### The daemon

The first share starts a background daemon, which connects to Tor (starting `tor` if needed). Later shares reuse the daemon and the same Tor, but each still gets a new onion service.

The daemon exits by itself 45 seconds after the last share ends, removing all its onion services. If GhostShare started Tor, that Tor is stopped too. A Tor you were already running is left alone.

**Restarts change the addresses.** After `ghostshare stop`, a crash, or a reboot, unfinished shares come back the next time the daemon starts, each at a new `.onion` address, because onion keys are never stored. `ghostshare list` shows their new links.

## Configuration

On first run, GhostShare writes `~/.ghostshare/config.toml` (or `$GHOSTSHARE_HOME/config.toml`):

```toml
[share]
default_expiry        = "24h"
default_max_downloads = 1
```

Flags override the config. There are no network settings; QuickShare's `[server]` section is reported as unused if present.

| Environment variable | Meaning |
| --- | --- |
| `GHOSTSHARE_HOME` | state directory (default `~/.ghostshare`) |
| `GHOSTSHARE_TOR_CONTROL` | Tor control port to try first (default `127.0.0.1:9051`) |
| `GHOSTSHARE_TOR_SOCKS` | SOCKS address for the reachability check (default: ask Tor) |
| `GHOSTSHARE_GRACE`, `GHOSTSHARE_TICK` | daemon idle timeout (45s) and expiry check interval (10s) |

The state directory holds `state.db` (the shares), `ghostshare.log` (the daemon log), and the daemon's lock and control socket.

## Security and privacy

- **Tor is anonymity, not encryption.** The onion service hides where the file is served from, but anyone who has the link can download the file. Encrypt sensitive files first, for example with `age -p`.
- **The link is the secret.** Each link has its own onion address and a random 144-bit token. Share it only over a channel you trust.
- **Shares are unlinkable.** Different shares never share an onion address, so recipients can't connect them to each other, and a finished share's address stops answering instead of confirming you're still online.
- **No onion keys on disk.** Tor is told to discard the onion service's private key, so GhostShare never has it and can't store it.
- **Minimal logs.** The daemon log never records client addresses or onion addresses, and shows tokens only as their first 8 characters.
- **Tor control access.** If your Tor runs as a system service and `tor-status` reports an authentication error, your user needs read access to Tor's auth cookie. On Debian/Ubuntu: `sudo usermod -aG debian-tor $USER`, then log out and back in.

## Building and testing

```sh
CGO_ENABLED=0 go build -o ghostshare .

# Cross-compile (no cgo, so this works from any machine)
GOOS=linux   GOARCH=amd64 CGO_ENABLED=0 go build -o ghostshare-linux-amd64 .
GOOS=darwin  GOARCH=arm64 CGO_ENABLED=0 go build -o ghostshare-darwin-arm64 .
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -o ghostshare-windows-amd64.exe .

# Tests: no Tor and no network needed (they use a fake Tor)
go test ./...

# Real-Tor tests (opt in; needs Tor and network access)
GHOSTSHARE_TOR_TEST=1 go test -tags=tortest -v ./...
```

## Relationship to QuickShare

GhostShare is the Tor-only sibling of [QuickShare](https://github.com/computerguymackay/QuickShare). Both are by the same author.

- **Transport:** QuickShare serves files over clearnet HTTP from a machine the internet can reach. GhostShare serves each file over its own temporary Tor onion service, so neither side needs a public IP or reveals one.
- **Shared model:** GhostShare inherits QuickShare's background daemon, control socket, token format, download-counting rules, flag names, and config layout. Code ported from QuickShare is marked with an attribution comment at the top of the file. GhostShare's own addition is the Tor transport (`tor.go`) and its warnings.
- **Shared license:** both projects use the same MIT license. Neither is relicensed without the other.
- **How fixes flow:** the two codebases are kept structurally aligned so fixes can be cherry-picked in either direction. A commit that ports a fix cites the other project. A commit that changes inherited behavior is marked `[diverges from QuickShare]`.

They are not competitors. They are two answers to "share this file with one command", split on transport.

## License

MIT. See [LICENSE](LICENSE).
