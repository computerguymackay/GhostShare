# ghostshare

GhostShare is a Tor-only file-sharing CLI, based on QuickShare (github.com/computerguymackay/QuickShare). One command shares a file through a temporary Tor onion service and prints one `.onion` link. The link stops working after a set number of downloads or a set time. No accounts, no relay, no third-party service, and no bundled Tor.

> **Status:** early development. Sharing, `list`, `revoke`, `stop` and `tor-status` work. QR codes (`-q`, `-o`) and `config.toml` defaults are not implemented yet.

```console
$ ghostshare report.pdf
warning: Tor provides anonymity, not file encryption. Anyone with this link can download the file. Encrypt sensitive files first (e.g. `age -p file && ghostshare file.age`).
sharing report.pdf (2.1 MiB) · 1 download, expires 2026-11-01 14:02 UTC
the recipient must open this link in Tor Browser
http://abc...xyz.onion/q3V9x.../report.pdf
```

The recipient opens the link in Tor Browser, the file downloads, and the link dies.

The first share starts a background daemon, which connects to Tor and publishes the onion service. That can take a minute, and the progress is shown while you wait. Later shares reuse the same daemon and the same `.onion` address, each with its own token, and print a link at once. The daemon exits by itself 45 seconds after the last share ends.

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
| `-j`, `--json` | print `{url, token, expires_at, max_downloads}` instead of the bare link |
| `-f`, `--watch` | follow the daemon log after sharing |
| `--external-tor` | only use an already-running Tor; never start one |

Only the link (or the JSON) goes to stdout. Everything else goes to stderr, so this works:

```sh
link=$(ghostshare build.tar.gz --json | jq -r .url)
```

A share always ends: setting both `--max-downloads 0` and `--expires 0` is refused.

A completed download counts once. A broken download doesn't count, and finishing it later counts once. Resumed downloads (Range requests) and HEAD requests never count.

**Restarts change the address.** After `ghostshare stop`, a crash, or a reboot, unfinished shares come back the next time the daemon starts, but at a new `.onion` address, because the onion key is never stored. Run `ghostshare list` to see their new links.

State lives in `~/.ghostshare/` (or `$GHOSTSHARE_HOME`): `state.db` holds the shares, and `ghostshare.log` is the daemon log.

## Requirements

- **Tor, running or installed.** GhostShare first tries a running Tor's control port (`127.0.0.1:9051`). If none is running, it starts `tor` from your `PATH`. If neither works, it prints install instructions and exits.
- **Tor Browser for recipients** (or `curl --socks5-hostname 127.0.0.1:9050 <link>`). A normal browser cannot open a `.onion` link.
- **No clearnet fallback.** If Tor is unavailable, GhostShare refuses to share. It never serves a file over plain HTTP on the open internet.

Run `ghostshare tor-status` to see which of these applies on your machine: Tor **running** (GhostShare will use it and leave it running), **spawnable** (GhostShare will start `tor` and stop it on exit), or **missing** (with install instructions). If your Tor's control port is somewhere else, set `GHOSTSHARE_TOR_CONTROL` (default `127.0.0.1:9051`). `GHOSTSHARE_TOR_SOCKS` overrides the SOCKS address used for the reachability check.

If Tor runs as a system service and `tor-status` reports an authentication error, your user needs read access to Tor's auth cookie. On Debian/Ubuntu: `sudo usermod -aG debian-tor $USER`, then log out and back in.

Tor gives anonymity, not encryption of the file itself. Anyone who has the link can download the file, so encrypt sensitive files first.

GhostShare never stores the onion service's private key: Tor is told to discard it, so every run gets a new `.onion` address.

## Building

```sh
CGO_ENABLED=0 go build -o ghostshare .
```

GhostShare is pure Go and never needs cgo, so it cross-compiles anywhere:

```sh
GOOS=linux   GOARCH=amd64 CGO_ENABLED=0 go build -o ghostshare-linux-amd64 .
GOOS=darwin  GOARCH=arm64 CGO_ENABLED=0 go build -o ghostshare-darwin-arm64 .
GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -o ghostshare-windows-amd64.exe .
```

## Relationship to QuickShare

GhostShare is the Tor-only sibling of [QuickShare](https://github.com/computerguymackay/QuickShare). Both are by the same author.

- **Transport:** QuickShare serves files over clearnet HTTP from a machine the internet can reach. GhostShare serves the same files over a temporary Tor onion service, so neither side needs a public IP or reveals one.
- **Shared model:** GhostShare inherits QuickShare's background daemon, control socket, token format, download-counting rules, flag names, and config layout. Code ported from QuickShare is marked with an attribution comment at the top of the file. GhostShare's own addition is the Tor transport (`tor.go`) and its warnings.
- **Shared license:** both projects use the same MIT license. Neither is relicensed without the other.
- **How fixes flow:** the two codebases are kept structurally aligned so fixes can be cherry-picked in either direction. A commit that ports a fix cites the other project. A commit that changes inherited behavior is marked `[diverges from QuickShare]`.

They are not competitors. They are two answers to "share this file with one command", split on transport.

## License

MIT. See [LICENSE](LICENSE).
