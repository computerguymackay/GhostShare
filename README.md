# ghostshare

GhostShare is a Tor-only file-sharing CLI, based on QuickShare (github.com/computerguymackay/QuickShare). One command shares a file through a temporary Tor onion service and prints one `.onion` link. The link stops working after a set number of downloads or a set time. No accounts, no relay, no third-party service, and no bundled Tor.

> **Status:** early development. `ghostshare <file>` currently serves one file in the foreground (one download, 24h expiry) until the download finishes or you press Ctrl-C. The background daemon, `list`, `revoke`, `stop`, and the share flags are not implemented yet.

```console
$ ghostshare report.pdf
warning: Tor provides anonymity, not file encryption. Anyone with this link can download the file. Encrypt sensitive files first (e.g. `age -p file && ghostshare file.age`).
http://abc...xyz.onion/q3V9x.../report.pdf
```

The recipient opens the link in Tor Browser, the file downloads, and the link dies.

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
