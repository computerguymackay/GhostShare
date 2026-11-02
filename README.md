# GhostShare

GhostShare is a Tor-only file-sharing CLI, based on QuickShare (github.com/computerguymackay/QuickShare).

Run `ghostshare <file>` and it prints a `.onion` link. The file is served from your own computer through a temporary Tor onion service made for that one file. When the download limit or expiry is reached, the onion service is removed and the link stops working. There are no accounts, no cloud hosting and no third-party file storage: the file never leaves your machine except to the person who downloads it.

```console
$ ghostshare holiday.jpg
publishing a new onion service for this file (this can take a minute)…
warning: Tor provides anonymity, not file encryption. Anyone with this link can download the file. Encrypt sensitive files first (e.g. `age -p file && ghostshare file.age`).
sharing holiday.jpg (3.4 MiB) · 1 download, expires 2026-11-01 14:02 UTC · metadata removed
the recipient must open this link in Tor Browser
http://abc...xyz.onion/q3V9x.../holiday.jpg
```

The recipient opens the link in Tor Browser and the file downloads. Neither side learns the other's IP address. The photo they receive has no GPS position, camera details or timestamps.

## Why use it

- **Anonymous by default.** Files are only ever served over Tor. There is no clearnet fallback: if Tor isn't available, GhostShare refuses to share.
- **Temporary.** Every share ends, after a number of downloads (default 1), a time limit (default 24 hours), or `ghostshare revoke`. Its onion address then disappears from Tor.
- **One onion per file.** Each share gets its own `.onion` address and token, so recipients of different files can't tell they came from the same person.
- **Metadata removed by default.** A cleaned copy is shared, using [metakill](https://github.com/computerguymackay/metakill): GPS, timestamps, device details and author names are removed, while a song's title, artist and cover art are kept. Your original file is never changed.
- **Nothing to sign up for or trust with your file.** No accounts, no upload to a server, no service that keeps a copy.
- **Small and scriptable.** A single static Go binary that uses the Tor you already have. Only the link goes to stdout.

## How it compares

| | Cloud file-sharing services | GhostShare |
| --- | --- | --- |
| Where the file is stored | On the provider's servers | Only on your computer |
| Account | Usually required | None |
| Who sees your IP address | The provider sees both yours and the recipient's | No one: both sides connect through Tor |
| Link lifetime | Often long-lived or permanent | Ends after N downloads or a set time |
| File metadata | Usually shared as-is | Removed by default |
| Availability | Always online | Only while your computer is on and connected |
| What the recipient needs | Any browser | Tor Browser |

[OnionShare](https://onionshare.org/) also shares files over onion services, and offers a GUI, receive mode and website hosting. GhostShare is deliberately narrower: one command shares one file, each on its own onion service, with metadata removed by default.

## Requirements

- **Tor, running or installed.** GhostShare first tries a running Tor's control port (`127.0.0.1:9051`). If none answers, it starts `tor` from your `PATH` and stops it when it's done. If neither works, it prints install instructions and exits.
- **Tor Browser for recipients**, or `curl --socks5-hostname 127.0.0.1:9050 <link>`. A normal browser can't open a `.onion` link. On phones: Tor Browser for Android, or Onion Browser on iOS.
- **No clearnet fallback.** GhostShare never serves a file over the open internet.
- **Your computer stays on** until the file has been downloaded. The file is served from your machine, not uploaded anywhere.

| System | Install Tor |
| --- | --- |
| Debian/Ubuntu | `sudo apt install tor` |
| Fedora | `sudo dnf install tor` |
| macOS | `brew install tor` |
| Windows | download the [Tor Expert Bundle](https://www.torproject.org/download/tor/) and put `tor.exe` on your `PATH` |

## Install

GhostShare is built from source and needs Go 1.26 or newer. There are no prebuilt binaries yet.

```sh
CGO_ENABLED=0 go install github.com/computerguymackay/ghostshare@latest
```

Or from a checkout:

```sh
git clone https://github.com/computerguymackay/GhostShare.git && cd GhostShare
CGO_ENABLED=0 go build -o ghostshare . && sudo mv ghostshare /usr/local/bin/
```

Then check that GhostShare can find Tor:

```console
$ ghostshare tor-status
Tor: spawnable
  no usable Tor on control port 127.0.0.1:9051 (dial tcp 127.0.0.1:9051: connect: connection refused).
  found /usr/bin/tor: ghostshare will start it when sharing and stop it on exit.
```

It reports **running** (GhostShare uses that Tor and leaves it running), **spawnable** (GhostShare starts `tor` itself and stops it afterwards) or **missing** (with install instructions). If your Tor runs as a system service and the check reports an authentication error, your user needs read access to Tor's auth cookie. On Debian/Ubuntu: `sudo usermod -aG debian-tor $USER`, then log out and back in.

## Usage

```sh
ghostshare report.pdf                    # 1 download, expires in 24 hours
ghostshare album.zip -m 3 -e 2h          # 3 downloads within 2 hours
ghostshare photo.jpg -q                  # also show a QR code, for a phone
ghostshare notes.txt -k                  # share as-is, without removing metadata
link=$(ghostshare build.tar.gz --json | jq -r .url)

ghostshare list                          # active shares and their links
ghostshare revoke q3V9xA                 # end a share early (6+ character prefix)
ghostshare stop                          # stop the daemon; unfinished shares are kept
```

Each share takes 10–60 seconds while its onion service is published, a little longer the first time if GhostShare has to start Tor. GhostShare only prints a link once that onion answers through Tor. Now and then a new link takes a minute or two to open in Tor Browser; if it doesn't load at first, wait a moment and try again.

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
| `-k`, `--keep-metadata` | share the file as-is, without removing metadata |
| `-i`, `--interactive` | prompt for the options (including whether to remove metadata) |
| `-q`, `--qr` | show the link as a QR code (on stderr) |
| `-o`, `--qr-out PATH` | save the QR code as a PNG |
| `-j`, `--json` | print `{url, token, expires_at, max_downloads, metadata_stripped}` instead of the bare link |
| `-f`, `--watch` | follow the daemon log after sharing |
| `--external-tor` | only use an already-running Tor; never start one |

Short flags take one or two dashes (`-m` and `--m` are the same). Combined short flags like `-iq` are not supported; write `-i -q`. Only the link (or the JSON) goes to stdout; warnings, summaries and QR codes go to stderr.

## Security and privacy

### What GhostShare protects

- **Your location.** The file is served through a Tor onion service, so the recipient, and anyone watching the network between you, doesn't learn your IP address. The recipient connects through Tor too, so you don't learn theirs, and the daemon log never records client addresses.
- **The connection.** Traffic to an onion service is end-to-end encrypted by Tor, even though the link starts with `http://`.
- **Links between shares.** Every share has its own onion address, so recipients can't connect different shares to each other. When a share ends, its address stops answering instead of showing that you're still online.
- **File metadata.** Removed by default; see [Metadata](#metadata).
- **File timestamps.** Downloads carry no `Last-Modified` header.
- **Onion keys.** Tor is told to discard each onion service's private key, so GhostShare never has it and can't write it to disk.

### What it doesn't protect

- **Anyone with the link can download the file.** The link is the only secret: a v3 onion address plus a random 144-bit token. There is no password. Send it only over a channel you trust, and set a low download limit.
- **Tor is anonymity, not file encryption.** Whoever downloads the file gets it in the clear. If it must stay confidential even when the link leaks, encrypt it first, for example `age -p file && ghostshare file.age`. GhostShare prints this warning on every share.
- **The file itself can identify you.** Removing metadata doesn't change what the file shows or says: faces, text, a document's content, a voice. The original filename is kept, so rename the file first if its name gives anything away.
- **Your computer is online while it shares.** The file is served from your machine, so a recipient with the link can see when it is reachable.
- **Tor's own limits.** An adversary able to watch traffic at both ends may be able to correlate it. GhostShare adds nothing beyond what Tor provides.
- **Your own machine.** Until a share ends, `~/.ghostshare` holds its file path, filename and full token (in `state.db`), and the cleaned copy. Finished shares are deleted from the database, but as with any SQLite delete the bytes may remain in the file until overwritten. Anyone with access to your user account can see what you are sharing.
- **No audit.** GhostShare is early software (0.1.0-dev) and has not been independently reviewed.

### Metadata

By default, GhostShare writes a cleaned copy of the file into `~/.ghostshare/files/` using [metakill](https://github.com/computerguymackay/metakill), and serves that under the original filename. Your original file is only read, never changed. The copy is deleted when the share ends, and kept across `ghostshare stop` and restarts. Files with nothing to remove (plain text, an already-clean photo) are served directly. The aim is to remove what identifies you and keep what makes the file useful:

- **Removed:** GPS and location, timestamps, camera and device details (make, model, serial numbers), owner and author names, software and encoder strings, comments, embedded thumbnails, and data hidden after the end of the file.
- **Kept:** the content; in music and video, the title, artist, album, track number, year (just the year) and cover art (with its own EXIF removed); document titles; photo orientation; colour profiles.

Supported formats include JPEG, PNG, WebP, HEIC, TIFF, GIF, SVG, PDF, Office (`.docx`, `.xlsx`, `.pptx`), OpenDocument, EPUB, MP3, FLAC, Ogg/Opus, WAV, MP4/MOV, MKV and AVI. Zip and tar archives are cleaned file by file, including archives inside archives; see metakill's README for the full list.

Details worth knowing:

- **7z and RAR are repacked as zip.** metakill can only rewrite them with 7-Zip or rar installed, and GhostShare runs no programs besides Tor, so it converts them to zip and cleans that. The link then ends in `.zip`, and stderr says so. Encrypted and multi-volume archives, and archives containing links, are shared as-is with a warning.
- **Cover art is kept only for audio and video files.** Inside an archive (a zip of songs) it is removed, because the same setting would also keep photos' thumbnails, which can show a picture before it was cropped.
- **Files that can't be cleaned are shared as-is, with a one-line warning** on stderr, such as `warning: can't remove metadata from .bin files; sharing as-is`. This covers unknown types, signed packages (APK, signed JAR), encrypted PDFs and encrypted files (`.age`, `.gpg`). A share is never refused because of metadata.
- **Things metakill deliberately leaves alone are reported too**, such as an archive entry under a home folder (`Users/jane/notes.txt`); names inside archives are never changed.
- **Limits:** encoder settings inside a video's compressed stream (such as x264's) are not touched. Genre, album artist, disc number and lyrics are removed along with other tags. The cleaned copy needs as much disk space as the file, and twice that while it is being made.

Turn cleaning off for one share with `-k` / `--keep-metadata` (GhostShare warns that metadata is not being removed), or for all shares with `strip_metadata = false` in the config. `--json` includes `"metadata_stripped"`, and `ghostshare list` has a METADATA column.

## How it works

**Shares end.** A completed download counts once. A broken download doesn't count, and finishing it later counts once. Resumed (Range) and HEAD requests never count. If two people finish on the last slot at the same moment, both may succeed. When a share ends (download limit, expiry, `revoke`, or the file is deleted), its onion service is removed from Tor at once; downloads already in progress may finish. Setting both `--max-downloads 0` and `--expires 0` is refused, so every share ends.

**The daemon.** The first share starts a background daemon, which connects to Tor, starting `tor` if needed. Later shares reuse the daemon and the same Tor, but each gets a new onion service. The daemon exits 45 seconds after the last share ends, removing its onion services. If GhostShare started Tor, that Tor is stopped too; a Tor you were already running is left alone.

**Restarts change addresses.** After `ghostshare stop`, a crash or a reboot, unfinished shares come back when the daemon next starts, each at a new `.onion` address, because onion keys are never stored. `ghostshare list` shows the new links.

## Configuration

On first run, GhostShare writes `~/.ghostshare/config.toml` (or `$GHOSTSHARE_HOME/config.toml`). Flags override it.

```toml
[share]
default_expiry        = "24h"
default_max_downloads = 1
strip_metadata        = true
```

| Environment variable | Meaning |
| --- | --- |
| `GHOSTSHARE_HOME` | state directory (default `~/.ghostshare`) |
| `GHOSTSHARE_TOR_CONTROL` | Tor control port to try first (default `127.0.0.1:9051`) |
| `GHOSTSHARE_TOR_SOCKS` | SOCKS address for the reachability check (default: ask Tor) |
| `GHOSTSHARE_GRACE`, `GHOSTSHARE_TICK` | daemon idle timeout (45s) and expiry check interval (10s) |

The state directory holds `state.db` (the shares), `files/` (cleaned copies), `tor/` (the data folder of a Tor that GhostShare started; removed when it stops, or at the next start if the daemon was killed), `ghostshare.log` (the daemon log; tokens appear only as their first 8 characters) and the daemon's lock and control socket.

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
- **Shared model:** GhostShare inherits QuickShare's background daemon, control socket, token format, download-counting rules, flag names and config layout. Code ported from QuickShare is marked with an attribution comment at the top of the file. GhostShare adds the Tor transport (`tor.go`), metadata removal and its warnings.
- **Shared license:** both projects use the same MIT license. Neither is relicensed without the other.
- **How fixes flow:** the two codebases are kept structurally aligned so fixes can be cherry-picked in either direction. A commit that ports a fix cites the other project. A commit that changes inherited behaviour is marked `[diverges from QuickShare]`.

They are not competitors: they are two answers to "share this file with one command", split on transport.

## License

MIT. See [LICENSE](LICENSE).
