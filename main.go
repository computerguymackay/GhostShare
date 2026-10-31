// Command ghostshare shares a file over a temporary Tor onion service.
// It is based on QuickShare (github.com/computerguymackay/QuickShare).
// See README.md and CLAUDE.md.
package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const version = "0.1.0-dev"

// attribution must appear in --help and --version (CLAUDE.md, Lineage & Attribution).
const attribution = "based on QuickShare (github.com/computerguymackay/QuickShare)"

// securityWarning is printed to stderr on every share (CLAUDE.md, Security & Privacy Invariants).
const securityWarning = "warning: Tor provides anonymity, not file encryption. Anyone with this link can download the file. Encrypt sensitive files first (e.g. `age -p file && ghostshare file.age`)."

const usage = `ghostshare — share a file over a temporary Tor onion service
` + attribution + `

Usage:
  ghostshare <file> [flags]       share a file and print its .onion link
  ghostshare list [-j|--json]     show active shares
  ghostshare revoke <prefix>      cancel a share (unique prefix of 6+ characters)
  ghostshare stop                 stop the background daemon (shares are kept)
  ghostshare tor-status           report whether Tor is running, spawnable, or missing

Requirements:
  Tor must be running or installed (tor on PATH). There is no clearnet fallback.
  Recipients must use Tor Browser (or curl --socks5-hostname 127.0.0.1:9050).
  A normal browser cannot open a .onion link.
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	switch args[0] {
	case "tor-status":
		return cmdTorStatus(stdout)
	case "list", "revoke", "stop":
		return errorf(stderr, "%s: not implemented yet (Phase 3)", args[0])
	case "help", "-h", "-help", "--help":
		fmt.Fprint(stdout, usage)
		return 0
	case "version", "--version":
		fmt.Fprintf(stdout, "ghostshare %s, %s\n", version, attribution)
		return 0
	case "--":
		args = args[1:]
	}
	return cmdShareForeground(args, stdout, stderr)
}

func errorf(w io.Writer, format string, a ...any) int {
	fmt.Fprintf(w, "ghostshare: "+format+"\n", a...)
	return 1
}

func cmdTorStatus(stdout io.Writer) int {
	st := probeTor(defaultTorEnv())
	writeTorStatus(stdout, st)
	if st.State == torMissing {
		return 1
	}
	return 0
}

// cmdShareForeground is a temporary Phase 2 mode: it serves one file over a
// fresh onion service in the foreground, with QuickShare's defaults (one
// download, 24h), until the share ends or the user presses Ctrl-C. Phase 3
// replaces it with QuickShare's daemon handoff, and flags come with it.
func cmdShareForeground(args []string, stdout, stderr io.Writer) int {
	if len(args) != 1 || strings.HasPrefix(args[0], "-") {
		return errorf(stderr, "usage: ghostshare <file>  (share flags arrive in Phase 3)")
	}
	path, err := filepath.Abs(args[0])
	if err != nil {
		return errorf(stderr, "%v", err)
	}
	if !fileExists(path) {
		return errorf(stderr, "%s is not a regular file", args[0])
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Throwaway state for this run; the daemon in Phase 3 uses ~/.ghostshare/state.db.
	dir, err := os.MkdirTemp("", "ghostshare-")
	if err != nil {
		return errorf(stderr, "%v", err)
	}
	defer os.RemoveAll(dir)
	st, err := openStore(filepath.Join(dir, "state.db"))
	if err != nil {
		return errorf(stderr, "%v", err)
	}
	defer st.Close()

	tok, err := newToken()
	if err != nil {
		return errorf(stderr, "%v", err)
	}
	now := time.Now()
	sh := Share{Token: tok, Path: path, Created: now.Unix(),
		ExpiresAt: now.Add(24 * time.Hour).Unix(), MaxDownloads: 1}
	if err := st.Add(sh); err != nil {
		return errorf(stderr, "%v", err)
	}
	sh, _ = st.Get(tok)

	sess, err := connectTor(defaultTorEnv(), true, stderr)
	if err != nil {
		return errorf(stderr, "%v", err)
	}
	defer sess.Close()

	fmt.Fprintln(stderr, "creating onion service (this can take a minute)…")
	lctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	onion, err := sess.Listen(lctx)
	cancel()
	if err != nil {
		return errorf(stderr, "%v", err)
	}
	defer onion.Close()

	// Request logs stay quiet until the health check is done.
	logger := log.New(io.Discard, "", log.LstdFlags)
	fsrv := &FileServer{store: st, log: logger, now: time.Now}
	hs := &http.Server{Handler: fsrv, ReadHeaderTimeout: 30 * time.Second}
	go hs.Serve(onion)
	defer hs.Close()

	host := onion.ID + ".onion"
	fmt.Fprintln(stderr, "checking that the onion service is reachable…")
	if err := sess.WaitReachable(ctx, host, healthTimeout); err != nil {
		return errorf(stderr, "%v", err)
	}
	logger.SetOutput(stderr)

	link := "http://" + host + "/" + tok + "/" + url.PathEscape(sh.Filename)
	fmt.Fprintln(stderr, securityWarning)
	fmt.Fprintf(stderr, "sharing %s · 1 download, expires %s\n", sh.Filename,
		time.Unix(sh.ExpiresAt, 0).UTC().Format("2006-01-02 15:04 UTC"))
	fmt.Fprintln(stderr, "open the link in Tor Browser. Press Ctrl-C to stop sharing.")
	fmt.Fprintln(stdout, link)

	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			fmt.Fprintln(stderr, "stopped; the link no longer works")
			return 0
		case <-tick.C:
			cur, err := st.Get(tok)
			if (err != nil || !cur.Active(time.Now())) && fsrv.InFlight() == 0 {
				fmt.Fprintln(stderr, "share finished; the link no longer works")
				return 0
			}
		}
	}
}
