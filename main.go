// Command ghostshare shares a file over a temporary Tor onion service.
// It is based on QuickShare (github.com/computerguymackay/QuickShare).
// See README.md and CLAUDE.md.
//
// Ported from QuickShare (github.com/computerguymackay/QuickShare).
//
// [diverges from QuickShare]
//   - No --wan, --bind, --tls or --allow-forever (Tor replaces the first
//     three; the last is out of scope for v1). Adds --external-tor and the
//     tor-status command.
//   - The share link uses the daemon's .onion address, and `list` shows each
//     share's current link, since restarts change the onion address.
//   - Every share prints the Tor security warning and the Tor Browser note.

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"text/tabwriter"
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
  ghostshare list [-j|--json]     show active shares and their current links
  ghostshare revoke <prefix>      cancel a share (unique prefix of 6+ characters)
  ghostshare stop                 stop the background daemon (shares are kept)
  ghostshare tor-status           report whether Tor is running, spawnable, or missing

Share flags:
  -m, --max-downloads N   downloads allowed (default 1; 0 = unlimited, needs --expires)
  -e, --expires DURATION  e.g. 30m, 24h, 7d (default 24h; 0 = never, needs --max-downloads)
  -i, --interactive       prompt for options
  -q, --qr                show the link as a QR code (on stderr)
  -o, --qr-out PATH       save the QR code as a PNG
  -j, --json              print {url, token, expires_at, max_downloads}
  -f, --watch             follow the daemon log after sharing
      --external-tor      only use an already-running Tor; never start one

Short flags take one or two dashes (-i and --i are the same). Combined
short flags like -iq are not supported; write -i -q.

The link is always the last line on stdout, so link=$(ghostshare f.zip) works.
Config: ~/.ghostshare/config.toml (or $GHOSTSHARE_HOME/config.toml)

Requirements:
  Tor must be running or installed (tor on PATH). There is no clearnet fallback.
  Recipients must use Tor Browser (or curl --socks5-hostname 127.0.0.1:9050).
  A normal browser cannot open a .onion link.

Environment:
  GHOSTSHARE_HOME          state directory (default ~/.ghostshare)
  GHOSTSHARE_TOR_CONTROL   Tor control port to try first (default 127.0.0.1:9051)
  GHOSTSHARE_TOR_SOCKS     SOCKS address for the reachability check (default: ask Tor)
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	switch args[0] {
	case "list":
		return cmdList(args[1:], stdout, stderr)
	case "revoke":
		return cmdRevoke(args[1:], stdout, stderr)
	case "stop":
		return cmdStop(stdout, stderr)
	case "tor-status":
		return cmdTorStatus(stdout)
	case "__daemon":
		return cmdDaemon(args[1:])
	case "help", "-h", "-help", "--help":
		fmt.Fprint(stdout, usage)
		return 0
	case "version", "--version":
		fmt.Fprintf(stdout, "ghostshare %s, %s\n", version, attribution)
		return 0
	case "--":
		args = args[1:]
	}
	return cmdShare(args, stdin, stdout, stderr)
}

func errorf(w io.Writer, format string, a ...any) int {
	fmt.Fprintf(w, "ghostshare: "+format+"\n", a...)
	return 1
}

func warnf(w io.Writer, format string, a ...any) {
	fmt.Fprintf(w, "warning: "+format+"\n", a...)
}

// parseInterspersed lets flags appear before or after the file name.
func parseInterspersed(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		args = fs.Args()
		if len(args) == 0 {
			return pos, nil
		}
		if args[0] == "--" {
			return append(pos, args[1:]...), nil
		}
		pos = append(pos, args[0])
		args = args[1:]
	}
}

func cmdShare(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("ghostshare", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	maxFlag := fs.Int("max-downloads", 1, "")
	expFlag := fs.String("expires", "", "")
	interactive := fs.Bool("interactive", false, "")
	showQR := fs.Bool("qr", false, "")
	qrOut := fs.String("qr-out", "", "")
	jsonOut := fs.Bool("json", false, "")
	watch := fs.Bool("watch", false, "")
	externalTor := fs.Bool("external-tor", false, "")

	// Short aliases. --external-tor deliberately has none.
	short := map[string]string{
		"m": "max-downloads", "e": "expires", "i": "interactive",
		"q": "qr", "o": "qr-out", "j": "json", "f": "watch",
	}
	for s, long := range short {
		fs.Var(fs.Lookup(long).Value, s, "")
	}

	pos, err := parseInterspersed(fs, args)
	if err != nil {
		fmt.Fprintf(stderr, "ghostshare: %v\n\n%s", err, usage)
		return 2
	}
	if len(pos) != 1 {
		fmt.Fprintf(stderr, "ghostshare: expected exactly one file\n\n%s", usage)
		return 2
	}
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) {
		if long, ok := short[f.Name]; ok {
			set[long] = true
		} else {
			set[f.Name] = true
		}
	})

	p, err := resolvePaths()
	if err != nil {
		return errorf(stderr, "%v", err)
	}
	cfg, cfgWarns, err := loadConfig(p)
	if err != nil {
		return errorf(stderr, "config: %v", err)
	}
	for _, w := range cfgWarns {
		warnf(stderr, "%s", w)
	}

	// The file.
	path, err := filepath.Abs(pos[0])
	if err != nil {
		return errorf(stderr, "%v", err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		return errorf(stderr, "%v", err)
	}
	if !fi.Mode().IsRegular() {
		return errorf(stderr, "%s is not a regular file (directories: zip or tar them first)", pos[0])
	}
	if f, err := os.Open(path); err != nil {
		return errorf(stderr, "%v", err)
	} else {
		f.Close()
	}

	// Limits.
	maxDl := *cfg.Share.DefaultMaxDownloads
	if set["max-downloads"] {
		maxDl = *maxFlag
	}
	expStr := cfg.Share.DefaultExpiry
	if set["expires"] {
		expStr = *expFlag
	}
	expires, err := parseDuration(expStr)
	if err != nil {
		return errorf(stderr, "--expires: %v", err)
	}
	if *interactive {
		maxDl, expires, *showQR, err = promptOptions(stdin, stderr, maxDl, expires, *showQR)
		if err != nil {
			return errorf(stderr, "%v", err)
		}
	}
	if err := validateLimits(maxDl, expires); err != nil {
		return errorf(stderr, "%v", err)
	}

	// Daemon.
	opt := defaultDaemonOptions()
	opt.ExternalTor = *externalTor
	logOffset := fileSize(p.Log)
	st, spawned, err := ensureDaemon(p, opt, stderr)
	if err != nil {
		return errorf(stderr, "%v", err)
	}
	if !spawned && opt.ExternalTor && st.TorSpawned {
		warnf(stderr, "the daemon is already running on a Tor it started; --external-tor applies after `ghostshare stop`")
	}
	if spawned && st.Active > 0 {
		fmt.Fprintf(stderr, "%d earlier share(s) are back online at this session's new .onion address; `ghostshare list` shows their links\n", st.Active)
	}

	var expiresAt int64
	if expires > 0 {
		expiresAt = time.Now().Add(expires).Unix()
	}
	resp, err := ctrlCall(p, ctrlRequest{Op: "add-share", Path: path, ExpiresAt: expiresAt, MaxDownloads: maxDl})
	if err != nil {
		return errorf(stderr, "add share: %v", err)
	}
	sh := *resp.Share
	link := shareURL(st.Onion, sh)

	fmt.Fprintln(stderr, securityWarning)

	if *jsonOut {
		out := struct {
			URL          string  `json:"url"`
			Token        string  `json:"token"`
			ExpiresAt    *string `json:"expires_at"`
			MaxDownloads int     `json:"max_downloads"`
		}{URL: link, Token: sh.Token, MaxDownloads: sh.MaxDownloads}
		if sh.ExpiresAt != 0 {
			s := time.Unix(sh.ExpiresAt, 0).UTC().Format(time.RFC3339)
			out.ExpiresAt = &s
		}
		enc := json.NewEncoder(stdout)
		enc.Encode(out)
	} else {
		fmt.Fprintf(stderr, "sharing %s (%s) · %s\n", sh.Filename, humanSize(fi.Size()), describeLimits(sh))
		fmt.Fprintln(stderr, "the recipient must open this link in Tor Browser")
		fmt.Fprintln(stdout, link)
	}

	if *showQR {
		fmt.Fprintln(stderr)
		color := false
		if f, ok := stderr.(*os.File); ok {
			color = isTerminal(f)
		}
		if err := renderQR(stderr, link, color); err != nil {
			warnf(stderr, "QR: %v", err)
		}
	}
	if *qrOut != "" {
		if err := writeQRPNG(*qrOut, link); err != nil {
			return errorf(stderr, "write QR: %v", err)
		}
		fmt.Fprintf(stderr, "QR code saved to %s\n", *qrOut)
	}
	if *showQR || *qrOut != "" {
		fmt.Fprintln(stderr, "the phone that scans it needs Tor Browser (Android) or Onion Browser (iOS) to open the link")
	}

	if *watch {
		watchLog(p, logOffset, stderr)
	}
	return 0
}

func promptOptions(stdin io.Reader, w io.Writer, maxDl int, exp time.Duration, qr bool) (int, time.Duration, bool, error) {
	r := bufio.NewReader(stdin)
	ask := func(q, def string) string {
		fmt.Fprintf(w, "%s [%s]: ", q, def)
		line, _ := r.ReadString('\n')
		if line = strings.TrimSpace(line); line == "" {
			return def
		}
		return line
	}
	for {
		v := ask("Max downloads (0 = unlimited)", itoa(maxDl))
		var n int
		if _, err := fmt.Sscan(v, &n); err == nil && n >= 0 {
			maxDl = n
			break
		}
		fmt.Fprintln(w, "  enter a whole number")
	}
	for {
		def := "0"
		if exp > 0 {
			def = formatDuration(exp)
		}
		d, err := parseDuration(ask("Expires after (e.g. 30m, 24h, 7d; 0 = never)", def))
		if err == nil {
			exp = d
			break
		}
		fmt.Fprintln(w, " ", err)
	}
	def := "n"
	if qr {
		def = "y"
	}
	ans := strings.ToLower(ask("Show QR code? (y/n)", def))
	return maxDl, exp, strings.HasPrefix(ans, "y"), nil
}

func watchLog(p Paths, offset int64, w io.Writer) {
	fmt.Fprintf(w, "\nwatching %s (Ctrl-C to stop watching; the daemon keeps running)\n", p.Log)
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	defer signal.Stop(sig)

	f, err := os.Open(p.Log)
	if err != nil {
		warnf(w, "%v", err)
		return
	}
	defer f.Close()
	f.Seek(offset, io.SeekStart)
	buf := make([]byte, 32<<10)
	drain := func() {
		for {
			n, _ := f.Read(buf)
			if n == 0 {
				return
			}
			w.Write(buf[:n])
		}
	}
	tick := time.NewTicker(300 * time.Millisecond)
	defer tick.Stop()
	checks := 0
	for {
		select {
		case <-sig:
			fmt.Fprintln(w)
			return
		case <-tick.C:
			drain()
			if checks++; checks%3 == 0 && !daemonAlive(p) {
				drain()
				fmt.Fprintln(w, "daemon has exited")
				return
			}
		}
	}
}

// listItem is a share plus its current link (empty while the daemon is down).
type listItem struct {
	Share
	URL string `json:"url,omitempty"`
}

func cmdList(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	fs.SetOutput(stderr)
	jsonOut := fs.Bool("json", false, "output JSON")
	fs.BoolVar(jsonOut, "j", false, "output JSON")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	p, err := resolvePaths()
	if err != nil {
		return errorf(stderr, "%v", err)
	}
	var shares []Share
	onion := ""
	running := true
	resp, err := ctrlCall(p, ctrlRequest{Op: "list"})
	switch {
	case errors.Is(err, errDaemonDown):
		running = false
		shares, err = offlineShares(p)
		if err != nil {
			return errorf(stderr, "%v", err)
		}
	case err != nil:
		return errorf(stderr, "%v", err)
	default:
		shares = resp.Shares
		if st, err := daemonStatus(p); err == nil && st.Ready {
			onion = st.Onion
		}
	}
	items := make([]listItem, 0, len(shares))
	for _, sh := range shares {
		it := listItem{Share: sh}
		if onion != "" {
			it.URL = shareURL(onion, sh)
		}
		items = append(items, it)
	}

	if *jsonOut {
		json.NewEncoder(stdout).Encode(items)
		return 0
	}
	if !running && len(items) > 0 {
		fmt.Fprintln(stderr, "daemon is not running: these shares are offline until the next `ghostshare <file>` starts it, and they will get a new .onion address")
	}
	if len(items) == 0 {
		fmt.Fprintln(stderr, "no active shares")
		return 0
	}
	tw := tabwriter.NewWriter(stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "TOKEN\tFILE\tDOWNLOADS\tEXPIRES\tLINK")
	now := time.Now()
	for _, it := range items {
		exp := "never"
		if it.ExpiresAt != 0 {
			exp = "in " + humanDuration(time.Unix(it.ExpiresAt, 0).Sub(now))
		}
		link := it.URL
		if link == "" {
			link = "(offline)"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", it.Token, it.Path, countString(it.Share), exp, link)
	}
	tw.Flush()
	return 0
}

// offlineShares reads the database directly when no daemon is running.
func offlineShares(p Paths) ([]Share, error) {
	if !fileExists(p.DB) {
		return nil, nil
	}
	st, err := openStore(p.DB)
	if err != nil {
		return nil, err
	}
	defer st.Close()
	all, err := st.List()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	var live []Share
	for _, sh := range all {
		if sh.Active(now) && fileExists(sh.Path) {
			live = append(live, sh)
		}
	}
	return live, nil
}

func cmdRevoke(args []string, stdout, stderr io.Writer) int {
	if len(args) != 1 {
		fmt.Fprintln(stderr, "usage: ghostshare revoke <prefix>")
		return 2
	}
	p, err := resolvePaths()
	if err != nil {
		return errorf(stderr, "%v", err)
	}
	resp, err := ctrlCall(p, ctrlRequest{Op: "revoke", Token: args[0]})
	if errors.Is(err, errDaemonDown) {
		tok, err := revokeOffline(p, args[0])
		if err != nil {
			return errorf(stderr, "%v", err)
		}
		fmt.Fprintf(stdout, "revoked %s\n", tok)
		return 0
	}
	if err != nil {
		return errorf(stderr, "%v", err)
	}
	fmt.Fprintf(stdout, "revoked %s\n", resp.Share.Token)
	return 0
}

func revokeOffline(p Paths, q string) (string, error) {
	live, err := offlineShares(p)
	if err != nil {
		return "", err
	}
	tok, err := resolveToken(live, q)
	if err != nil {
		return "", err
	}
	st, err := openStore(p.DB)
	if err != nil {
		return "", err
	}
	defer st.Close()
	_, err = st.Revoke(tok)
	return tok, err
}

func cmdStop(stdout, stderr io.Writer) int {
	p, err := resolvePaths()
	if err != nil {
		return errorf(stderr, "%v", err)
	}
	st, err := daemonStatus(p)
	if err != nil {
		if daemonAlive(p) {
			return errorf(stderr, "a daemon holds %s but is not answering; check %s", p.DaemonLock, p.Log)
		}
		clearStale(p)
		fmt.Fprintln(stdout, "daemon is not running")
		return 0
	}
	if _, err := ctrlCall(p, ctrlRequest{Op: "stop"}); err != nil {
		return errorf(stderr, "%v", err)
	}
	deadline := time.Now().Add(15 * time.Second)
	for daemonAlive(p) {
		if time.Now().After(deadline) {
			return errorf(stderr, "daemon (pid %d) did not exit within 15s", st.PID)
		}
		time.Sleep(50 * time.Millisecond)
	}
	fmt.Fprintf(stdout, "daemon stopped (pid %d)\n", st.PID)
	if st.Active > 0 {
		fmt.Fprintf(stderr, "%d share(s) kept: they come back online, at a new .onion address, next time the daemon starts. Use `ghostshare revoke <prefix>` to cancel them.\n", st.Active)
	}
	return 0
}

func cmdTorStatus(stdout io.Writer) int {
	st := probeTor(defaultTorEnv())
	writeTorStatus(stdout, st)
	if st.State == torMissing {
		return 1
	}
	return 0
}

func cmdDaemon(args []string) int {
	fs := flag.NewFlagSet("__daemon", flag.ContinueOnError)
	opt := defaultDaemonOptions()
	fs.BoolVar(&opt.ExternalTor, "external-tor", false, "")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	p, err := resolvePaths()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	logger := log.New(os.Stderr, "", log.LstdFlags)
	ctx, cancel := signal.NotifyContext(context.Background(), stopSignals...)
	defer cancel()
	err = newDaemon(p, opt, logger).Run(ctx)
	if errors.Is(err, errAlreadyRunning) {
		logger.Printf("%v; exiting", err)
		return 0
	}
	if err != nil {
		logger.Printf("error: %v", err)
		return 1
	}
	return 0
}

func fileSize(path string) int64 {
	fi, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return fi.Size()
}

func humanSize(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

// formatDuration prints a duration the way a user would type it.
func formatDuration(d time.Duration) string {
	switch {
	case d >= 48*time.Hour && d%(24*time.Hour) == 0:
		return fmt.Sprintf("%dd", d/(24*time.Hour))
	case d%time.Hour == 0:
		return fmt.Sprintf("%dh", d/time.Hour)
	case d%time.Minute == 0:
		return fmt.Sprintf("%dm", d/time.Minute)
	}
	return d.String()
}

func humanDuration(d time.Duration) string {
	if d < time.Minute {
		return d.Round(time.Second).String()
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm", int(d.Round(time.Minute).Minutes()))
	}
	if d < 48*time.Hour {
		m := int(d.Round(time.Minute).Minutes())
		return fmt.Sprintf("%dh%02dm", m/60, m%60)
	}
	return fmt.Sprintf("%dd", int(d.Hours()/24))
}
