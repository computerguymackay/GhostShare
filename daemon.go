// Ported from QuickShare (github.com/computerguymackay/QuickShare).
//
// [diverges from QuickShare]
//   - Every share is served on its own Tor onion service (tor.go) instead
//     of one TCP listener, so shares can't be linked to each other. A
//     share's onion is removed from Tor as soon as the share ends.
//   - Tor can take a while to start, so the control socket opens first and
//     reports progress, and the auto-shutdown timer only runs once Tor is
//     connected. Adding a share waits until its onion is reachable.
//   - Revoke marks a share revoked instead of deleting it.
//   - Metadata is stripped by default: each share serves a stripped copy
//     from the state directory, deleted when the share ends.
//   - QuickShare's spawn.go (ensureDaemon and helpers) is at the end of this
//     file, because CLAUDE.md's layout has no spawn.go.

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

type DaemonOptions struct {
	ExternalTor  bool          // only use a running Tor; never start one
	Tor          torEnv        // where to find Tor
	Grace        time.Duration // wait this long with no active shares before exiting
	Tick         time.Duration // how often to check for expiry
	OnionTimeout time.Duration // how long Tor may take to publish one onion
}

func defaultDaemonOptions() DaemonOptions {
	return DaemonOptions{
		Tor:          defaultTorEnv(),
		Grace:        envDuration("GHOSTSHARE_GRACE", 45*time.Second),
		Tick:         envDuration("GHOSTSHARE_TICK", 10*time.Second),
		OnionTimeout: 3 * time.Minute,
	}
}

const (
	// daemonStartTimeout is how long a CLI waits for a new daemon to
	// connect to Tor (which includes starting tor, if needed).
	daemonStartTimeout = 2 * time.Minute

	// shareWaitTimeout is how long a CLI waits for a new share's onion to
	// be published and reachable. It covers Tor's bootstrap on first use.
	shareWaitTimeout = 5 * time.Minute

	// drainTimeout is how long downloads already in progress may continue
	// after their share ends and its onion is removed.
	drainTimeout = time.Hour
)

func envDuration(name string, def time.Duration) time.Duration {
	if v := os.Getenv(name); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
	}
	return def
}

var errAlreadyRunning = errors.New("another daemon is already running")

type Daemon struct {
	p   Paths
	opt DaemonOptions
	log *log.Logger

	store   *Store
	fs      *FileServer
	tor     *torSession
	runCtx  context.Context
	ctrlKey string
	session string // onion_session id: diagnostic only, never the key

	stateMu    sync.Mutex
	ready      bool
	phase      string
	torSpawned bool

	onionsMu     sync.Mutex
	onions       map[string]*shareOnion // by share token
	onionsClosed bool

	copiesMu  sync.Mutex
	preparing map[string]bool // tokens whose stripped copy is being written

	mu         sync.Mutex
	graceTimer *time.Timer

	stopOnce sync.Once
	stop     chan struct{}
}

// shareOnion is one share's own onion service and the HTTP server on it.
type shareOnion struct {
	host string
	ln   *onionListener
	srv  *http.Server
}

func newDaemon(p Paths, opt DaemonOptions, logger *log.Logger) *Daemon {
	return &Daemon{p: p, opt: opt, log: logger, stop: make(chan struct{}),
		phase: "starting", onions: map[string]*shareOnion{}, preparing: map[string]bool{}}
}

// Run serves until ctx is cancelled, a stop command arrives, or no
// shares have been active for the grace period.
func (d *Daemon) Run(ctx context.Context) error {
	if err := d.p.ensure(); err != nil {
		return err
	}
	release, err := lockFile(d.p.DaemonLock, false)
	if errors.Is(err, errLocked) {
		return errAlreadyRunning
	}
	if err != nil {
		return fmt.Errorf("daemon lock: %w", err)
	}
	defer release()

	d.store, err = openStore(d.p.DB)
	if err != nil {
		return err
	}
	defer d.store.Close()

	// Restore state: drop anything that can no longer be served.
	now := time.Now()
	removed, err := d.store.Prune(now)
	if err != nil {
		return err
	}
	for _, sh := range removed {
		d.log.Printf("dropped %s on startup (%s)", shortToken(sh.Token), deadReason(sh, now))
	}
	d.sweepCopies()

	sid, err := newToken()
	if err != nil {
		return err
	}
	d.session = sid[:8]
	d.fs = &FileServer{store: d.store, log: d.log, now: time.Now, onChange: d.evaluate}

	cl, key, err := listenControl(d.p)
	if err != nil {
		return fmt.Errorf("control socket: %w", err)
	}
	d.ctrlKey = key
	defer cleanupControl(d.p)
	defer cl.Close()

	pid := strconv.Itoa(os.Getpid())
	os.WriteFile(d.p.PID, []byte(pid+"\n"), 0o600)
	defer func() {
		if b, _ := os.ReadFile(d.p.PID); strings.TrimSpace(string(b)) == pid {
			os.Remove(d.p.PID)
		}
	}()

	// A stop request or signal also cuts slow onion publication short.
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	d.runCtx = runCtx
	go func() {
		select {
		case <-d.stop:
			cancel()
		case <-runCtx.Done():
		}
	}()

	d.log.Printf("daemon started pid=%s session=%s", pid, d.session)
	go d.serveControl(cl)

	d.setPhase("connecting to Tor")
	sess, err := connectTor(d.opt.Tor, !d.opt.ExternalTor, logWriter{d.log})
	if err != nil {
		return err
	}
	d.tor = sess
	defer func() {
		if err := sess.Close(); err != nil {
			d.log.Printf("tor shutdown: %v", err)
		}
	}()
	defer d.closeAllOnions() // runs before the Tor session closes

	d.stateMu.Lock()
	d.torSpawned = sess.spawned
	d.ready, d.phase = true, "ready"
	d.stateMu.Unlock()
	d.log.Printf("connected to Tor; ready for shares")

	// Restored shares each get a new onion address.
	if live, err := d.liveShares(); err == nil && len(live) > 0 {
		d.log.Printf("restoring %d share(s), each on a new onion address", len(live))
		for _, sh := range live {
			go func(sh Share) {
				if _, err := d.publishShare(sh); err != nil && runCtx.Err() == nil {
					d.log.Printf("share %s could not be restored: %v", shortToken(sh.Token), err)
				}
			}(sh)
		}
	}

	ticker := time.NewTicker(d.opt.Tick)
	defer ticker.Stop()
	d.evaluate()

loop:
	for {
		select {
		case <-ctx.Done():
			d.log.Printf("signal received")
			break loop
		case <-d.stop:
			break loop
		case <-ticker.C:
			d.prune()
			d.evaluate()
		}
	}

	cl.Close()
	d.closeAllOnions()
	d.log.Printf("daemon stopped; all onion services are gone")
	return nil
}

// publishShare gives a share its own onion service and waits until it
// answers through Tor. It returns the onion host.
func (d *Daemon) publishShare(sh Share) (string, error) {
	lctx, cancel := context.WithTimeout(d.runCtx, d.opt.OnionTimeout)
	defer cancel()
	ln, err := d.tor.Listen(lctx)
	if err != nil {
		return "", err
	}
	so := &shareOnion{host: ln.ID + ".onion", ln: ln}
	so.srv = newShareServer(d.onionHandler(sh.Token), d.log)
	d.onionsMu.Lock()
	if d.onionsClosed {
		d.onionsMu.Unlock()
		ln.Close()
		return "", errors.New("the daemon is shutting down")
	}
	d.onions[sh.Token] = so
	d.onionsMu.Unlock()
	go so.srv.Serve(ln)

	if err := d.tor.WaitReachable(d.runCtx, so.host, healthTimeout); err != nil {
		d.endShareOnion(sh.Token, true)
		return "", err
	}
	// The share may have been revoked or expired while we waited.
	if cur, err := d.store.Get(sh.Token); err != nil || !cur.Active(time.Now()) {
		d.endShareOnion(sh.Token, true)
		return "", errors.New("the share ended before its onion service was ready")
	}
	d.log.Printf("share %s is online on its own onion service", shortToken(sh.Token))
	return so.host, nil
}

// HTTP limits for each share's server. There is deliberately no
// ReadTimeout or WriteTimeout: a large download over Tor can legitimately
// take hours, and a whole-response deadline would cut it off.
var (
	shareReadHeaderTimeout = 20 * time.Second // generous, for Tor latency
	shareIdleTimeout       = 60 * time.Second
)

// shareMaxHeaderBytes is plenty for a browser GET and far below Go's 1 MiB
// default, so a client can't make the daemon buffer large headers.
const shareMaxHeaderBytes = 16 << 10

// newShareServer is the HTTP server for one share's onion. A client that
// doesn't finish sending its headers within shareReadHeaderTimeout (for
// example, a slowloris trickling bytes) is disconnected.
func newShareServer(h http.Handler, logger *log.Logger) *http.Server {
	return &http.Server{
		Handler:           h,
		ReadHeaderTimeout: shareReadHeaderTimeout,
		IdleTimeout:       shareIdleTimeout,
		MaxHeaderBytes:    shareMaxHeaderBytes,
		ErrorLog:          logger,
	}
}

// onionHandler serves one share's onion. Only that share's token works
// there; anything else gets the same 410 as an unknown link.
func (d *Daemon) onionHandler(token string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, _, _ := strings.Cut(strings.TrimPrefix(r.URL.Path, "/"), "/")
		if got != token {
			http.Error(w, "this link has expired or does not exist", http.StatusGone)
			return
		}
		d.fs.ServeHTTP(w, r)
		if sh, err := d.store.Get(token); err != nil || !sh.Active(time.Now()) {
			go d.endShareOnion(token, false)
		}
	})
}

// endShareOnion removes a share's onion from Tor. With hard set, open
// connections are cut; otherwise downloads in progress may finish.
func (d *Daemon) endShareOnion(token string, hard bool) {
	d.onionsMu.Lock()
	so := d.onions[token]
	delete(d.onions, token)
	d.onionsMu.Unlock()
	if so == nil {
		return
	}
	if hard {
		so.srv.Close()
	} else {
		// Shutdown stops accepting at once, then waits for active downloads.
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), drainTimeout)
			defer cancel()
			if so.srv.Shutdown(ctx) != nil {
				so.srv.Close()
			}
		}()
	}
	so.ln.Close()
	d.log.Printf("share %s: onion service removed", shortToken(token))
}

func (d *Daemon) closeAllOnions() {
	d.onionsMu.Lock()
	d.onionsClosed = true
	all := d.onions
	d.onions = map[string]*shareOnion{}
	d.onionsMu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	for _, so := range all {
		wg.Add(1)
		go func(so *shareOnion) {
			defer wg.Done()
			if so.srv.Shutdown(ctx) != nil {
				so.srv.Close()
			}
			so.ln.Close()
		}(so)
	}
	wg.Wait()
}

// onionURLs maps each share token to its current link.
func (d *Daemon) onionURLs(shares []Share) map[string]string {
	d.onionsMu.Lock()
	defer d.onionsMu.Unlock()
	urls := map[string]string{}
	for _, sh := range shares {
		if so, ok := d.onions[sh.Token]; ok {
			urls[sh.Token] = shareURL(so.host, sh)
		}
	}
	return urls
}

func (d *Daemon) setPhase(phase string) {
	d.stateMu.Lock()
	d.phase = phase
	d.stateMu.Unlock()
	d.log.Printf("%s", phase)
}

func (d *Daemon) isReady() bool {
	d.stateMu.Lock()
	defer d.stateMu.Unlock()
	return d.ready
}

func (d *Daemon) shutdown(reason string) {
	d.stopOnce.Do(func() {
		d.log.Printf("shutting down: %s", reason)
		close(d.stop)
	})
}

func (d *Daemon) prune() {
	now := time.Now()
	removed, err := d.store.Prune(now)
	if err != nil {
		d.log.Printf("prune: %v", err)
	}
	for _, sh := range removed {
		d.log.Printf("share %s ended (%s)", shortToken(sh.Token), deadReason(sh, now))
		d.endShareOnion(sh.Token, false)
	}
	d.sweepCopies()
}

// copyPath is where a share's metadata-stripped copy lives. It is derived
// from the token, never from a stored path, so cleanup can only ever
// delete ghostshare's own copies, never a user's file.
func copyPath(p Paths, token string) string { return filepath.Join(p.Files, token) }

// prepareCopy strips metadata from src into the state directory. It
// returns the path to serve ("" for the original), whether the served file
// is metadata-free, and a warning for the user. It never fails a share.
func (d *Daemon) prepareCopy(token, src string) (servePath string, stripped bool, warning string) {
	d.copiesMu.Lock()
	d.preparing[token] = true
	d.copiesMu.Unlock()
	if err := os.MkdirAll(d.p.Files, 0o700); err != nil {
		return "", false, fmt.Sprintf("couldn't create %s for the stripped copy (%v); sharing as-is", d.p.Files, err)
	}
	dst := copyPath(d.p, token)
	res := stripMetadata(src, dst)
	switch {
	case res.Copied:
		d.log.Printf("share %s: metadata removed", shortToken(token))
		return dst, true, res.Warning
	case res.Warning != "":
		d.log.Printf("share %s: sharing as-is (%s)", shortToken(token), res.Warning)
	}
	return "", res.Stripped, res.Warning
}

// donePreparing lets sweepCopies see token's copy again, once its share
// is in the store (or abandoned).
func (d *Daemon) donePreparing(token string) {
	d.copiesMu.Lock()
	delete(d.preparing, token)
	d.copiesMu.Unlock()
}

// sweepCopies deletes stripped copies whose share no longer exists. On
// Windows a copy still open for a draining download can't be deleted yet;
// a later sweep gets it.
func (d *Daemon) sweepCopies() {
	entries, err := os.ReadDir(d.p.Files)
	if err != nil {
		return
	}
	all, err := d.store.List()
	if err != nil {
		return
	}
	live := map[string]bool{}
	for _, sh := range all {
		live[sh.Token] = true
	}
	d.copiesMu.Lock()
	defer d.copiesMu.Unlock()
	for _, e := range entries {
		tok := strings.TrimSuffix(e.Name(), ".tmp")
		finished := !strings.HasSuffix(e.Name(), ".tmp")
		if (live[tok] && finished) || d.preparing[tok] {
			continue
		}
		os.Remove(filepath.Join(d.p.Files, e.Name()))
	}
}

func deadReason(sh Share, now time.Time) string {
	switch {
	case sh.Revoked:
		return "revoked"
	case !sh.Servable():
		return "file missing"
	case sh.ExpiresAt != 0 && now.Unix() >= sh.ExpiresAt:
		return "expired"
	case sh.MaxDownloads != 0 && sh.Count >= sh.MaxDownloads:
		return "download limit reached"
	}
	return "inactive"
}

// idle is true when no share is active and no request is being served.
// Callers hold d.mu.
func (d *Daemon) idle() bool {
	n, err := d.store.CountActive(time.Now())
	if err != nil {
		d.log.Printf("count active: %v", err)
		return false
	}
	return n == 0 && d.fs.InFlight() == 0
}

// evaluate starts the grace timer when idle and cancels it otherwise.
// It runs after every request, every control change and every tick,
// once Tor is connected.
func (d *Daemon) evaluate() {
	if !d.isReady() {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if !d.idle() {
		if d.graceTimer != nil {
			d.graceTimer.Stop()
			d.graceTimer = nil
			d.log.Printf("shutdown cancelled: shares are active again")
		}
		return
	}
	if d.graceTimer != nil {
		return
	}
	d.log.Printf("no active shares; exiting in %s unless a new share arrives", d.opt.Grace)
	var t *time.Timer
	t = time.AfterFunc(d.opt.Grace, func() {
		d.mu.Lock()
		defer d.mu.Unlock()
		if d.graceTimer != t {
			return
		}
		d.graceTimer = nil
		if d.idle() {
			d.shutdown("no active shares")
		}
	})
	d.graceTimer = t
}

func (d *Daemon) serveControl(l net.Listener) {
	for {
		c, err := l.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			c.SetDeadline(time.Now().Add(10 * time.Second))
			var req ctrlRequest
			if err := json.NewDecoder(c).Decode(&req); err != nil {
				return
			}
			if req.Op == "add-share" {
				// Publishing the share's onion can take a while.
				c.SetDeadline(time.Now().Add(shareWaitTimeout))
			}
			resp := d.handleControl(req)
			err := json.NewEncoder(c).Encode(resp)
			if err != nil && req.Op == "add-share" && resp.OK {
				// Nobody received the link, so nobody can use it.
				d.log.Printf("share %s: the CLI went away before getting its link; revoking", shortToken(resp.Share.Token))
				d.store.Revoke(resp.Share.Token)
				d.endShareOnion(resp.Share.Token, true)
				os.Remove(copyPath(d.p, resp.Share.Token))
				d.evaluate()
			}
			if req.Op == "stop" && resp.OK {
				d.shutdown("stop requested")
			}
		}(c)
	}
}

// liveShares lists the shares that can still be downloaded.
func (d *Daemon) liveShares() ([]Share, error) {
	all, err := d.store.List()
	if err != nil {
		return nil, err
	}
	now := time.Now()
	var live []Share
	for _, sh := range all {
		if sh.Active(now) {
			live = append(live, sh)
		}
	}
	return live, nil
}

func (d *Daemon) handleControl(req ctrlRequest) ctrlResponse {
	fail := func(format string, a ...any) ctrlResponse {
		return ctrlResponse{Error: fmt.Sprintf(format, a...)}
	}
	if d.ctrlKey != "" && req.Key != d.ctrlKey {
		return fail("unauthorized")
	}
	switch req.Op {
	case "status":
		n, _ := d.store.CountActive(time.Now())
		d.onionsMu.Lock()
		onions := len(d.onions)
		d.onionsMu.Unlock()
		d.stateMu.Lock()
		defer d.stateMu.Unlock()
		return ctrlResponse{OK: true, Status: &DaemonStatus{
			PID: os.Getpid(), Ready: d.ready, Phase: d.phase, TorSpawned: d.torSpawned,
			Active: n, Onions: onions, Version: version,
		}}

	case "add-share":
		if !d.isReady() {
			return fail("the daemon is still starting; try again in a moment")
		}
		if !filepath.IsAbs(req.Path) || !fileExists(req.Path) {
			return fail("not a readable file: %s", req.Path)
		}
		if req.MaxDownloads < 0 || req.ExpiresAt < 0 {
			return fail("invalid limits")
		}
		tok, err := newToken()
		if err != nil {
			return fail("token: %v", err)
		}
		sh := Share{Token: tok, Path: req.Path, Filename: filepath.Base(req.Path),
			Created: time.Now().Unix(), ExpiresAt: req.ExpiresAt, MaxDownloads: req.MaxDownloads,
			OnionSession: d.session}
		warning := ""
		if !req.KeepMetadata {
			sh.ServePath, sh.MetadataStripped, warning = d.prepareCopy(tok, req.Path)
		}
		err = d.store.Add(sh)
		d.donePreparing(tok)
		if err != nil {
			os.Remove(copyPath(d.p, tok))
			return fail("save share: %v", err)
		}
		d.log.Printf("share %s added: %s (%s)", shortToken(tok), sh.Filename, describeLimits(sh))
		d.evaluate()
		host, err := d.publishShare(sh)
		if err != nil {
			d.store.Delete(tok)
			os.Remove(copyPath(d.p, tok))
			d.evaluate()
			return fail("could not publish an onion service for this share: %v", err)
		}
		return ctrlResponse{OK: true, Share: &sh, URL: shareURL(host, sh), Warning: warning}

	case "list":
		live, err := d.liveShares()
		if err != nil {
			return fail("%v", err)
		}
		return ctrlResponse{OK: true, Shares: live, URLs: d.onionURLs(live)}

	case "revoke":
		live, err := d.liveShares()
		if err != nil {
			return fail("%v", err)
		}
		tok, err := resolveToken(live, req.Token)
		if err != nil {
			return fail("%v", err)
		}
		if _, err := d.store.Revoke(tok); err != nil {
			return fail("revoke: %v", err)
		}
		d.log.Printf("share %s revoked", shortToken(tok))
		d.endShareOnion(tok, true)
		os.Remove(copyPath(d.p, tok))
		d.evaluate()
		return ctrlResponse{OK: true, Share: &Share{Token: tok}}

	case "stop":
		return ctrlResponse{OK: true}
	}
	return fail("unknown op %q", req.Op)
}

func describeLimits(sh Share) string {
	var parts []string
	if sh.MaxDownloads == 0 {
		parts = append(parts, "unlimited downloads")
	} else if sh.MaxDownloads == 1 {
		parts = append(parts, "1 download")
	} else {
		parts = append(parts, itoa(sh.MaxDownloads)+" downloads")
	}
	if sh.ExpiresAt == 0 {
		parts = append(parts, "no expiry")
	} else {
		parts = append(parts, "expires "+time.Unix(sh.ExpiresAt, 0).Format("2006-01-02 15:04 MST"))
	}
	return strings.Join(parts, ", ")
}

func itoa(n int) string { return strconv.Itoa(n) }

// logWriter sends each line written to it to a logger, so Tor progress
// messages land in the daemon log with timestamps.
type logWriter struct{ l *log.Logger }

func (w logWriter) Write(p []byte) (int, error) {
	for _, line := range strings.Split(strings.TrimRight(string(p), "\n"), "\n") {
		w.l.Print(line)
	}
	return len(p), nil
}

// ---- Daemon spawning (QuickShare: spawn.go) ----

var errDaemonExited = errors.New("daemon exited")

// ensureDaemon returns the status of a ready daemon, starting one if
// needed. spawned reports whether this call started it. Startup progress
// goes to progress (stderr).
func ensureDaemon(p Paths, opt DaemonOptions, progress io.Writer) (st DaemonStatus, spawned bool, err error) {
	if _, err := daemonStatus(p); err == nil {
		st, err := waitReady(p, progress, nil)
		return st, false, err
	}
	if err := p.ensure(); err != nil {
		return st, false, err
	}

	// Serialise probe+spawn so parallel invocations start one daemon.
	release, err := lockFile(p.SpawnLock, true)
	if err != nil {
		return st, false, fmt.Errorf("spawn lock: %w", err)
	}
	defer release()

	if _, err := daemonStatus(p); err == nil {
		st, err := waitReady(p, progress, nil)
		return st, false, err
	}
	clearStale(p)

	// [diverges from QuickShare] Check Tor before starting a daemon, so a
	// missing Tor is reported at once instead of from a failed daemon's log.
	if err := torPreflight(opt.Tor, opt.ExternalTor); err != nil {
		return st, false, err
	}

	exe, err := os.Executable()
	if err != nil {
		return st, false, err
	}
	rotateLog(p.Log)
	logf, err := os.OpenFile(p.Log, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return st, false, err
	}
	defer logf.Close()

	args := []string{"__daemon"}
	if opt.ExternalTor {
		args = append(args, "--external-tor")
	}
	cmd := exec.Command(exe, args...)
	cmd.Dir = p.Home
	cmd.Stdout = logf
	cmd.Stderr = logf
	cmd.SysProcAttr = detachAttr()
	logStart, _ := logf.Seek(0, 2)
	if err := cmd.Start(); err != nil {
		return st, false, fmt.Errorf("start daemon: %w", err)
	}
	exited := make(chan error, 1)
	go func() { exited <- cmd.Wait() }()

	st, err = waitReady(p, progress, exited)
	if errors.Is(err, errDaemonExited) {
		// It may have lost a race to another daemon that is now up.
		if _, err := daemonStatus(p); err == nil {
			st, err := waitReady(p, progress, nil)
			return st, false, err
		}
		return st, false, fmt.Errorf("daemon failed to start:\n%s", logSince(p.Log, logStart))
	}
	return st, err == nil, err
}

// waitReady polls the daemon until its onion service is reachable,
// printing each startup step once. exited, if not nil, fires when the
// daemon process this CLI started has exited.
func waitReady(p Paths, progress io.Writer, exited <-chan error) (DaemonStatus, error) {
	deadline := time.After(daemonStartTimeout)
	lastPhase := ""
	for {
		st, err := daemonStatus(p)
		switch {
		case err == nil && st.Ready:
			return st, nil
		case err == nil:
			if st.Phase != lastPhase {
				fmt.Fprintf(progress, "%s…\n", st.Phase)
				lastPhase = st.Phase
			}
		case exited == nil:
			return st, fmt.Errorf("the daemon stopped while starting; see %s", p.Log)
		}
		select {
		case <-exited:
			return st, errDaemonExited
		case <-deadline:
			return st, fmt.Errorf("the daemon was not ready within %v; see %s", daemonStartTimeout, p.Log)
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// clearStale removes a PID file and socket left by a daemon that died.
// If the daemon lock is free, no daemon is alive.
func clearStale(p Paths) {
	release, err := lockFile(p.DaemonLock, false)
	if err != nil {
		return // a daemon holds it (maybe still starting up)
	}
	defer release()
	os.Remove(p.PID)
	cleanupControl(p)
}

// daemonAlive reports whether a daemon process holds the daemon lock.
func daemonAlive(p Paths) bool {
	release, err := lockFile(p.DaemonLock, false)
	if err != nil {
		return errors.Is(err, errLocked)
	}
	release()
	return false
}

func rotateLog(path string) {
	if fi, err := os.Stat(path); err == nil && fi.Size() > 5<<20 {
		os.Rename(path, path+".1")
	}
}

func logSince(path string, offset int64) string {
	b, err := os.ReadFile(path)
	if err != nil || offset > int64(len(b)) {
		return "  (no log output)"
	}
	s := strings.TrimSpace(string(b[offset:]))
	if s == "" {
		return "  (no log output)"
	}
	return "  " + strings.ReplaceAll(s, "\n", "\n  ")
}
