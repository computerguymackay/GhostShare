// Ported from QuickShare (github.com/computerguymackay/QuickShare).
//
// [diverges from QuickShare]
//   - The daemon serves over a Tor onion service (tor.go) instead of a TCP
//     listener. Tor can take a minute to start, so the control socket opens
//     first and reports progress, and the auto-shutdown timer only runs once
//     the onion is reachable.
//   - Revoke marks a share revoked instead of deleting it.
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
	OnionTimeout time.Duration // how long Tor may take to publish the onion
}

func defaultDaemonOptions() DaemonOptions {
	return DaemonOptions{
		Tor:          defaultTorEnv(),
		Grace:        envDuration("GHOSTSHARE_GRACE", 45*time.Second),
		Tick:         envDuration("GHOSTSHARE_TICK", 10*time.Second),
		OnionTimeout: 3 * time.Minute,
	}
}

// daemonStartTimeout is how long a CLI waits for a new daemon to be ready:
// Tor bootstrap, onion publication, and the reachability check.
const daemonStartTimeout = 4 * time.Minute

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
	ctrlKey string
	session string // onion_session id: diagnostic only, never the key

	stateMu    sync.Mutex
	ready      bool
	phase      string
	onion      string
	torSpawned bool

	mu         sync.Mutex
	graceTimer *time.Timer

	stopOnce sync.Once
	stop     chan struct{}
}

func newDaemon(p Paths, opt DaemonOptions, logger *log.Logger) *Daemon {
	return &Daemon{p: p, opt: opt, log: logger, stop: make(chan struct{}), phase: "starting"}
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
	if n, _ := d.store.CountActive(now); n > 0 {
		d.log.Printf("restored %d share(s); they get this session's new onion address", n)
	}

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

	d.log.Printf("daemon started pid=%s session=%s", pid, d.session)
	go d.serveControl(cl)

	// A stop request or signal also cuts a slow Tor startup short.
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		select {
		case <-d.stop:
			cancel()
		case <-runCtx.Done():
		}
	}()

	d.setPhase("connecting to Tor")
	sess, err := connectTor(d.opt.Tor, !d.opt.ExternalTor, logWriter{d.log})
	if err != nil {
		return err
	}
	defer func() {
		if err := sess.Close(); err != nil {
			d.log.Printf("tor shutdown: %v", err)
		}
	}()
	d.stateMu.Lock()
	d.torSpawned = sess.spawned
	d.stateMu.Unlock()

	d.setPhase("publishing the onion service (this can take a minute)")
	lctx, lcancel := context.WithTimeout(runCtx, d.opt.OnionTimeout)
	onion, err := sess.Listen(lctx)
	lcancel()
	if err != nil {
		if runCtx.Err() != nil {
			d.log.Printf("stopped during startup")
			return nil
		}
		return err
	}
	defer onion.Close()
	host := onion.ID + ".onion"

	srv := &http.Server{
		Handler:           d.fs,
		ReadHeaderTimeout: 15 * time.Second,
		IdleTimeout:       60 * time.Second,
		ErrorLog:          d.log,
	}
	srvErr := make(chan error, 1)
	go func() { srvErr <- srv.Serve(onion) }()

	d.setPhase("checking that the onion service is reachable")
	if err := sess.WaitReachable(runCtx, host, healthTimeout); err != nil {
		srv.Close()
		if runCtx.Err() != nil {
			d.log.Printf("stopped during startup")
			return nil
		}
		return err
	}
	d.stateMu.Lock()
	d.ready, d.onion, d.phase = true, host, "ready"
	d.stateMu.Unlock()
	d.log.Printf("onion service ready at %s (session %s)", host, d.session)

	ticker := time.NewTicker(d.opt.Tick)
	defer ticker.Stop()
	d.evaluate()

	var exitErr error
loop:
	for {
		select {
		case <-ctx.Done():
			d.log.Printf("signal received")
			break loop
		case <-d.stop:
			break loop
		case err := <-srvErr:
			exitErr = fmt.Errorf("http server: %w", err)
			break loop
		case <-ticker.C:
			d.prune()
			d.evaluate()
		}
	}

	cl.Close()
	sctx, scancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer scancel()
	if err := srv.Shutdown(sctx); err != nil {
		srv.Close()
	}
	d.log.Printf("daemon stopped; the onion service is gone")
	return exitErr
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
	}
}

func deadReason(sh Share, now time.Time) string {
	switch {
	case sh.Revoked:
		return "revoked"
	case !fileExists(sh.Path):
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
// once the onion service is ready.
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
			resp := d.handleControl(req)
			json.NewEncoder(c).Encode(resp)
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
		d.stateMu.Lock()
		defer d.stateMu.Unlock()
		return ctrlResponse{OK: true, Status: &DaemonStatus{
			PID: os.Getpid(), Ready: d.ready, Phase: d.phase, Onion: d.onion,
			TorSpawned: d.torSpawned, Active: n, Version: version,
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
		if err := d.store.Add(sh); err != nil {
			return fail("save share: %v", err)
		}
		d.log.Printf("share %s added: %s (%s)", shortToken(tok), sh.Filename, describeLimits(sh))
		d.evaluate()
		return ctrlResponse{OK: true, Share: &sh}

	case "list":
		live, err := d.liveShares()
		if err != nil {
			return fail("%v", err)
		}
		return ctrlResponse{OK: true, Shares: live}

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
