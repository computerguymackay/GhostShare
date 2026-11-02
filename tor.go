// tor.go is the only file that touches Tor. It finds a Tor to use (a running
// one first, else one started from PATH), creates the v3 onion service, and
// checks that the onion is reachable before a link is shown. There is no
// clearnet fallback: if no Tor is usable, the caller gets an error with
// install instructions.

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/textproto"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cretz/bine/control"
	"github.com/cretz/bine/process"
	"github.com/cretz/bine/tor"
	"golang.org/x/net/proxy"
)

const (
	defaultControlAddr = "127.0.0.1:9051"
	defaultSocksAddr   = "127.0.0.1:9050"

	// onionPort is the port on the .onion address, so links need no port.
	onionPort = 80

	// healthTimeout is the total budget for the reachability check. On the
	// live network a new onion usually answered within 2-24s, but a lookup
	// sometimes stalls and only a fresh attempt gets through, so allow
	// several attempts.
	healthTimeout = 2 * time.Minute
	killTimeout   = 5 * time.Second
)

// controlTimeout bounds each step of talking to a control port. Tests lower it.
var controlTimeout = 5 * time.Second

const torInstallHelp = `GhostShare needs Tor and never falls back to the open internet.
Install Tor, then run ghostshare again:
  Debian/Ubuntu:  sudo apt install tor
  Fedora:         sudo dnf install tor
  macOS:          brew install tor
  Windows:        download the Tor Expert Bundle from
                  https://www.torproject.org/download/tor/
                  and put tor.exe on your PATH
Or run Tor yourself with a control port on 127.0.0.1:9051
(set GHOSTSHARE_TOR_CONTROL to use a different address).`

const torAuthHelp = `Tor is running, but ghostshare could not log in to its control port.
If Tor runs as a system service, your user needs to read its auth cookie:
  Debian/Ubuntu:  sudo usermod -aG debian-tor $USER   (then log out and back in)
Or enable cookie auth in torrc: CookieAuthentication 1`

// errTorAuth marks a control port that answered but refused our login.
var errTorAuth = errors.New("control port authentication failed")

// torEnv is where to look for Tor. Tests replace it.
type torEnv struct {
	controlAddr string
	socksAddr   string // empty: ask Tor, then fall back to defaultSocksAddr
	lookPath    func(file string) (string, error)
	dataDir     string // parent of a spawned Tor's data directory; empty: os.TempDir()
}

func defaultTorEnv() torEnv {
	env := torEnv{
		controlAddr: defaultControlAddr,
		socksAddr:   os.Getenv("GHOSTSHARE_TOR_SOCKS"),
		lookPath:    exec.LookPath,
	}
	if v := os.Getenv("GHOSTSHARE_TOR_CONTROL"); v != "" {
		env.controlAddr = v
	}
	return env
}

// attachTor connects to a running Tor's control port and logs in with
// cookie or no-auth. Closing the returned Tor never stops that Tor.
func attachTor(addr string) (*tor.Tor, string, error) {
	conn, err := net.DialTimeout("tcp", addr, controlTimeout)
	if err != nil {
		return nil, "", err
	}
	// A deadline stops us hanging on a port that isn't Tor.
	conn.SetDeadline(time.Now().Add(controlTimeout))
	ctl := control.NewConn(textproto.NewConn(conn))
	if err := ctl.Authenticate(""); err != nil {
		ctl.Close()
		return nil, "", fmt.Errorf("%w: %v", errTorAuth, err)
	}
	version := ""
	if info, err := ctl.GetInfo("version"); err == nil && len(info) == 1 {
		version, _, _ = strings.Cut(info[0].Val, " ")
	}
	conn.SetDeadline(time.Time{})
	return &tor.Tor{Control: ctl, StopProcessOnClose: false}, version, nil
}

type torState string

const (
	torRunning   torState = "running"
	torSpawnable torState = "spawnable"
	torMissing   torState = "missing"
)

// torStatus is what `ghostshare tor-status` reports.
type torStatus struct {
	State       torState
	ControlAddr string
	Version     string // set when State is torRunning
	TorPath     string // set when State is torSpawnable
	AttachErr   error  // why the running-Tor check failed
}

// probeTor runs the same checks as connectTor, in the same order, without
// starting Tor.
func probeTor(env torEnv) torStatus {
	st := torStatus{ControlAddr: env.controlAddr}
	t, version, err := attachTor(env.controlAddr)
	if err == nil {
		t.Close()
		st.State, st.Version = torRunning, version
		return st
	}
	st.AttachErr = err
	if path, err := env.lookPath("tor"); err == nil {
		st.State, st.TorPath = torSpawnable, path
		return st
	}
	st.State = torMissing
	return st
}

func writeTorStatus(w io.Writer, st torStatus) {
	fmt.Fprintf(w, "Tor: %s\n", st.State)
	switch st.State {
	case torRunning:
		v := ""
		if st.Version != "" {
			v = " (Tor " + st.Version + ")"
		}
		fmt.Fprintf(w, "  control port %s is working%s.\n", st.ControlAddr, v)
		fmt.Fprintln(w, "  ghostshare will use this Tor and leave it running when it exits.")
	case torSpawnable:
		fmt.Fprintf(w, "  no usable Tor on control port %s (%v).\n", st.ControlAddr, st.AttachErr)
		fmt.Fprintf(w, "  found %s: ghostshare will start it when sharing and stop it on exit.\n", st.TorPath)
		if errors.Is(st.AttachErr, errTorAuth) {
			fmt.Fprintln(w)
			fmt.Fprintln(w, torAuthHelp)
		}
	case torMissing:
		fmt.Fprintf(w, "  no usable Tor on control port %s (%v).\n", st.ControlAddr, st.AttachErr)
		fmt.Fprintln(w, "  no tor program on PATH.")
		fmt.Fprintln(w)
		if errors.Is(st.AttachErr, errTorAuth) {
			fmt.Fprintln(w, torAuthHelp)
		} else {
			fmt.Fprintln(w, torInstallHelp)
		}
	}
}

// torSession is the Tor that one daemon session uses.
type torSession struct {
	t           *tor.Tor
	spawned     bool
	proc        *torProcess // set when spawned
	controlAddr string
	socksAddr   string // override from env, may be empty

	// mu is held for every control-port command, and guards closed, so
	// onions and the session close in any order. bine deadlocks when two
	// goroutines send commands at once (each takes its read lock and its
	// textproto pipeline turn in an order that can cross), which happened
	// with two shares publishing together.
	mu       sync.Mutex
	closed   bool
	closeErr error
}

var errSessionClosed = errors.New("the Tor session is closed")

// control runs fn, which sends control-port commands, on its own.
func (s *torSession) control(fn func() error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return errSessionClosed
	}
	return fn()
}

// onionListener is the session's onion service as a net.Listener. Closing
// it is safe even after the session has closed.
type onionListener struct {
	*tor.OnionService
	sess *torSession
	once sync.Once
	err  error
}

func (o *onionListener) Close() error {
	o.once.Do(func() {
		o.sess.mu.Lock()
		defer o.sess.mu.Unlock()
		if o.sess.closed {
			// Tor dropped the onion with our control connection; only the
			// local listener is left.
			if o.LocalListener != nil {
				o.err = o.LocalListener.Close()
			}
			return
		}
		o.err = o.OnionService.Close()
	})
	return o.err
}

// connectTor finds a Tor in the order CLAUDE.md requires: a running Tor's
// control port, else a tor on PATH (only if allowSpawn), else an error.
// Progress messages go to progress (stderr), never stdout.
func connectTor(env torEnv, allowSpawn bool, progress io.Writer) (*torSession, error) {
	t, version, err := attachTor(env.controlAddr)
	if err == nil {
		v := ""
		if version != "" {
			v = " (Tor " + version + ")"
		}
		fmt.Fprintf(progress, "using the running Tor at %s%s\n", env.controlAddr, v)
		return &torSession{t: t, controlAddr: env.controlAddr, socksAddr: env.socksAddr}, nil
	}
	attachErr := err
	if !allowSpawn {
		return nil, torUnavailable(env.controlAddr, attachErr, true)
	}
	path, err := env.lookPath("tor")
	if err != nil {
		return nil, torUnavailable(env.controlAddr, attachErr, false)
	}
	fmt.Fprintf(progress, "no running Tor at %s; starting %s\n", env.controlAddr, path)
	t, proc, err := spawnTor(path, env.dataDir)
	if err != nil {
		return nil, err
	}
	return &torSession{t: t, spawned: true, proc: proc, socksAddr: env.socksAddr}, nil
}

// torPreflight checks, without starting anything, that connectTor would
// find a usable Tor. The error says what to do next.
func torPreflight(env torEnv, externalTor bool) error {
	st := probeTor(env)
	if st.State == torRunning || (st.State == torSpawnable && !externalTor) {
		return nil
	}
	return torUnavailable(st.ControlAddr, st.AttachErr, externalTor)
}

// torUnavailable is the error for "no Tor we may use", with install or
// auth instructions.
func torUnavailable(controlAddr string, attachErr error, externalTor bool) error {
	help := torInstallHelp
	if errors.Is(attachErr, errTorAuth) {
		help = torAuthHelp
	}
	if externalTor {
		return fmt.Errorf("--external-tor: no usable Tor on control port %s (%v)\n\n%s", controlAddr, attachErr, help)
	}
	return fmt.Errorf("no usable Tor on control port %s (%v), and no tor program on PATH\n\n%s", controlAddr, attachErr, help)
}

// spawnTor starts a private Tor with a fresh data directory inside base
// (os.TempDir() if empty). Tor's own output is captured, not printed, so it
// can't reach stdout.
func spawnTor(path, base string) (*tor.Tor, *torProcess, error) {
	if base == "" {
		base = os.TempDir()
	} else if err := os.MkdirAll(base, 0o700); err != nil {
		return nil, nil, fmt.Errorf("tor data directory: %w", err)
	}
	out := &tailBuffer{max: 4096}
	creator := &torCreator{path: path, out: out}
	t, err := tor.Start(context.Background(), &tor.StartConf{
		ProcessCreator:  creator,
		TempDataDirBase: base,
		// Tor exits by itself if ghostshare dies without cleaning up.
		ExtraArgs: []string{"__OwningControllerProcess", strconv.Itoa(os.Getpid())},
	})
	if err != nil {
		// tor.Start already tried to close; make sure the process is gone.
		if creator.proc != nil {
			creator.proc.stop()
		}
		msg := fmt.Sprintf("could not start %s: %v", path, err)
		if tail := strings.TrimSpace(out.String()); tail != "" {
			msg += "\ntor output:\n" + tail
		}
		return nil, nil, errors.New(msg)
	}
	return t, creator.proc, nil
}

// Listen creates the session's v3 onion service on port 80. The private key
// is discarded by Tor and never reaches ghostshare, so it can't be written
// anywhere. The service is removed when it or the session is closed.
//
// Listen returns once the onion's descriptor is on several directory
// servers (see waitPublished), not just the first one, so the reachability
// check that follows doesn't look it up too early.
func (s *torSession) Listen(ctx context.Context) (*onionListener, error) {
	// A spawned Tor starts with its network off; turn it on and wait for
	// bootstrap (other shares wait too). For a running Tor this is a no-op.
	if err := s.control(func() error { return s.t.EnableNetwork(ctx, true) }); err != nil {
		return nil, fmt.Errorf("connect Tor to the network: %w", err)
	}

	// Listen for descriptor uploads before the onion exists, so none are
	// missed. bine relays events with a blocking send, so the buffer is
	// large and the listener is removed before we stop reading it.
	events := make(chan control.Event, 256)
	if err := s.control(func() error { return s.t.Control.AddEventListener(events, control.EventCodeHSDesc) }); err != nil {
		return nil, fmt.Errorf("watch onion publication: %w", err)
	}
	evCtx, stopEvents := context.WithCancel(ctx)
	go s.t.Control.HandleEvents(evCtx)
	defer func() {
		s.control(func() error { return s.t.Control.RemoveEventListener(events, control.EventCodeHSDesc) })
		stopEvents()
	}()

	var svc *tor.OnionService
	err := s.control(func() (err error) {
		svc, err = s.t.Listen(ctx, &tor.ListenConf{
			Version3:    true,
			DiscardKey:  true,
			RemotePorts: []int{onionPort},
			NoWait:      true, // waitPublished below does the waiting
		})
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("create onion service: %w", err)
	}
	onion := &onionListener{OnionService: svc, sess: s}
	if svc.Key != nil {
		onion.Close()
		return nil, errors.New("create onion service: Tor returned a private key despite DiscardPK; refusing to continue")
	}
	if err := waitPublished(ctx, events, svc.ID); err != nil {
		onion.Close()
		return nil, fmt.Errorf("publish onion service: %w", err)
	}
	return onion, nil
}

// Tor uploads each onion's two descriptors to 8 directory servers each,
// all at once; on the live network they all finished within ~3s of each
// other. A client that looks the onion up on a server that doesn't have it
// yet gets a failure, and Tor then won't ask those servers again for about
// 15 minutes. So wait for every upload, not just the first.
//
// extraUploadWait caps the wait after the first successful upload, in case
// some uploads never report back (one of 16 often doesn't).
var extraUploadWait = 10 * time.Second

// waitPublished waits until every descriptor upload for id has finished
// with at least one success, or one upload succeeded and extraUploadWait
// has passed. It fails if every upload attempt fails.
func waitPublished(ctx context.Context, events <-chan control.Event, id string) error {
	attempted, uploaded, failed := 0, 0, 0
	var reasons []string
	var extra <-chan time.Time
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-extra:
			return nil
		case ev := <-events:
			hs, _ := ev.(*control.HSDescEvent)
			if hs == nil || hs.Address != id {
				continue
			}
			switch hs.Action {
			case "UPLOAD":
				attempted++
			case "UPLOADED":
				uploaded++
				if extra == nil {
					extra = time.After(extraUploadWait)
				}
			case "FAILED":
				failed++
				reasons = append(reasons, hs.Reason)
			default:
				continue
			}
			if attempted > 0 && uploaded+failed >= attempted {
				if uploaded == 0 {
					return fmt.Errorf("every descriptor upload failed (%s)", strings.Join(reasons, ", "))
				}
				return nil // all uploads done
			}
		}
	}
}

// WaitReachable blocks until host answers HTTP through Tor's SOCKS proxy,
// so a link is never shown before it works.
func (s *torSession) WaitReachable(ctx context.Context, host string, timeout time.Duration) error {
	return waitReachable(ctx, s.socks(), host, timeout)
}

func (s *torSession) socks() string {
	if s.socksAddr != "" {
		return s.socksAddr
	}
	addr := ""
	s.control(func() error {
		if info, err := s.t.Control.GetInfo("net/listeners/socks"); err == nil && len(info) == 1 {
			addr = firstTCPListener(info[0].Val)
		}
		return nil
	})
	if addr != "" {
		return addr
	}
	return defaultSocksAddr
}

// firstTCPListener picks the first TCP address from a GETINFO
// net/listeners/socks value such as `"127.0.0.1:9050" "[::1]:9050"`.
func firstTCPListener(v string) string {
	for _, f := range strings.Fields(v) {
		f = strings.Trim(f, `"`)
		if f != "" && !strings.HasPrefix(f, "unix:") {
			return f
		}
	}
	return ""
}

// reachAttemptTimeout bounds one reachability request through Tor: longer
// than a slow successful lookup (24s measured), short enough that a stalled
// one is abandoned for a fresh attempt.
var reachAttemptTimeout = 30 * time.Second

func waitReachable(ctx context.Context, socksAddr, host string, timeout time.Duration) error {
	dialer, err := proxy.SOCKS5("tcp", socksAddr, nil, proxy.Direct)
	if err != nil {
		return err
	}
	cd, ok := dialer.(proxy.ContextDialer)
	if !ok {
		return errors.New("SOCKS dialer does not support contexts")
	}
	client := &http.Client{Transport: &http.Transport{
		DialContext:       cd.DialContext,
		DisableKeepAlives: true,
	}}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	for {
		// Bound each attempt, so one stuck lookup can't use up the whole budget.
		actx, acancel := context.WithTimeout(ctx, reachAttemptTimeout)
		req, _ := http.NewRequestWithContext(actx, http.MethodHead, "http://"+host+"/", nil)
		resp, err := client.Do(req)
		acancel()
		if err == nil {
			resp.Body.Close()
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("onion service not reachable through Tor (SOCKS %s) after %v: %v", socksAddr, timeout, err)
		case <-time.After(time.Second):
		}
	}
}

// Close removes the onion service and, if we started Tor, stops it and
// deletes its data directory. An attached Tor is left running.
func (s *torSession) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return s.closeErr
	}
	s.closed = true
	err := s.t.Close()
	if !s.spawned {
		s.closeErr = err
		return s.closeErr
	}
	// bine waits only 300ms for Tor to exit; make sure it does.
	if !s.proc.stop() {
		s.closeErr = fmt.Errorf("tor (pid %d) did not exit", s.proc.cmd.Process.Pid)
		return s.closeErr
	}
	if s.t.DataDir != "" {
		os.RemoveAll(s.t.DataDir)
	}
	return nil
}

// torCreator starts tor with its output captured, and keeps a handle on the
// process so Close can make sure it exits.
type torCreator struct {
	path string
	out  io.Writer
	proc *torProcess
}

func (c *torCreator) New(ctx context.Context, args ...string) (process.Process, error) {
	cmd := exec.CommandContext(ctx, c.path, args...)
	cmd.Stdout, cmd.Stderr = c.out, c.out
	c.proc = &torProcess{cmd: cmd, done: make(chan struct{})}
	return c.proc, nil
}

// torProcess is a bine process whose Wait can be called more than once.
type torProcess struct {
	cmd  *exec.Cmd
	done chan struct{}
	err  error
}

func (p *torProcess) Start() error {
	if err := p.cmd.Start(); err != nil {
		close(p.done)
		p.err = err
		return err
	}
	go func() {
		p.err = p.cmd.Wait()
		close(p.done)
	}()
	return nil
}

func (p *torProcess) Wait() error {
	<-p.done
	return p.err
}

func (p *torProcess) EmbeddedControlConn() (net.Conn, error) {
	return nil, process.ErrControlConnUnsupported
}

// stop waits for the process to exit, killing it if it takes too long.
// It reports whether the process is gone.
func (p *torProcess) stop() bool {
	if p.cmd.Process == nil {
		return true
	}
	select {
	case <-p.done:
		return true
	case <-time.After(killTimeout):
	}
	p.cmd.Process.Kill()
	select {
	case <-p.done:
		return true
	case <-time.After(killTimeout):
		return false
	}
}

// tailBuffer keeps the last max bytes written to it.
type tailBuffer struct {
	mu  sync.Mutex
	max int
	b   []byte
}

func (t *tailBuffer) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.b = append(t.b, p...)
	if len(t.b) > t.max {
		t.b = t.b[len(t.b)-t.max:]
	}
	return len(p), nil
}

func (t *tailBuffer) String() string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return string(t.b)
}

// sweepTorData deletes the data directories that spawned Tors left in dir
// when their daemon was killed before it could clean up. Call it only while
// holding the daemon lock, so no live Tor of ours is using them. They hold
// Tor's caches and state, never onion keys. It returns how many it removed.
func sweepTorData(dir string) int {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}
	n := 0
	for _, e := range entries {
		if os.RemoveAll(filepath.Join(dir, e.Name())) == nil {
			n++
		}
	}
	return n
}
