// Ported from QuickShare (github.com/computerguymackay/QuickShare).
//
// The daemon runs against fakeTor (faketor_test.go), so these tests cover
// the real Tor code path without Tor or a network.

package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// testPaths returns paths under a short temp dir (Unix socket paths
// have a length limit).
func testPaths(t *testing.T) Paths {
	t.Helper()
	dir, err := os.MkdirTemp("", "gs")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	t.Setenv("GHOSTSHARE_HOME", dir)
	p, err := resolvePaths()
	if err != nil {
		t.Fatal(err)
	}
	return p
}

type runningDaemon struct {
	p      Paths
	ft     *fakeTor
	exited chan struct{} // closed when Run returns, so any number of waiters see it
	err    error         // Run's result, valid once exited is closed
	cancel context.CancelFunc
}

func testDaemonOptions(ft *fakeTor, grace time.Duration) DaemonOptions {
	return DaemonOptions{Tor: ft.env(), Grace: grace, Tick: 100 * time.Millisecond, OnionTimeout: 5 * time.Second}
}

func startTestDaemonWithLog(t *testing.T, p Paths, ft *fakeTor, grace time.Duration, logw io.Writer) *runningDaemon {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	rd := &runningDaemon{p: p, ft: ft, exited: make(chan struct{}), cancel: cancel}
	go func() {
		rd.err = newDaemon(p, testDaemonOptions(ft, grace), log.New(logw, "", 0)).Run(ctx)
		close(rd.exited)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-rd.exited:
		case <-time.After(5 * time.Second):
		}
	})
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if st, err := daemonStatus(p); err == nil && st.Ready {
			return rd
		}
		select {
		case <-rd.exited:
			t.Fatalf("daemon exited early: %v", rd.err)
		case <-time.After(20 * time.Millisecond):
		}
	}
	t.Fatal("daemon did not become ready")
	return nil
}

func startTestDaemon(t *testing.T, p Paths, ft *fakeTor, grace time.Duration) *runningDaemon {
	t.Helper()
	return startTestDaemonWithLog(t, p, ft, grace, io.Discard)
}

// add shares a file and returns the share and its link.
func (rd *runningDaemon) add(t *testing.T, path string, max int, expiresAt int64) (Share, string) {
	t.Helper()
	resp, err := ctrlCallTimeout(rd.p, ctrlRequest{Op: "add-share", Path: path, MaxDownloads: max, ExpiresAt: expiresAt}, 10*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if resp.URL == "" {
		t.Fatal("add-share returned no link")
	}
	return *resp.Share, resp.URL
}

// get downloads a link through the fake Tor's SOCKS proxy. It returns 0
// when the link's onion is gone.
func (rd *runningDaemon) get(t *testing.T, link string) int {
	t.Helper()
	code, _, ok := onionGet(t, rd.ft.socksAddr(), link)
	if !ok {
		return 0
	}
	return code
}

// waitGone waits until a link's onion has been removed from Tor.
func (rd *runningDaemon) waitGone(t *testing.T, link string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for rd.get(t, link) != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("%s still reachable", link)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func (rd *runningDaemon) urls(t *testing.T) map[string]string {
	t.Helper()
	resp, err := ctrlCall(rd.p, ctrlRequest{Op: "list"})
	if err != nil {
		t.Fatal(err)
	}
	return resp.URLs
}

func (rd *runningDaemon) exitsWithin(d time.Duration) bool {
	select {
	case <-rd.exited:
		return true
	case <-time.After(d):
		return false
	}
}

func TestDaemonExitsAfterLastDownload(t *testing.T) {
	p := testPaths(t)
	rd := startTestDaemon(t, p, newFakeTor(t, "AUTH METHODS=NULL"), 500*time.Millisecond)
	_, link := rd.add(t, testFile(t, "data"), 1, 0)
	if rd.exitsWithin(800 * time.Millisecond) {
		t.Fatal("daemon exited while a share was active")
	}
	if code := rd.get(t, link); code != 200 {
		t.Fatalf("download: %d", code)
	}
	if rd.exitsWithin(200 * time.Millisecond) {
		t.Fatal("daemon exited before the grace period")
	}
	if !rd.exitsWithin(2 * time.Second) {
		t.Fatal("daemon did not exit after the download limit was reached")
	}
}

func TestDaemonExitsOnExpiry(t *testing.T) {
	p := testPaths(t)
	rd := startTestDaemon(t, p, newFakeTor(t, "AUTH METHODS=NULL"), 200*time.Millisecond)
	rd.add(t, testFile(t, "data"), 1, time.Now().Add(2*time.Second).Unix())
	if rd.exitsWithin(time.Second) {
		t.Fatal("daemon exited before the share expired")
	}
	if !rd.exitsWithin(3 * time.Second) {
		t.Fatal("daemon did not exit after expiry")
	}
}

func TestOneDaemonManySharesExitsWhenLastEnds(t *testing.T) {
	p := testPaths(t)
	rd := startTestDaemon(t, p, newFakeTor(t, "AUTH METHODS=NULL"), 300*time.Millisecond)
	_, a := rd.add(t, testFile(t, "a"), 1, 0)
	_, b := rd.add(t, testFile(t, "b"), 1, 0)

	rd.get(t, a)
	if rd.exitsWithin(time.Second) {
		t.Fatal("daemon exited with one share still active")
	}
	if resp, err := ctrlCall(p, ctrlRequest{Op: "list"}); err != nil || len(resp.Shares) != 1 {
		t.Fatalf("list after first download: %+v %v", resp.Shares, err)
	}
	rd.get(t, b)
	if !rd.exitsWithin(2 * time.Second) {
		t.Fatal("daemon did not exit after the last share ended")
	}
}

func TestNewShareCancelsGrace(t *testing.T) {
	p := testPaths(t)
	rd := startTestDaemon(t, p, newFakeTor(t, "AUTH METHODS=NULL"), 600*time.Millisecond)
	_, a := rd.add(t, testFile(t, "a"), 1, 0)
	rd.get(t, a) // grace starts
	time.Sleep(300 * time.Millisecond)
	rd.add(t, testFile(t, "b"), 1, 0)
	if rd.exitsWithin(time.Second) {
		t.Fatal("daemon exited even though a new share arrived during the grace period")
	}
}

func TestRevokeEndsShare(t *testing.T) {
	p := testPaths(t)
	rd := startTestDaemon(t, p, newFakeTor(t, "AUTH METHODS=NULL"), 200*time.Millisecond)
	sh, link := rd.add(t, testFile(t, "a"), 1, 0)
	if _, err := ctrlCall(p, ctrlRequest{Op: "revoke", Token: sh.Token[:8]}); err != nil {
		t.Fatal(err)
	}
	rd.waitGone(t, link)
	if _, err := ctrlCall(p, ctrlRequest{Op: "revoke", Token: sh.Token[:8]}); err == nil {
		t.Fatal("revoking an already revoked share succeeded")
	}
	if !rd.exitsWithin(2 * time.Second) {
		t.Fatal("daemon did not exit after revoking the only share")
	}
}

func TestRestartRestoresLiveShares(t *testing.T) {
	p := testPaths(t)
	if err := p.ensure(); err != nil {
		t.Fatal(err)
	}
	f := testFile(t, "data")
	st, err := openStore(p.DB)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	st.Add(Share{Token: "live-share-000000000000", Path: f, MaxDownloads: 1, ExpiresAt: now.Add(time.Hour).Unix()})
	st.Add(Share{Token: "expired-share-000000000", Path: f, MaxDownloads: 1, ExpiresAt: now.Add(-time.Minute).Unix()})
	st.Add(Share{Token: "missing-file-0000000000", Path: "/nonexistent/x", MaxDownloads: 1})
	st.Add(Share{Token: "revoked-share-000000000", Path: f, MaxDownloads: 1, Revoked: true})
	st.Close()

	ft := newFakeTor(t, "AUTH METHODS=NULL")
	rd := startTestDaemon(t, p, ft, time.Second)
	var link string
	for i := 0; i < 100 && link == ""; i++ { // restored onions publish in the background
		link = rd.urls(t)["live-share-000000000000"]
		time.Sleep(20 * time.Millisecond)
	}
	resp, err := ctrlCall(p, ctrlRequest{Op: "list"})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Shares) != 1 || resp.Shares[0].Token != "live-share-000000000000" || link == "" {
		t.Fatalf("restored shares = %+v (link %q), want only the live one, with a link", resp.Shares, link)
	}
	if n := ft.onionCount(); n != 1 {
		t.Fatalf("%d onions published on restore, want 1 (only for the live share)", n)
	}
	if code := rd.get(t, link); code != 200 {
		t.Fatalf("restored share download: %d", code)
	}
}

func TestSecondDaemonRefuses(t *testing.T) {
	p := testPaths(t)
	ft := newFakeTor(t, "AUTH METHODS=NULL")
	startTestDaemon(t, p, ft, time.Minute)
	err := newDaemon(p, testDaemonOptions(ft, time.Minute), log.New(io.Discard, "", 0)).Run(context.Background())
	if err != errAlreadyRunning {
		t.Fatalf("second daemon: %v, want errAlreadyRunning", err)
	}
	if _, err := daemonStatus(p); err != nil {
		t.Fatalf("first daemon disturbed: %v", err)
	}
}

// Tests below are GhostShare additions.

func TestEachShareGetsItsOwnOnion(t *testing.T) {
	p := testPaths(t)
	ft := newFakeTor(t, "AUTH METHODS=NULL")
	rd := startTestDaemon(t, p, ft, time.Minute)
	_, linkA := rd.add(t, testFile(t, "a"), 1, 0)
	b, linkB := rd.add(t, testFile(t, "b"), 1, 0)
	onionA, _ := linkParts(t, linkA)
	onionB, _ := linkParts(t, linkB)
	if onionA == onionB {
		t.Fatal("two shares got the same onion address")
	}
	if n := ft.onionCount(); n != 2 {
		t.Fatalf("%d onion services for two shares, want 2", n)
	}
	// A token only works on its own onion.
	if code := rd.get(t, "http://"+onionA+"/"+b.Token+"/file.txt"); code != 410 {
		t.Fatalf("share B's token on share A's onion: %d, want 410", code)
	}
	if resp, _ := ctrlCall(p, ctrlRequest{Op: "list"}); len(resp.Shares) != 2 {
		t.Fatalf("the wrong-onion request changed the shares: %+v", resp.Shares)
	}
	for _, l := range []string{linkA, linkB} {
		if code := rd.get(t, l); code != 200 {
			t.Fatalf("download %s: %d", l, code)
		}
	}
}

func TestOnionIsRemovedWhenShareEnds(t *testing.T) {
	p := testPaths(t)
	ft := newFakeTor(t, "AUTH METHODS=NULL")
	rd := startTestDaemon(t, p, ft, time.Minute)
	_, used := rd.add(t, testFile(t, "a"), 1, 0)
	_, other := rd.add(t, testFile(t, "b"), 1, 0)
	if code := rd.get(t, used); code != 200 {
		t.Fatalf("download: %d", code)
	}
	rd.waitGone(t, used)
	if n := ft.onionCount(); n != 1 {
		t.Fatalf("%d onions after one share ended, want 1", n)
	}
	if code := rd.get(t, other); code != 200 {
		t.Fatalf("the other share was affected: %d", code)
	}
}

func TestOnionIsRemovedOnExpiry(t *testing.T) {
	p := testPaths(t)
	ft := newFakeTor(t, "AUTH METHODS=NULL")
	rd := startTestDaemon(t, p, ft, time.Minute)
	_, link := rd.add(t, testFile(t, "a"), 1, time.Now().Add(time.Second).Unix())
	time.Sleep(1200 * time.Millisecond)
	rd.waitGone(t, link)
	if n := ft.onionCount(); n != 0 {
		t.Fatalf("%d onions after the only share expired, want 0", n)
	}
}

func TestStopRemovesOnionsAndLeavesTorRunning(t *testing.T) {
	p := testPaths(t)
	ft := newFakeTor(t, "AUTH METHODS=NULL")
	rd := startTestDaemon(t, p, ft, time.Minute)
	_, link := rd.add(t, testFile(t, "a"), 1, 0)
	rd.add(t, testFile(t, "b"), 1, 0)
	if _, err := ctrlCall(p, ctrlRequest{Op: "stop"}); err != nil {
		t.Fatal(err)
	}
	if !rd.exitsWithin(5 * time.Second) {
		t.Fatal("daemon did not stop")
	}
	time.Sleep(100 * time.Millisecond)
	if n := ft.onionCount(); n != 0 {
		t.Fatalf("%d onion(s) left after stop", n)
	}
	if rd.get(t, link) != 0 {
		t.Fatal("link still works after stop")
	}
	for _, c := range ft.commands() {
		if strings.HasPrefix(c, "SIGNAL") {
			t.Fatalf("stopping the daemon sent %q to an attached Tor", c)
		}
	}
	// Unfinished shares are kept for the next session.
	if s, _ := offlineShares(p); len(s) != 2 {
		t.Fatalf("shares after stop = %+v, want both unfinished ones", s)
	}
}

func TestRestartGetsNewOnions(t *testing.T) {
	p := testPaths(t)
	ft := newFakeTor(t, "AUTH METHODS=NULL")
	first := startTestDaemon(t, p, ft, time.Minute)
	sh, oldLink := first.add(t, testFile(t, "a"), 1, 0)
	first.cancel()
	if !first.exitsWithin(5 * time.Second) {
		t.Fatal("first daemon did not stop")
	}

	second := startTestDaemon(t, p, ft, time.Minute)
	var newLink string
	for i := 0; i < 100 && newLink == ""; i++ {
		newLink = second.urls(t)[sh.Token]
		time.Sleep(20 * time.Millisecond)
	}
	if newLink == "" || newLink == oldLink {
		t.Fatalf("restored link %q, want a new one (old %q)", newLink, oldLink)
	}
	if second.get(t, oldLink) != 0 {
		t.Fatal("old onion address still works after restart")
	}
	if code := second.get(t, newLink); code != 200 {
		t.Fatalf("restored share on its new onion: %d", code)
	}
}

func TestDaemonExternalTorNeverSpawns(t *testing.T) {
	p := testPaths(t)
	looked := false
	opt := DaemonOptions{ExternalTor: true, Grace: time.Minute, Tick: time.Second, OnionTimeout: time.Second,
		Tor: torEnv{controlAddr: closedAddr(t), lookPath: func(string) (string, error) {
			looked = true
			return "/usr/bin/tor", nil
		}}}
	err := newDaemon(p, opt, log.New(io.Discard, "", 0)).Run(context.Background())
	if err == nil || !strings.Contains(err.Error(), "--external-tor") {
		t.Fatalf("Run = %v, want an --external-tor error", err)
	}
	if looked {
		t.Fatal("daemon looked for a tor binary with --external-tor")
	}
}

func TestDaemonLogHasNoFullTokensOrOnions(t *testing.T) {
	p := testPaths(t)
	var logBuf syncBuffer
	rd := startTestDaemonWithLog(t, p, newFakeTor(t, "AUTH METHODS=NULL"), time.Minute, &logBuf)
	sh, link := rd.add(t, testFile(t, "a"), 1, 0)
	rd.get(t, link)
	ctrlCall(p, ctrlRequest{Op: "list"})
	onion, _ := linkParts(t, link)
	out := logBuf.String()
	if strings.Contains(out, sh.Token) {
		t.Fatalf("daemon log contains a full token:\n%s", out)
	}
	if strings.Contains(out, onion) {
		t.Fatalf("daemon log ties a share to its onion address:\n%s", out)
	}
}

// syncBuffer is a bytes.Buffer safe for concurrent writes and reads.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func TestShareServerLimits(t *testing.T) {
	srv := newShareServer(http.NotFoundHandler(), log.New(io.Discard, "", 0))
	if srv.ReadTimeout != 0 || srv.WriteTimeout != 0 {
		t.Fatalf("ReadTimeout %v, WriteTimeout %v: must be 0 so long Tor downloads aren't cut off", srv.ReadTimeout, srv.WriteTimeout)
	}
	if srv.ReadHeaderTimeout < 15*time.Second || srv.IdleTimeout == 0 || srv.MaxHeaderBytes == 0 || srv.MaxHeaderBytes > 64<<10 {
		t.Fatalf("limits: header %v, idle %v, max header %d", srv.ReadHeaderTimeout, srv.IdleTimeout, srv.MaxHeaderBytes)
	}
}

// startShareServer runs newShareServer on a loopback port with a short
// header timeout.
func startShareServer(t *testing.T, headerTimeout time.Duration, h http.Handler) string {
	t.Helper()
	defer func(d time.Duration) { shareReadHeaderTimeout = d }(shareReadHeaderTimeout)
	shareReadHeaderTimeout = headerTimeout
	srv := newShareServer(h, log.New(io.Discard, "", 0))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return ln.Addr().String()
}

// closedWithin reports whether the server closes c within d.
func closedWithin(c net.Conn, d time.Duration) bool {
	c.SetReadDeadline(time.Now().Add(d))
	_, err := io.Copy(io.Discard, c)
	var ne net.Error
	return !(errors.As(err, &ne) && ne.Timeout())
}

func TestSlowHeadersAreDisconnected(t *testing.T) {
	addr := startShareServer(t, 300*time.Millisecond, http.NotFoundHandler())

	// Headers that never finish.
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	io.WriteString(c, "GET / HTTP/1.1\r\nHost: x\r\n")
	if !closedWithin(c, 3*time.Second) {
		t.Fatal("a client with unfinished headers was not disconnected")
	}

	// A slowloris trickling one header byte at a time.
	c2, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		for _, b := range []byte("GET / HTTP/1.1\r\nHost: x\r\nX-Slow: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") {
			if _, err := c2.Write([]byte{b}); err != nil {
				return
			}
			time.Sleep(50 * time.Millisecond)
		}
	}()
	start := time.Now()
	if !closedWithin(c2, 3*time.Second) {
		t.Fatal("a slowloris client was not disconnected")
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("slowloris disconnected only after %v with a 300ms header timeout", d)
	}
	c2.Close()
	<-done
}

func TestPromptHeadersAreServed(t *testing.T) {
	addr := startShareServer(t, 300*time.Millisecond, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(600 * time.Millisecond) // a slow response is fine: no WriteTimeout
		io.WriteString(w, "ok")
	}))
	resp, err := http.Get("http://" + addr + "/")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || string(body) != "ok" {
		t.Fatalf("got %d %q", resp.StatusCode, body)
	}
}

func TestOversizedHeadersAreRejected(t *testing.T) {
	addr := startShareServer(t, 5*time.Second, http.NotFoundHandler())
	req, _ := http.NewRequest("GET", "http://"+addr+"/", nil)
	req.Header.Set("X-Big", strings.Repeat("a", 64<<10))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusRequestHeaderFieldsTooLarge {
		t.Fatalf("64 KiB header: %d, want 431", resp.StatusCode)
	}
}
