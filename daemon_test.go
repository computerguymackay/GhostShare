// Ported from QuickShare (github.com/computerguymackay/QuickShare).
//
// The daemon runs against fakeTor (faketor_test.go), so these tests cover
// the real Tor code path without Tor or a network.

package main

import (
	"bytes"
	"context"
	"io"
	"log"
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
	onion  string
	exited chan struct{} // closed when Run returns, so any number of waiters see it
	err    error         // Run's result, valid once exited is closed
	cancel context.CancelFunc
}

func testDaemonOptions(ft *fakeTor, grace time.Duration) DaemonOptions {
	return DaemonOptions{Tor: ft.env(), Grace: grace, Tick: 100 * time.Millisecond, OnionTimeout: 5 * time.Second}
}

func startTestDaemon(t *testing.T, p Paths, ft *fakeTor, grace time.Duration) *runningDaemon {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	rd := &runningDaemon{p: p, ft: ft, exited: make(chan struct{}), cancel: cancel}
	go func() {
		rd.err = newDaemon(p, testDaemonOptions(ft, grace), log.New(io.Discard, "", 0)).Run(ctx)
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
			rd.onion = st.Onion
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

func (rd *runningDaemon) add(t *testing.T, path string, max int, expiresAt int64) Share {
	t.Helper()
	resp, err := ctrlCall(rd.p, ctrlRequest{Op: "add-share", Path: path, MaxDownloads: max, ExpiresAt: expiresAt})
	if err != nil {
		t.Fatal(err)
	}
	return *resp.Share
}

// get downloads a share over the onion, through the fake Tor's SOCKS proxy.
func (rd *runningDaemon) get(t *testing.T, tok string) int {
	t.Helper()
	code, _, ok := onionGet(t, rd.ft.socksAddr(), "http://"+rd.onion+"/"+tok)
	if !ok {
		t.Fatalf("onion %s not reachable", rd.onion)
	}
	return code
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
	sh := rd.add(t, testFile(t, "data"), 1, 0)
	if rd.exitsWithin(800 * time.Millisecond) {
		t.Fatal("daemon exited while a share was active")
	}
	if code := rd.get(t, sh.Token); code != 200 {
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
	a := rd.add(t, testFile(t, "a"), 1, 0)
	b := rd.add(t, testFile(t, "b"), 1, 0)

	rd.get(t, a.Token)
	if rd.exitsWithin(time.Second) {
		t.Fatal("daemon exited with one share still active")
	}
	if resp, err := ctrlCall(p, ctrlRequest{Op: "list"}); err != nil || len(resp.Shares) != 1 {
		t.Fatalf("list after first download: %+v %v", resp.Shares, err)
	}
	rd.get(t, b.Token)
	if !rd.exitsWithin(2 * time.Second) {
		t.Fatal("daemon did not exit after the last share ended")
	}
}

func TestNewShareCancelsGrace(t *testing.T) {
	p := testPaths(t)
	rd := startTestDaemon(t, p, newFakeTor(t, "AUTH METHODS=NULL"), 600*time.Millisecond)
	a := rd.add(t, testFile(t, "a"), 1, 0)
	rd.get(t, a.Token) // grace starts
	time.Sleep(300 * time.Millisecond)
	rd.add(t, testFile(t, "b"), 1, 0)
	if rd.exitsWithin(time.Second) {
		t.Fatal("daemon exited even though a new share arrived during the grace period")
	}
}

func TestRevokeEndsShare(t *testing.T) {
	p := testPaths(t)
	rd := startTestDaemon(t, p, newFakeTor(t, "AUTH METHODS=NULL"), 200*time.Millisecond)
	sh := rd.add(t, testFile(t, "a"), 1, 0)
	if _, err := ctrlCall(p, ctrlRequest{Op: "revoke", Token: sh.Token[:8]}); err != nil {
		t.Fatal(err)
	}
	if code := rd.get(t, sh.Token); code != 410 {
		t.Fatalf("revoked share: %d, want 410", code)
	}
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

	rd := startTestDaemon(t, p, newFakeTor(t, "AUTH METHODS=NULL"), time.Second)
	resp, err := ctrlCall(p, ctrlRequest{Op: "list"})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Shares) != 1 || resp.Shares[0].Token != "live-share-000000000000" {
		t.Fatalf("restored shares = %+v, want only the live one", resp.Shares)
	}
	if code := rd.get(t, "live-share-000000000000"); code != 200 {
		t.Fatalf("restored share download: %d", code)
	}
	if code := rd.get(t, "expired-share-000000000"); code != 410 {
		t.Fatalf("expired share: %d, want 410", code)
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

func TestTwoSharesUseOneOnion(t *testing.T) {
	p := testPaths(t)
	ft := newFakeTor(t, "AUTH METHODS=NULL")
	rd := startTestDaemon(t, p, ft, time.Minute)
	a := rd.add(t, testFile(t, "a"), 1, 0)
	b := rd.add(t, testFile(t, "b"), 1, 0)
	if a.Token == b.Token {
		t.Fatal("two shares got the same token")
	}
	if n := ft.onionCount(); n != 1 {
		t.Fatalf("%d onion services for one daemon session, want 1", n)
	}
	for _, tok := range []string{a.Token, b.Token} {
		if code := rd.get(t, tok); code != 200 {
			t.Fatalf("download %s…: %d", tok[:8], code)
		}
	}
}

func TestStopRemovesOnionAndLeavesTorRunning(t *testing.T) {
	p := testPaths(t)
	ft := newFakeTor(t, "AUTH METHODS=NULL")
	rd := startTestDaemon(t, p, ft, time.Minute)
	sh := rd.add(t, testFile(t, "a"), 1, 0)
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
	if _, _, ok := onionGet(t, ft.socksAddr(), "http://"+rd.onion+"/"+sh.Token); ok {
		t.Fatal("link still works after stop")
	}
	for _, c := range ft.commands() {
		if strings.HasPrefix(c, "SIGNAL") {
			t.Fatalf("stopping the daemon sent %q to an attached Tor", c)
		}
	}
	// The share is kept for the next session.
	if s, _ := offlineShares(p); len(s) != 1 || s[0].Token != sh.Token {
		t.Fatalf("shares after stop = %+v, want the unfinished one", s)
	}
}

func TestRestartGetsNewOnion(t *testing.T) {
	p := testPaths(t)
	ft := newFakeTor(t, "AUTH METHODS=NULL")
	first := startTestDaemon(t, p, ft, time.Minute)
	sh := first.add(t, testFile(t, "a"), 1, 0)
	first.cancel()
	if !first.exitsWithin(5 * time.Second) {
		t.Fatal("first daemon did not stop")
	}

	second := startTestDaemon(t, p, ft, time.Minute)
	if second.onion == first.onion {
		t.Fatal("restarted daemon reused the old onion address")
	}
	if _, _, ok := onionGet(t, ft.socksAddr(), "http://"+first.onion+"/"+sh.Token); ok {
		t.Fatal("old onion address still works after restart")
	}
	if code := second.get(t, sh.Token); code != 200 {
		t.Fatalf("restored share on the new onion: %d", code)
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

func TestDaemonLogHasNoFullTokens(t *testing.T) {
	p := testPaths(t)
	ft := newFakeTor(t, "AUTH METHODS=NULL")
	var logBuf syncBuffer
	ctx, cancel := context.WithCancel(context.Background())
	rd := &runningDaemon{p: p, ft: ft, exited: make(chan struct{}), cancel: cancel}
	go func() {
		rd.err = newDaemon(p, testDaemonOptions(ft, time.Minute), log.New(&logBuf, "", 0)).Run(ctx)
		close(rd.exited)
	}()
	defer func() { cancel(); <-rd.exited }()
	for i := 0; i < 250; i++ {
		if st, err := daemonStatus(p); err == nil && st.Ready {
			rd.onion = st.Onion
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	sh := rd.add(t, testFile(t, "a"), 1, 0)
	rd.get(t, sh.Token)
	ctrlCall(p, ctrlRequest{Op: "list"})
	if out := logBuf.String(); strings.Contains(out, sh.Token) {
		t.Fatalf("daemon log contains a full token:\n%s", out)
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
