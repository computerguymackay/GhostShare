package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// closedAddr returns an address with nothing listening on it.
func closedAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

func foundTor(string) (string, error)   { return "/usr/bin/tor", nil }
func missingTor(string) (string, error) { return "", errors.New("executable file not found in $PATH") }

func TestProbeRunning(t *testing.T) {
	ft := newFakeTor(t, "AUTH METHODS=NULL")
	st := probeTor(torEnv{controlAddr: ft.controlAddr(), lookPath: missingTor})
	if st.State != torRunning || st.Version != "0.4.8.10" {
		t.Fatalf("got %+v, want running 0.4.8.10", st)
	}
}

func TestProbeSpawnable(t *testing.T) {
	st := probeTor(torEnv{controlAddr: closedAddr(t), lookPath: foundTor})
	if st.State != torSpawnable || st.TorPath != "/usr/bin/tor" || st.AttachErr == nil {
		t.Fatalf("got %+v, want spawnable with an attach error", st)
	}
}

func TestProbeMissing(t *testing.T) {
	st := probeTor(torEnv{controlAddr: closedAddr(t), lookPath: missingTor})
	if st.State != torMissing {
		t.Fatalf("got %+v, want missing", st)
	}
}

func TestProbeAuthFailureIsReported(t *testing.T) {
	ft := newFakeTor(t, `AUTH METHODS=COOKIE,SAFECOOKIE COOKIEFILE="/nonexistent/control.authcookie"`)
	st := probeTor(torEnv{controlAddr: ft.controlAddr(), lookPath: foundTor})
	if st.State != torSpawnable || !errors.Is(st.AttachErr, errTorAuth) {
		t.Fatalf("got %+v, want spawnable with errTorAuth", st)
	}
	var out bytes.Buffer
	writeTorStatus(&out, st)
	if !strings.Contains(out.String(), "debian-tor") {
		t.Errorf("status output is missing the cookie permission hint:\n%s", out.String())
	}
}

func TestProbeNotTor(t *testing.T) {
	// Something that accepts but never speaks the control protocol.
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			defer c.Close()
		}
	}()
	defer func(d time.Duration) { controlTimeout = d }(controlTimeout)
	controlTimeout = 300 * time.Millisecond
	start := time.Now()
	st := probeTor(torEnv{controlAddr: ln.Addr().String(), lookPath: missingTor})
	if st.State != torMissing {
		t.Fatalf("got %+v, want missing", st)
	}
	if time.Since(start) > 2*controlTimeout {
		t.Fatalf("probe took %v; the control deadline is not working", time.Since(start))
	}
}

func TestTorStatusOutput(t *testing.T) {
	for _, tc := range []struct {
		st   torStatus
		want []string
	}{
		{torStatus{State: torRunning, ControlAddr: "127.0.0.1:9051", Version: "0.4.8.10"},
			[]string{"Tor: running", "127.0.0.1:9051", "0.4.8.10", "leave it running"}},
		{torStatus{State: torSpawnable, ControlAddr: "127.0.0.1:9051", TorPath: "/usr/bin/tor", AttachErr: errors.New("connection refused")},
			[]string{"Tor: spawnable", "/usr/bin/tor", "connection refused", "stop it on exit"}},
		{torStatus{State: torMissing, ControlAddr: "127.0.0.1:9051", AttachErr: errors.New("connection refused")},
			[]string{"Tor: missing", "sudo apt install tor", "sudo dnf install tor", "brew install tor", "Tor Expert Bundle", "never falls back"}},
	} {
		var out bytes.Buffer
		writeTorStatus(&out, tc.st)
		for _, w := range tc.want {
			if !strings.Contains(out.String(), w) {
				t.Errorf("%s: output is missing %q:\n%s", tc.st.State, w, out.String())
			}
		}
	}
}

func TestConnectMissingGivesInstallHelp(t *testing.T) {
	_, err := connectTor(torEnv{controlAddr: closedAddr(t), lookPath: missingTor}, true, io.Discard)
	if err == nil {
		t.Fatal("connectTor succeeded with no Tor")
	}
	for _, w := range []string{"sudo apt install tor", "brew install tor", "Tor Expert Bundle"} {
		if !strings.Contains(err.Error(), w) {
			t.Errorf("error is missing %q:\n%v", w, err)
		}
	}
}

func TestConnectWithoutSpawnNeverLooksForTor(t *testing.T) {
	looked := false
	env := torEnv{controlAddr: closedAddr(t), lookPath: func(string) (string, error) {
		looked = true
		return "/usr/bin/tor", nil
	}}
	if _, err := connectTor(env, false, io.Discard); err == nil {
		t.Fatal("connectTor succeeded with no running Tor and spawning disabled")
	}
	if looked {
		t.Fatal("connectTor looked for a tor binary with spawning disabled")
	}
}

func TestAttachedTorIsLeftRunning(t *testing.T) {
	ft := newFakeTor(t, "AUTH METHODS=NULL")
	var progress bytes.Buffer
	sess, err := connectTor(torEnv{controlAddr: ft.controlAddr(), lookPath: missingTor}, true, &progress)
	if err != nil {
		t.Fatal(err)
	}
	if sess.spawned {
		t.Fatal("attached session reports spawned")
	}
	if !strings.Contains(progress.String(), "using the running Tor") {
		t.Errorf("progress = %q", progress.String())
	}
	sess.Close()
	sess.Close() // must be safe to call twice
	time.Sleep(100 * time.Millisecond)
	for _, c := range ft.commands() {
		if strings.HasPrefix(c, "SIGNAL") {
			t.Fatalf("closing an attached session sent %q to Tor", c)
		}
	}
}

func TestFirstTCPListener(t *testing.T) {
	for in, want := range map[string]string{
		`"127.0.0.1:9050" "[::1]:9050"`:          "127.0.0.1:9050",
		`127.0.0.1:41234`:                        "127.0.0.1:41234",
		`"unix:/run/tor/socks" "127.0.0.1:9050"`: "127.0.0.1:9050",
		``:                                       "",
	} {
		if got := firstTCPListener(in); got != want {
			t.Errorf("firstTCPListener(%q) = %q, want %q", in, got, want)
		}
	}
}

// fakeSocks is a SOCKS5 proxy that sends every connection to target and
// records the host:port the client asked for.
func fakeSocks(t *testing.T, target string) (addr string, requested chan string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	requested = make(chan string, 10)
	go acceptLoop(ln, func(c net.Conn) {
		serveSocks(c, func(host string, port int) (string, bool) {
			requested <- net.JoinHostPort(host, strconv.Itoa(port))
			return target, true
		})
	})
	return ln.Addr().String(), requested
}

func TestWaitReachableGoesThroughSocks(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusGone)
	}))
	defer srv.Close()
	socks, requested := fakeSocks(t, strings.TrimPrefix(srv.URL, "http://"))

	host := "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion"
	if err := waitReachable(context.Background(), socks, host, 5*time.Second); err != nil {
		t.Fatal(err)
	}
	if got := <-requested; got != host+":80" {
		t.Fatalf("SOCKS request for %q, want %q", got, host+":80")
	}
}

func TestWaitReachableTimesOut(t *testing.T) {
	start := time.Now()
	err := waitReachable(context.Background(), closedAddr(t), "example.onion", 500*time.Millisecond)
	if err == nil {
		t.Fatal("waitReachable succeeded with no SOCKS proxy")
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Fatalf("waitReachable took %v with a 500ms timeout", d)
	}
}

func TestTailBufferKeepsTheEnd(t *testing.T) {
	tb := &tailBuffer{max: 5}
	io.WriteString(tb, "hello ")
	io.WriteString(tb, "world")
	if tb.String() != "world" {
		t.Fatalf("tail = %q", tb.String())
	}
}

func TestListenIsV3AndDiscardsKey(t *testing.T) {
	ft := newFakeTor(t, "AUTH METHODS=NULL")
	sess, err := connectTor(ft.env(), false, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	svc, err := sess.Listen(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer svc.Close()
	if svc.Key != nil {
		t.Fatal("onion private key reached ghostshare")
	}
	var add string
	for _, c := range ft.commands() {
		if strings.HasPrefix(c, "ADD_ONION") {
			add = c
		}
	}
	for _, want := range []string{"NEW:ED25519-V3", "Flags=DiscardPK", "Port=80,127.0.0.1:"} {
		if !strings.Contains(add, want) {
			t.Errorf("ADD_ONION %q is missing %q", add, want)
		}
	}
	if strings.Contains(add, "Detach") {
		t.Errorf("ADD_ONION %q must not detach: the onion has to die with the session", add)
	}
}

func TestListenRefusesReturnedKey(t *testing.T) {
	ft := newFakeTor(t, "AUTH METHODS=NULL")
	ft.returnKey = true
	sess, err := connectTor(ft.env(), false, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()
	if _, err := sess.Listen(context.Background()); err == nil {
		t.Fatal("Listen accepted a private key from Tor")
	}
	if n := ft.onionCount(); n != 0 {
		t.Fatalf("%d onion(s) left after refusing the key", n)
	}
}

func TestOnionServesAndDiesOnClose(t *testing.T) {
	ft := newFakeTor(t, "AUTH METHODS=NULL")
	sess, err := connectTor(ft.env(), false, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	svc, err := sess.Listen(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "hi")
	})}
	go srv.Serve(svc)
	defer srv.Close()

	host := svc.ID + ".onion"
	if err := sess.WaitReachable(context.Background(), host, 5*time.Second); err != nil {
		t.Fatal(err)
	}
	if code, body, ok := onionGet(t, ft.socksAddr(), "http://"+host+"/"); !ok || code != 200 || body != "hi" {
		t.Fatalf("over the onion: %d %q reachable=%v", code, body, ok)
	}
	sess.Close()
	time.Sleep(100 * time.Millisecond)
	if _, _, ok := onionGet(t, ft.socksAddr(), "http://"+host+"/"); ok {
		t.Fatal("onion still reachable after the session closed")
	}
}
