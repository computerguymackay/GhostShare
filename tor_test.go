package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeTor is a minimal Tor control port: enough for PROTOCOLINFO,
// AUTHENTICATE, GETINFO and QUIT.
type fakeTor struct {
	ln      net.Listener
	authHdr string // the AUTH line of PROTOCOLINFO

	mu   sync.Mutex
	cmds []string
}

func newFakeTor(t *testing.T, authHdr string) *fakeTor {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ft := &fakeTor{ln: ln, authHdr: authHdr}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go ft.serve(c)
		}
	}()
	return ft
}

func (ft *fakeTor) serve(c net.Conn) {
	defer c.Close()
	r := bufio.NewReader(c)
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimSpace(line)
		ft.mu.Lock()
		ft.cmds = append(ft.cmds, line)
		ft.mu.Unlock()
		switch {
		case line == "PROTOCOLINFO":
			io.WriteString(c, "250-PROTOCOLINFO 1\r\n250-"+ft.authHdr+"\r\n250-VERSION Tor=\"0.4.8.10\"\r\n250 OK\r\n")
		case strings.HasPrefix(line, "AUTHENTICATE"):
			io.WriteString(c, "250 OK\r\n")
		case line == "GETINFO version":
			io.WriteString(c, "250-version=0.4.8.10 (git-0123456789abcdef)\r\n250 OK\r\n")
		case line == "QUIT":
			io.WriteString(c, "250 closing connection\r\n")
			return
		default:
			io.WriteString(c, "510 Unrecognized command\r\n")
		}
	}
}

func (ft *fakeTor) commands() []string {
	ft.mu.Lock()
	defer ft.mu.Unlock()
	return append([]string(nil), ft.cmds...)
}

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
	st := probeTor(torEnv{controlAddr: ft.ln.Addr().String(), lookPath: missingTor})
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
	st := probeTor(torEnv{controlAddr: ft.ln.Addr().String(), lookPath: foundTor})
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
	sess, err := connectTor(torEnv{controlAddr: ft.ln.Addr().String(), lookPath: missingTor}, true, &progress)
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
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				hdr := make([]byte, 2)
				io.ReadFull(c, hdr) // version, method count
				io.ReadFull(c, make([]byte, hdr[1]))
				c.Write([]byte{5, 0}) // no auth
				req := make([]byte, 4)
				io.ReadFull(c, req) // version, cmd, rsv, atyp
				if req[3] != 3 {    // domain name: the client must not resolve .onion itself
					return
				}
				n := make([]byte, 1)
				io.ReadFull(c, n)
				name := make([]byte, n[0])
				io.ReadFull(c, name)
				port := make([]byte, 2)
				io.ReadFull(c, port)
				requested <- net.JoinHostPort(string(name), strconv.Itoa(int(binary.BigEndian.Uint16(port))))
				up, err := net.Dial("tcp", target)
				if err != nil {
					c.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
					return
				}
				defer up.Close()
				c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
				go io.Copy(up, c)
				io.Copy(c, up)
			}(c)
		}
	}()
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
