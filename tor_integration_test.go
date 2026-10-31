//go:build tortest

// Real-Tor tests. Opt in with:
//
//	GHOSTSHARE_TOR_TEST=1 go test -tags=tortest -run Tor -v ./...
//
// They use a running Tor if there is one, else start tor from PATH, and
// need network access. They can take a few minutes.

package main

import (
	"context"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/proxy"
)

func requireTor(t *testing.T) {
	t.Helper()
	if os.Getenv("GHOSTSHARE_TOR_TEST") != "1" {
		t.Skip("set GHOSTSHARE_TOR_TEST=1 to run real-Tor tests")
	}
}

func onionClient(t *testing.T, socks string) *http.Client {
	t.Helper()
	d, err := proxy.SOCKS5("tcp", socks, nil, proxy.Direct)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{Timeout: 2 * time.Minute, Transport: &http.Transport{
		DialContext:       d.(proxy.ContextDialer).DialContext,
		DisableKeepAlives: true,
	}}
}

func TestTorShareEndToEnd(t *testing.T) {
	requireTor(t)

	st := testStore(t)
	tok, _ := newToken()
	st.Add(Share{Token: tok, Path: testFile(t, content), Filename: "file.txt",
		Created: time.Now().Unix(), MaxDownloads: 1})

	sess, err := connectTor(defaultTorEnv(), true, os.Stderr)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("spawned Tor: %v", sess.spawned)
	socks := sess.socks()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	onion, err := sess.Listen(ctx)
	if err != nil {
		sess.Close()
		t.Fatal(err)
	}
	if onion.Key != nil {
		t.Fatal("onion private key reached ghostshare")
	}
	if len(onion.ID) != 56 {
		t.Fatalf("onion ID %q is not a v3 address", onion.ID)
	}
	hs := &http.Server{Handler: &FileServer{store: st, log: log.New(io.Discard, "", 0), now: time.Now}}
	go hs.Serve(onion)

	host := onion.ID + ".onion"
	if err := sess.WaitReachable(ctx, host, 2*time.Minute); err != nil {
		t.Fatal(err)
	}

	client := onionClient(t, socks)
	resp, err := client.Get("http://" + host + "/" + tok + "/file.txt")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || string(body) != content {
		t.Fatalf("download: %d %q", resp.StatusCode, body)
	}
	resp, err = client.Get("http://" + host + "/" + tok + "/file.txt")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 410 {
		t.Fatalf("second download: %d, want 410", resp.StatusCode)
	}

	// Teardown: the onion goes away; a spawned Tor exits; an attached one stays.
	hs.Close()
	onion.Close()
	spawned, proc, dataDir := sess.spawned, sess.proc, sess.t.DataDir
	if err := sess.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if spawned {
		select {
		case <-proc.done:
		default:
			t.Fatal("spawned tor is still running after Close")
		}
		if _, err := os.Stat(dataDir); !os.IsNotExist(err) {
			t.Fatalf("tor data dir %s still exists", dataDir)
		}
		return
	}
	// Attached: Tor must still answer, and the onion must be gone.
	if st := probeTor(defaultTorEnv()); st.State != torRunning {
		t.Fatalf("attached Tor is not running after Close: %+v", st)
	}
	short := onionClient(t, socks)
	short.Timeout = 30 * time.Second
	if resp, err := short.Get("http://" + host + "/"); err == nil {
		resp.Body.Close()
		t.Fatalf("onion still answers after Close: %d", resp.StatusCode)
	}
}

// A spawned Tor gets __OwningControllerProcess, so it exits even if
// ghostshare is killed without cleaning up, and Close stops it.
func TestTorSpawnedIsOwned(t *testing.T) {
	requireTor(t)
	path, err := defaultTorEnv().lookPath("tor")
	if err != nil {
		t.Skip("no tor on PATH")
	}
	tt, proc, err := spawnTor(path)
	if err != nil {
		t.Fatal(err)
	}
	sess := &torSession{t: tt, spawned: true, proc: proc}
	args := strings.Join(proc.cmd.Args, " ")
	if !strings.Contains(args, "__OwningControllerProcess") {
		t.Errorf("tor args lack __OwningControllerProcess: %s", args)
	}
	if err := sess.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-proc.done:
	default:
		t.Fatalf("tor pid %d still running after Close", proc.cmd.Process.Pid)
	}
}
