//go:build !windows

// Ported from QuickShare (github.com/computerguymackay/QuickShare).
//
// End-to-end tests that build the real binary (with CGO_ENABLED=0) and run
// it, so daemon spawning, locking and crash recovery are exercised for real.
// Tor is fakeTor (faketor_test.go); PATH is empty so a real tor is never used.

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"image/jpeg"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

var gsBinary string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "gsbin")
	if err != nil {
		panic(err)
	}
	gsBinary = filepath.Join(dir, "ghostshare")
	build := exec.Command("go", "build", "-o", gsBinary, ".")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "build failed: %v\n%s", err, out)
		os.Exit(1)
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

type cliEnv struct {
	home        string
	ft          *fakeTor
	controlAddr string // Tor control port the binary tries
	path        string // PATH for the binary: no tor unless a test adds one
}

func newCLIEnv(t *testing.T) *cliEnv {
	t.Helper()
	home, err := os.MkdirTemp("", "gs")
	if err != nil {
		t.Fatal(err)
	}
	ft := newFakeTor(t, "AUTH METHODS=NULL")
	e := &cliEnv{home: home, ft: ft, controlAddr: ft.controlAddr(), path: t.TempDir()}
	t.Cleanup(func() {
		e.run(t, "stop")
		os.RemoveAll(home)
	})
	return e
}

func (e *cliEnv) run(t *testing.T, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	cmd := exec.Command(gsBinary, args...)
	cmd.Env = append(os.Environ(),
		"GHOSTSHARE_HOME="+e.home, "GHOSTSHARE_GRACE=1s", "GHOSTSHARE_TICK=200ms",
		"GHOSTSHARE_TOR_CONTROL="+e.controlAddr, "GHOSTSHARE_TOR_SOCKS=", "PATH="+e.path)
	var o, er bytes.Buffer
	cmd.Stdout, cmd.Stderr = &o, &er
	err := cmd.Run()
	code = 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	return o.String(), er.String(), code
}

func (e *cliEnv) share(t *testing.T, file string, extra ...string) string {
	t.Helper()
	out, errOut, code := e.run(t, append([]string{file}, extra...)...)
	if code != 0 {
		t.Fatalf("share failed (%d): %s", code, errOut)
	}
	return strings.TrimSpace(out)
}

func (e *cliEnv) list(t *testing.T) []listItem {
	t.Helper()
	out, errOut, code := e.run(t, "list", "--json")
	if code != 0 {
		t.Fatalf("list failed: %s", errOut)
	}
	var items []listItem
	if err := json.Unmarshal([]byte(out), &items); err != nil {
		t.Fatalf("list output %q: %v", out, err)
	}
	return items
}

func (e *cliEnv) daemonPID(t *testing.T) int {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(e.home, "daemon.pid"))
	if err != nil {
		t.Fatal(err)
	}
	pid, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	return pid
}

func (e *cliEnv) waitDaemonGone(t *testing.T, within time.Duration) {
	t.Helper()
	p := Paths{DaemonLock: filepath.Join(e.home, "daemon.lock")}
	deadline := time.Now().Add(within)
	for daemonAlive(p) {
		if time.Now().After(deadline) {
			t.Fatal("daemon still running")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func (e *cliEnv) download(t *testing.T, link string) (int, string) {
	t.Helper()
	code, body, ok := onionGet(t, e.ft.socksAddr(), link)
	if !ok {
		t.Fatalf("%s is not reachable", link)
	}
	return code, body
}

func (e *cliEnv) reachable(t *testing.T, link string) bool {
	t.Helper()
	_, _, ok := onionGet(t, e.ft.socksAddr(), link)
	return ok
}

// waitGone waits until a link's onion has been removed from Tor.
func (e *cliEnv) waitGone(t *testing.T, link string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for e.reachable(t, link) {
		if time.Now().After(deadline) {
			t.Fatalf("%s still reachable", link)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestCLIShareDownloadAndAutoStop(t *testing.T) {
	e := newCLIEnv(t)
	out, errOut, code := e.run(t, testFile(t, "hello"))
	if code != 0 {
		t.Fatalf("share failed (%d): %s", code, errOut)
	}
	if strings.Count(out, "\n") != 1 {
		t.Fatalf("stdout should be just the link, got %q", out)
	}
	link := strings.TrimSpace(out)
	linkParts(t, link)
	for _, want := range []string{securityWarning, "Tor Browser"} {
		if !strings.Contains(errOut, want) {
			t.Errorf("stderr is missing %q:\n%s", want, errOut)
		}
	}
	if code, body := e.download(t, link); code != 200 || body != "hello" {
		t.Fatalf("download: %d %q", code, body)
	}
	e.waitGone(t, link) // the share's onion goes away once it's used up
	e.waitDaemonGone(t, 4*time.Second)
	if e.reachable(t, link) {
		t.Fatal("link still reachable after the daemon exited")
	}
	if n := e.ft.onionCount(); n != 0 {
		t.Fatalf("%d onion(s) left after the daemon exited", n)
	}
}

func TestCLIJSON(t *testing.T) {
	e := newCLIEnv(t)
	out, errOut, code := e.run(t, testFile(t, "x"), "--json", "--max-downloads", "3", "--expires", "1h")
	if code != 0 {
		t.Fatal(errOut)
	}
	// Pipe-clean: stdout is exactly one JSON object, so
	// link=$(ghostshare f --json | jq -r .url) works.
	var v struct {
		URL          string  `json:"url"`
		Token        string  `json:"token"`
		ExpiresAt    *string `json:"expires_at"`
		MaxDownloads int     `json:"max_downloads"`
	}
	dec := json.NewDecoder(strings.NewReader(out))
	if err := dec.Decode(&v); err != nil {
		t.Fatalf("%q: %v", out, err)
	}
	if dec.More() {
		t.Fatalf("stdout has more than one JSON value: %q", out)
	}
	if v.MaxDownloads != 3 || v.ExpiresAt == nil || !strings.Contains(v.URL, v.Token) {
		t.Fatalf("unexpected JSON: %+v", v)
	}
	linkParts(t, v.URL)
	exp, err := time.Parse(time.RFC3339, *v.ExpiresAt)
	if err != nil || exp.Sub(time.Now()) < 59*time.Minute {
		t.Fatalf("expires_at %q", *v.ExpiresAt)
	}
	if !strings.Contains(errOut, securityWarning) {
		t.Errorf("--json share is missing the security warning on stderr:\n%s", errOut)
	}
}

func TestCLIForeverRefused(t *testing.T) {
	e := newCLIEnv(t)
	_, errOut, code := e.run(t, testFile(t, "x"), "--max-downloads", "0", "--expires", "0")
	if code == 0 || !strings.Contains(errOut, "share forever") {
		t.Fatalf("forever share accepted: code %d, %s", code, errOut)
	}
	if _, err := os.Stat(filepath.Join(e.home, "daemon.pid")); err == nil {
		t.Fatal("daemon started for a refused share")
	}
	if _, errOut, code := e.run(t, testFile(t, "x"), "--allow-forever"); code == 0 {
		t.Fatalf("--allow-forever accepted, but it is not part of v1: %s", errOut)
	}
}

func TestCLIParallelInvocationsShareOneDaemon(t *testing.T) {
	e := newCLIEnv(t)
	f := testFile(t, "x")
	const n = 8
	links := make([]string, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			links[i] = e.share(t, f)
		}(i)
	}
	wg.Wait()
	if got := len(e.list(t)); got != n {
		t.Fatalf("daemon has %d shares, want %d (were two daemons started?)", got, n)
	}
	seen := map[string]bool{}
	for _, l := range links {
		o, _ := linkParts(t, l)
		if seen[o] {
			t.Fatalf("two shares got the same onion %s; want one per share", o)
		}
		seen[o] = true
	}
	if got := e.ft.onionCount(); got != n {
		t.Fatalf("%d onions for %d shares, want one each", got, n)
	}
	for _, l := range links {
		if code, _ := e.download(t, l); code != 200 {
			t.Fatalf("download %s: %d", l, code)
		}
	}
	log, _ := os.ReadFile(filepath.Join(e.home, "ghostshare.log"))
	if c := strings.Count(string(log), "daemon started"); c != 1 {
		t.Fatalf("daemon started %d times, want 1", c)
	}
}

func TestCLIStalePIDAndSocket(t *testing.T) {
	e := newCLIEnv(t)
	os.WriteFile(filepath.Join(e.home, "daemon.pid"), []byte("999999\n"), 0o600)
	os.WriteFile(filepath.Join(e.home, "control.sock"), []byte("stale"), 0o600)

	link := e.share(t, testFile(t, "x"))
	if code, _ := e.download(t, link); code != 200 {
		t.Fatalf("download: %d", code)
	}
	if pid := e.daemonPID(t); pid == 999999 {
		t.Fatal("stale PID file not replaced")
	}
}

func TestCLICrashRestoresSharesOnNewOnion(t *testing.T) {
	e := newCLIEnv(t)
	f := testFile(t, "data")
	first := e.share(t, f, "--max-downloads", "2")
	expired := e.share(t, f, "--expires", "1s")
	time.Sleep(1100 * time.Millisecond)

	syscall.Kill(e.daemonPID(t), syscall.SIGKILL)
	e.waitDaemonGone(t, 2*time.Second)
	time.Sleep(100 * time.Millisecond)
	if e.reachable(t, first) {
		t.Fatal("old link still reachable after the daemon was killed")
	}

	_, errOut, code := e.run(t, f) // starts a fresh daemon
	if code != 0 {
		t.Fatal(errOut)
	}
	if !strings.Contains(errOut, "back online") {
		t.Errorf("no notice about restored shares:\n%s", errOut)
	}
	items := e.list(t)
	if len(items) != 2 {
		t.Fatalf("after restart: %d shares, want 2: %+v", len(items), items)
	}
	oldOnion, firstTok := linkParts(t, first)
	var restored string
	for _, it := range items {
		if it.Token == firstTok {
			restored = it.URL
		}
	}
	if restored == "" {
		t.Fatalf("restored share missing from list: %+v", items)
	}
	if newOnion, _ := linkParts(t, restored); newOnion == oldOnion {
		t.Fatal("restored share kept the old onion address")
	}
	if code, _ := e.download(t, restored); code != 200 {
		t.Fatalf("restored share on the new onion: %d", code)
	}
	_, expTok := linkParts(t, expired)
	for _, it := range items {
		if it.Token == expTok {
			t.Fatal("the expired share was restored")
		}
	}
	if e.reachable(t, expired) {
		t.Fatal("the expired share's old link works")
	}
}

func TestCLIStopListRevoke(t *testing.T) {
	e := newCLIEnv(t)
	link := e.share(t, testFile(t, "x"))
	_, tok := linkParts(t, link)

	if items := e.list(t); len(items) != 1 || items[0].URL != link {
		t.Fatalf("running list: %+v, want the share with its link", items)
	}
	out, _, code := e.run(t, "stop")
	if code != 0 || !strings.Contains(out, "daemon stopped") {
		t.Fatalf("stop: %d %q", code, out)
	}
	e.waitDaemonGone(t, 2*time.Second)
	if e.reachable(t, link) {
		t.Fatal("link still reachable after stop")
	}

	// Offline list and revoke work against the database.
	if items := e.list(t); len(items) != 1 || items[0].Token != tok || items[0].URL != "" {
		t.Fatalf("offline list: %+v", items)
	}
	if out, errOut, code := e.run(t, "revoke", tok[:10]); code != 0 || !strings.Contains(out, tok) {
		t.Fatalf("revoke: %d %q %q", code, out, errOut)
	}
	if items := e.list(t); len(items) != 0 {
		t.Fatalf("after revoke: %+v", items)
	}
	if out, _, _ := e.run(t, "stop"); !strings.Contains(out, "not running") {
		t.Fatalf("stop when stopped: %q", out)
	}
}

func TestCLIRevokeWhileRunning(t *testing.T) {
	e := newCLIEnv(t)
	link := e.share(t, testFile(t, "x"))
	_, tok := linkParts(t, link)
	if out, errOut, code := e.run(t, "revoke", tok[:6]); code != 0 || !strings.Contains(out, tok) {
		t.Fatalf("revoke: %d %q %q", code, out, errOut)
	}
	e.waitGone(t, link)
	if _, _, code := e.run(t, "revoke", tok[:5]); code == 0 {
		t.Fatal("a 5-character prefix was accepted")
	}
}

func TestCLIShortFlags(t *testing.T) {
	e := newCLIEnv(t)
	png := filepath.Join(t.TempDir(), "qr.png")
	out, errOut, code := e.run(t, "-m", "3", "--e", "2h", "-j", "-o", png, testFile(t, "x"))
	if code != 0 {
		t.Fatal(errOut)
	}
	var v struct {
		MaxDownloads int `json:"max_downloads"`
	}
	if err := json.Unmarshal([]byte(out), &v); err != nil || v.MaxDownloads != 3 {
		t.Fatalf("short flags not applied: %q %v", out, err)
	}
	if !fileExists(png) {
		t.Fatal("-o did not write the QR PNG")
	}
	if out, _, code := e.run(t, "list", "-j"); code != 0 || !strings.HasPrefix(out, "[") {
		t.Fatalf("list -j: %d %q", code, out)
	}
	if _, errOut, code := e.run(t, testFile(t, "y"), "-m", "0", "-e", "0"); code == 0 {
		t.Fatalf("forever share accepted via short flags: %s", errOut)
	}
}

func TestCLITorMissing(t *testing.T) {
	e := newCLIEnv(t)
	e.controlAddr = closedAddr(t)
	out, errOut, code := e.run(t, testFile(t, "x"))
	if code == 0 {
		t.Fatal("share succeeded with no Tor")
	}
	if out != "" {
		t.Fatalf("stdout must stay empty on error, got %q", out)
	}
	for _, want := range []string{"sudo apt install tor", "brew install tor", "Tor Expert Bundle", "never falls back"} {
		if !strings.Contains(errOut, want) {
			t.Errorf("stderr is missing %q:\n%s", want, errOut)
		}
	}
	if daemonAlive(Paths{DaemonLock: filepath.Join(e.home, "daemon.lock")}) {
		t.Fatal("a daemon was started without Tor")
	}
}

func TestCLIExternalTorNeverSpawns(t *testing.T) {
	e := newCLIEnv(t)
	e.controlAddr = closedAddr(t)
	marker := filepath.Join(t.TempDir(), "tor-was-run")
	script := "#!/bin/sh\ntouch " + marker + "\nexit 1\n"
	if err := os.WriteFile(filepath.Join(e.path, "tor"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	out, errOut, code := e.run(t, testFile(t, "x"), "--external-tor")
	if code == 0 || out != "" || !strings.Contains(errOut, "--external-tor") {
		t.Fatalf("--external-tor with no running Tor: code %d, stdout %q, stderr %s", code, out, errOut)
	}
	if fileExists(marker) {
		t.Fatal("--external-tor started a tor binary")
	}
}

func TestCLITorStatus(t *testing.T) {
	e := newCLIEnv(t)
	out, _, code := e.run(t, "tor-status")
	if code != 0 || !strings.Contains(out, "Tor: running") {
		t.Fatalf("running: %d %q", code, out)
	}
	if err := os.WriteFile(filepath.Join(e.path, "tor"), []byte("#!/bin/sh\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	e.controlAddr = closedAddr(t)
	if out, _, code := e.run(t, "tor-status"); code != 0 || !strings.Contains(out, "Tor: spawnable") {
		t.Fatalf("spawnable: %d %q", code, out)
	}
	os.Remove(filepath.Join(e.path, "tor"))
	if out, _, code := e.run(t, "tor-status"); code != 1 || !strings.Contains(out, "Tor: missing") {
		t.Fatalf("missing: %d %q", code, out)
	}
}

func TestCLIHelpAndVersion(t *testing.T) {
	e := newCLIEnv(t)
	for _, args := range [][]string{{"--help"}, {"--version"}} {
		out, _, code := e.run(t, args...)
		if code != 0 || !strings.Contains(out, attribution) {
			t.Errorf("%v: %d %q", args, code, out)
		}
	}
}

// Phase 4 check (CLAUDE.md, Build Order): `ghostshare report.pdf -m 3 -e 2h -q`
// works end to end, with only the link on stdout.
func TestCLIPhase4ReportPDF(t *testing.T) {
	e := newCLIEnv(t)
	pdf := filepath.Join(t.TempDir(), "report.pdf")
	os.WriteFile(pdf, []byte("%PDF-1.4 test"), 0o644)
	out, errOut, code := e.run(t, pdf, "-m", "3", "-e", "2h", "-q")
	if code != 0 {
		t.Fatal(errOut)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 1 || !strings.HasSuffix(lines[0], "/report.pdf") {
		t.Fatalf("stdout = %q, want only the link", out)
	}
	link := lines[0]
	linkParts(t, link)
	for _, want := range []string{"█", securityWarning, "3 downloads", "Tor Browser", "Onion Browser"} {
		if !strings.Contains(errOut, want) {
			t.Errorf("stderr is missing %q:\n%s", want, errOut)
		}
	}
	items := e.list(t)
	if len(items) != 1 || items[0].MaxDownloads != 3 || time.Until(time.Unix(items[0].ExpiresAt, 0)) < 119*time.Minute {
		t.Fatalf("share limits not applied: %+v", items)
	}
	for i := 1; i <= 3; i++ {
		if code, body := e.download(t, link); code != 200 || body != "%PDF-1.4 test" {
			t.Fatalf("download %d: %d %q", i, code, body)
		}
	}
	e.waitGone(t, link) // used up: the onion is removed
}

func TestCLIQRKeepsLinkOnStdout(t *testing.T) {
	e := newCLIEnv(t)
	png := filepath.Join(t.TempDir(), "qr.png")
	out, errOut, code := e.run(t, testFile(t, "x"), "--qr", "--qr-out", png)
	if code != 0 {
		t.Fatal(errOut)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 1 || !strings.HasPrefix(lines[0], "http://") {
		t.Fatalf("stdout = %q, want only the link", out)
	}
	if !strings.Contains(errOut, "█") {
		t.Fatal("QR code not rendered on stderr")
	}
	checkQRPNG(t, png, lines[0])
}

func TestCLIJSONWithQRIsPipeClean(t *testing.T) {
	e := newCLIEnv(t)
	out, errOut, code := e.run(t, testFile(t, "x"), "-j", "-q")
	if code != 0 {
		t.Fatal(errOut)
	}
	var v struct {
		URL string `json:"url"`
	}
	dec := json.NewDecoder(strings.NewReader(out))
	if err := dec.Decode(&v); err != nil || dec.More() {
		t.Fatalf("stdout is not exactly one JSON object: %q (%v)", out, err)
	}
	linkParts(t, v.URL)
	if strings.Contains(out, "█") || !strings.Contains(errOut, "█") {
		t.Fatal("the QR code must go to stderr only")
	}
}

func TestCLIConfigDefaults(t *testing.T) {
	e := newCLIEnv(t)
	cfg := "[server]\nwan = \"203.0.113.5:9000\"\n\n[share]\ndefault_max_downloads = 4\ndefault_expiry = \"3h\"\n"
	os.MkdirAll(e.home, 0o700)
	os.WriteFile(filepath.Join(e.home, "config.toml"), []byte(cfg), 0o600)

	out, errOut, code := e.run(t, testFile(t, "x"), "-j")
	if code != 0 {
		t.Fatal(errOut)
	}
	var v struct {
		ExpiresAt    *string `json:"expires_at"`
		MaxDownloads int     `json:"max_downloads"`
	}
	json.Unmarshal([]byte(out), &v)
	if v.MaxDownloads != 4 || v.ExpiresAt == nil {
		t.Fatalf("config defaults not applied: %q", out)
	}
	if exp, _ := time.Parse(time.RFC3339, *v.ExpiresAt); time.Until(exp) < 179*time.Minute {
		t.Fatalf("expires_at %q, want ~3h", *v.ExpiresAt)
	}
	if !strings.Contains(errOut, "server.wan") {
		t.Errorf("no warning about the QuickShare-only key:\n%s", errOut)
	}
	// Flags still win over the config.
	out, _, _ = e.run(t, testFile(t, "y"), "-j", "-m", "1")
	json.Unmarshal([]byte(out), &v)
	if v.MaxDownloads != 1 {
		t.Fatalf("-m did not override the config: %q", out)
	}
}

func TestCLIConfigTemplateWritten(t *testing.T) {
	e := newCLIEnv(t)
	e.share(t, testFile(t, "x"))
	b, err := os.ReadFile(filepath.Join(e.home, "config.toml"))
	if err != nil || !strings.Contains(string(b), "default_max_downloads = 1") {
		t.Fatalf("config template: %v %q", err, b)
	}
}

func TestCLIInteractive(t *testing.T) {
	e := newCLIEnv(t)
	cmd := exec.Command(gsBinary, testFile(t, "x"), "-i", "-j")
	cmd.Env = append(os.Environ(),
		"GHOSTSHARE_HOME="+e.home, "GHOSTSHARE_GRACE=1s", "GHOSTSHARE_TICK=200ms",
		"GHOSTSHARE_TOR_CONTROL="+e.controlAddr, "PATH="+e.path)
	cmd.Stdin = strings.NewReader("5\n90m\nn\ny\n") // max, expiry, strip metadata, QR
	var o, er bytes.Buffer
	cmd.Stdout, cmd.Stderr = &o, &er
	if err := cmd.Run(); err != nil {
		t.Fatalf("%v: %s", err, er.String())
	}
	var v struct {
		MaxDownloads     int  `json:"max_downloads"`
		MetadataStripped bool `json:"metadata_stripped"`
	}
	if err := json.Unmarshal(o.Bytes(), &v); err != nil || v.MaxDownloads != 5 || v.MetadataStripped {
		t.Fatalf("interactive answers not applied: %q %v", o.String(), err)
	}
	for _, want := range []string{"Strip metadata (EXIF, GPS, author, etc.) before sharing? [Y/n]", "metadata is not being removed"} {
		if !strings.Contains(er.String(), want) {
			t.Errorf("stderr is missing %q:\n%s", want, er.String())
		}
	}
	if !strings.Contains(er.String(), "Max downloads") || !strings.Contains(er.String(), "█") {
		t.Fatalf("prompts or QR missing from stderr:\n%s", er.String())
	}
}

// ---- Metadata stripping, end to end ----

type shareJSON struct {
	URL              string `json:"url"`
	Token            string `json:"token"`
	MetadataStripped bool   `json:"metadata_stripped"`
}

func (e *cliEnv) shareJSON(t *testing.T, file string, extra ...string) (shareJSON, string) {
	t.Helper()
	out, errOut, code := e.run(t, append([]string{file, "-j"}, extra...)...)
	if code != 0 {
		t.Fatalf("share failed (%d): %s", code, errOut)
	}
	var v shareJSON
	dec := json.NewDecoder(strings.NewReader(out))
	if err := dec.Decode(&v); err != nil || dec.More() {
		t.Fatalf("stdout is not exactly one JSON object: %q (%v)", out, err)
	}
	return v, errOut
}

func (e *cliEnv) fetch(t *testing.T, link string) (*http.Response, []byte) {
	t.Helper()
	resp, body, ok := onionFetch(t, e.ft.socksAddr(), link)
	if !ok {
		t.Fatalf("%s is not reachable", link)
	}
	return resp, body
}

func writeFixture(t *testing.T, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func (e *cliEnv) copyFor(token string) string { return filepath.Join(e.home, "files", token) }

func (e *cliEnv) waitNoCopy(t *testing.T, token string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for fileExists(e.copyFor(token)) {
		if time.Now().After(deadline) {
			t.Fatalf("stripped copy for %s… still exists", token[:8])
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func TestCLIStripsMetadataByDefault(t *testing.T) {
	e := newCLIEnv(t)
	data := jpegFixture(t, 6)
	photo := writeFixture(t, "holiday photo.jpg", data)
	v, errOut := e.shareJSON(t, photo)
	if !v.MetadataStripped {
		t.Fatal("metadata_stripped = false for a JPEG")
	}
	if strings.Contains(errOut, "warning: can't") || strings.Contains(errOut, "warning: couldn't") || strings.Contains(errOut, "not being removed") {
		t.Errorf("unexpected metadata warning:\n%s", errOut)
	}
	if !fileExists(e.copyFor(v.Token)) {
		t.Fatal("no stripped copy in the state directory")
	}
	if got, _ := os.ReadFile(photo); !bytes.Equal(got, data) {
		t.Fatal("the original file was modified")
	}

	resp, body := e.fetch(t, v.URL)
	if resp.StatusCode != 200 {
		t.Fatalf("download: %d", resp.StatusCode)
	}
	assertNoSecrets(t, body, jpegSecrets)
	if _, err := jpeg.Decode(bytes.NewReader(body)); err != nil {
		t.Fatalf("downloaded JPEG doesn't decode: %v", err)
	}
	if cd := resp.Header.Get("Content-Disposition"); !strings.Contains(cd, `filename="holiday photo.jpg"`) {
		t.Fatalf("Content-Disposition = %q, want the original filename", cd)
	}
	// Used up: the copy is deleted.
	e.waitNoCopy(t, v.Token)
}

func TestCLIKeepMetadataServesOriginal(t *testing.T) {
	e := newCLIEnv(t)
	data := jpegFixture(t, 6)
	photo := writeFixture(t, "photo.jpg", data)
	for _, flag := range []string{"--keep-metadata", "-k"} {
		v, errOut := e.shareJSON(t, photo, flag)
		if v.MetadataStripped {
			t.Fatalf("%s: metadata_stripped = true", flag)
		}
		if !strings.Contains(errOut, "warning: metadata is not being removed") || !strings.Contains(errOut, securityWarning) {
			t.Errorf("%s: stderr is missing the metadata or encryption warning:\n%s", flag, errOut)
		}
		if fileExists(e.copyFor(v.Token)) {
			t.Fatalf("%s: a stripped copy was made", flag)
		}
		if _, body := e.fetch(t, v.URL); !bytes.Equal(body, data) {
			t.Fatalf("%s: download differs from the original", flag)
		}
	}
}

func TestCLIUnsupportedTypeSharesWithWarning(t *testing.T) {
	e := newCLIEnv(t)
	data := []byte("\x00\x00\x00\x18ftypmp42\x00\x00\x00\x00mp42isom-video-bytes")
	v, errOut := e.shareJSON(t, writeFixture(t, "clip.mp4", data))
	if v.MetadataStripped {
		t.Fatal("metadata_stripped = true for an unsupported type")
	}
	if !strings.Contains(errOut, "warning: can't remove metadata from .mp4 files; sharing as-is\n") {
		t.Fatalf("stderr is missing the one-line warning:\n%s", errOut)
	}
	if _, body := e.fetch(t, v.URL); !bytes.Equal(body, data) {
		t.Fatal("download differs from the original")
	}
}

func TestCLIEncryptedFileWarnsToStripFirst(t *testing.T) {
	e := newCLIEnv(t)
	_, errOut := e.shareJSON(t, writeFixture(t, "secret.age", []byte("age-encryption.org/v1\n-> X25519 abc\n")))
	if !strings.Contains(errOut, "strip metadata before encrypting") {
		t.Fatalf("stderr:\n%s", errOut)
	}
}

func TestCLIStripFailureSharesWithWarning(t *testing.T) {
	e := newCLIEnv(t)
	data := []byte{0xFF, 0xD8, 0xFF, 0xE1, 0x7F, 0xFF, 'E', 'x'}
	v, errOut := e.shareJSON(t, writeFixture(t, "broken.jpg", data))
	if v.MetadataStripped || !strings.Contains(errOut, "warning: couldn't remove metadata from broken.jpg") {
		t.Fatalf("metadata_stripped %v, stderr:\n%s", v.MetadataStripped, errOut)
	}
	if _, body := e.fetch(t, v.URL); !bytes.Equal(body, data) {
		t.Fatal("download differs from the original")
	}
	if entries, _ := os.ReadDir(filepath.Join(e.home, "files")); len(entries) != 0 {
		t.Fatalf("leftover files after a failed strip: %v", entries)
	}
}

func TestCLIConfigStripMetadata(t *testing.T) {
	e := newCLIEnv(t)
	os.MkdirAll(e.home, 0o700)
	os.WriteFile(filepath.Join(e.home, "config.toml"), []byte("[share]\nstrip_metadata = false\n"), 0o600)
	photo := writeFixture(t, "photo.jpg", jpegFixture(t, 1))
	v, errOut := e.shareJSON(t, photo)
	if v.MetadataStripped || !strings.Contains(errOut, "not being removed") {
		t.Fatalf("strip_metadata = false not applied: %+v\n%s", v, errOut)
	}
	if v, _ := e.shareJSON(t, photo, "--keep-metadata=false"); !v.MetadataStripped {
		t.Fatal("--keep-metadata=false did not override strip_metadata = false")
	}
}

func TestCLIListShowsMetadataStatus(t *testing.T) {
	e := newCLIEnv(t)
	stripped, _ := e.shareJSON(t, writeFixture(t, "a.jpg", jpegFixture(t, 1)))
	kept, _ := e.shareJSON(t, writeFixture(t, "b.jpg", jpegFixture(t, 1)), "-k")
	got := map[string]bool{}
	for _, it := range e.list(t) {
		got[it.Token] = it.MetadataStripped
	}
	if !got[stripped.Token] || got[kept.Token] {
		t.Fatalf("list JSON metadata_stripped = %v", got)
	}
	out, _, _ := e.run(t, "list")
	if !strings.Contains(out, "METADATA") || !strings.Contains(out, "removed") || !strings.Contains(out, "kept") {
		t.Fatalf("list table:\n%s", out)
	}
}

func TestCLIStrippedCopySurvivesRestartAndIsDeletedOnRevoke(t *testing.T) {
	e := newCLIEnv(t)
	v, _ := e.shareJSON(t, writeFixture(t, "photo.jpg", jpegFixture(t, 1)), "-m", "5")
	if _, _, code := e.run(t, "stop"); code != 0 {
		t.Fatal("stop failed")
	}
	e.waitDaemonGone(t, 3*time.Second)
	if !fileExists(e.copyFor(v.Token)) {
		t.Fatal("stop deleted the stripped copy of an unfinished share")
	}

	e.share(t, testFile(t, "other")) // restarts the daemon
	var link string
	for i := 0; i < 100 && link == ""; i++ {
		for _, it := range e.list(t) {
			if it.Token == v.Token {
				link = it.URL
			}
		}
		time.Sleep(30 * time.Millisecond)
	}
	if link == "" {
		t.Fatal("restored share has no link")
	}
	if _, body := e.fetch(t, link); bytes.Contains(body, []byte("GPSSECRET")) || bytes.Contains(body, []byte("XMPSECRET")) {
		t.Fatal("restored share serves metadata")
	}
	if _, _, code := e.run(t, "revoke", v.Token[:8]); code != 0 {
		t.Fatal("revoke failed")
	}
	e.waitNoCopy(t, v.Token)
}

func TestCLIDeletingOriginalEndsStrippedShare(t *testing.T) {
	e := newCLIEnv(t)
	photo := writeFixture(t, "photo.jpg", jpegFixture(t, 1))
	v, _ := e.shareJSON(t, photo, "-m", "5")
	os.Remove(photo)
	e.waitGone(t, v.URL)
	e.waitNoCopy(t, v.Token)
}
