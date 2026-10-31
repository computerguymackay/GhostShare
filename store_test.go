// Ported from QuickShare (github.com/computerguymackay/QuickShare).

package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	st, err := openStore(filepath.Join(t.TempDir(), "state.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func testFile(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "file.txt")
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestIncrementClampsAtMax(t *testing.T) {
	st := testStore(t)
	st.Add(Share{Token: "tok", Path: "/x", MaxDownloads: 2})
	for i := 0; i < 5; i++ {
		st.Increment("tok")
	}
	sh, _ := st.Get("tok")
	if sh.Count != 2 {
		t.Fatalf("count = %d, want 2", sh.Count)
	}
}

func TestIncrementUnlimited(t *testing.T) {
	st := testStore(t)
	st.Add(Share{Token: "tok", Path: "/x", MaxDownloads: 0, ExpiresAt: time.Now().Add(time.Hour).Unix()})
	for i := 0; i < 5; i++ {
		st.Increment("tok")
	}
	if sh, _ := st.Get("tok"); sh.Count != 5 {
		t.Fatalf("count = %d, want 5", sh.Count)
	}
}

func TestPruneDropsDeadShares(t *testing.T) {
	st := testStore(t)
	f := testFile(t, "x")
	now := time.Now()
	st.Add(Share{Token: "live", Path: f, MaxDownloads: 1, ExpiresAt: now.Add(time.Hour).Unix()})
	st.Add(Share{Token: "expired", Path: f, MaxDownloads: 1, ExpiresAt: now.Add(-time.Second).Unix()})
	st.Add(Share{Token: "used", Path: f, MaxDownloads: 1, Count: 1})
	st.Add(Share{Token: "missing", Path: "/nonexistent/file", MaxDownloads: 1})
	st.Add(Share{Token: "revoked", Path: f, MaxDownloads: 1, Revoked: true})

	removed, err := st.Prune(now)
	if err != nil {
		t.Fatal(err)
	}
	if len(removed) != 4 {
		t.Fatalf("removed %d shares, want 4", len(removed))
	}
	all, _ := st.List()
	if len(all) != 1 || all[0].Token != "live" {
		t.Fatalf("remaining = %+v, want only live", all)
	}
	if n, _ := st.CountActive(now); n != 1 {
		t.Fatalf("active = %d, want 1", n)
	}
}

func TestTokenProperties(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 1000; i++ {
		tok, err := newToken()
		if err != nil {
			t.Fatal(err)
		}
		if len(tok) != 24 {
			t.Fatalf("token %q has length %d", tok, len(tok))
		}
		if seen[tok] {
			t.Fatal("duplicate token")
		}
		seen[tok] = true
	}
	if s := shortToken("abcdefghijkl"); s != "abcdefgh…" {
		t.Fatalf("shortToken = %q", s)
	}
}

// Tests below cover GhostShare's schema (CLAUDE.md, Data Model).

func TestRoundTripAllFields(t *testing.T) {
	st := testStore(t)
	want := Share{Token: "tok", Path: "/srv/report.pdf", Filename: "renamed.pdf", Created: 100,
		ExpiresAt: 200, MaxDownloads: 3, Count: 1, OnionSession: "sess-1"}
	if err := st.Add(want); err != nil {
		t.Fatal(err)
	}
	got, err := st.Get("tok")
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("got %+v\nwant %+v", got, want)
	}
}

func TestFilenameDefaultsToBaseName(t *testing.T) {
	st := testStore(t)
	st.Add(Share{Token: "tok", Path: "/srv/files/report.pdf"})
	if sh, _ := st.Get("tok"); sh.Filename != "report.pdf" {
		t.Fatalf("filename = %q, want report.pdf", sh.Filename)
	}
}

func TestNoExpiryIsStoredAsNull(t *testing.T) {
	st := testStore(t)
	st.Add(Share{Token: "forever", Path: "/x", MaxDownloads: 1})
	st.Add(Share{Token: "timed", Path: "/x", MaxDownloads: 1, ExpiresAt: 12345})
	for tok, wantNull := range map[string]bool{"forever": true, "timed": false} {
		var isNull bool
		if err := st.db.QueryRow(`SELECT expires_at IS NULL FROM shares WHERE token = ?`, tok).Scan(&isNull); err != nil {
			t.Fatal(err)
		}
		if isNull != wantNull {
			t.Errorf("%s: expires_at IS NULL = %v, want %v", tok, isNull, wantNull)
		}
	}
	if sh, _ := st.Get("forever"); sh.ExpiresAt != 0 || !sh.Active(time.Now()) {
		t.Fatalf("forever share = %+v, want active with ExpiresAt 0", sh)
	}
}

func TestRevoke(t *testing.T) {
	st := testStore(t)
	now := time.Now()
	st.Add(Share{Token: "tok", Path: "/x", MaxDownloads: 1})
	if ok, err := st.Revoke("tok"); !ok || err != nil {
		t.Fatalf("Revoke = %v, %v; want true, nil", ok, err)
	}
	if ok, _ := st.Revoke("tok"); ok {
		t.Fatal("second Revoke reported success")
	}
	if ok, _ := st.Revoke("nosuch"); ok {
		t.Fatal("Revoke of unknown token reported success")
	}
	sh, _ := st.Get("tok")
	if !sh.Revoked || sh.Active(now) {
		t.Fatalf("revoked share = %+v, want revoked and inactive", sh)
	}
	if n, _ := st.CountActive(now); n != 0 {
		t.Fatalf("active = %d, want 0", n)
	}
}
