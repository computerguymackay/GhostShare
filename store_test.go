// Ported from QuickShare (github.com/computerguymackay/QuickShare).

package main

import (
	"database/sql"
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

func TestServePathAndMetadataRoundTrip(t *testing.T) {
	st := testStore(t)
	want := Share{Token: "tok", Path: "/srv/photo.jpg", Filename: "photo.jpg", Created: 1,
		MaxDownloads: 1, ServePath: "/home/u/.ghostshare/files/tok", MetadataStripped: true}
	st.Add(want)
	if got, _ := st.Get("tok"); got != want {
		t.Fatalf("got %+v\nwant %+v", got, want)
	}
	st.Add(Share{Token: "plain", Path: "/srv/a.txt", MaxDownloads: 1})
	if got, _ := st.Get("plain"); got.ServePath != "" || got.MetadataStripped || got.ServedPath() != "/srv/a.txt" {
		t.Fatalf("plain share = %+v", got)
	}
}

// A state.db from before metadata stripping gets the new columns and keeps
// its shares.
func TestOpenStoreUpgradesOldDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.db")
	db, err := sql.Open("sqlite", "file:"+path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`CREATE TABLE shares (token TEXT PRIMARY KEY, file_path TEXT NOT NULL, filename TEXT NOT NULL,
		expires_at INTEGER, max_downloads INTEGER, downloads INTEGER DEFAULT 0, created_at INTEGER NOT NULL,
		revoked INTEGER DEFAULT 0, onion_session TEXT);
		INSERT INTO shares (token, file_path, filename, max_downloads, created_at) VALUES ('old', '/x/a.jpg', 'a.jpg', 1, 5);`)
	db.Close()
	if err != nil {
		t.Fatal(err)
	}
	st, err := openStore(path)
	if err != nil {
		t.Fatalf("opening an old database: %v", err)
	}
	defer st.Close()
	got, err := st.Get("old")
	if err != nil || got.Path != "/x/a.jpg" || got.ServePath != "" || got.MetadataStripped {
		t.Fatalf("old share after upgrade = %+v, %v", got, err)
	}
	if err := st.Add(Share{Token: "new", Path: "/x/b.jpg", ServePath: "/c", MetadataStripped: true}); err != nil {
		t.Fatalf("adding to an upgraded database: %v", err)
	}
}

func TestDeletingOriginalEndsStrippedShare(t *testing.T) {
	st := testStore(t)
	orig := testFile(t, "orig")
	cp := filepath.Join(t.TempDir(), "copy")
	os.WriteFile(cp, []byte("copy"), 0o600)
	st.Add(Share{Token: "tok", Path: orig, ServePath: cp, MaxDownloads: 1})
	os.Remove(orig)
	if removed, _ := st.Prune(time.Now()); len(removed) != 1 {
		t.Fatal("share with a deleted original was not pruned")
	}
}
