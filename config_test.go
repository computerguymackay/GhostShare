// Ported from QuickShare (github.com/computerguymackay/QuickShare).

package main

import (
	"os"
	"strings"
	"testing"
	"time"
)

func TestValidateLimits(t *testing.T) {
	cases := []struct {
		max int
		exp time.Duration
		ok  bool
	}{
		{1, 24 * time.Hour, true},
		{0, time.Hour, true}, // unlimited downloads, expires
		{3, 0, true},         // no expiry, limited downloads
		{0, 0, false},        // forever is always refused in v1
		{-1, time.Hour, false},
		{1, 500 * time.Millisecond, false},
	}
	for _, c := range cases {
		err := validateLimits(c.max, c.exp)
		if (err == nil) != c.ok {
			t.Errorf("validateLimits(%d, %s) = %v, want ok=%v", c.max, c.exp, err, c.ok)
		}
	}
}

func TestParseDuration(t *testing.T) {
	for in, want := range map[string]time.Duration{"0": 0, "30s": 30 * time.Second, "24h": 24 * time.Hour, "7d": 7 * 24 * time.Hour} {
		got, err := parseDuration(in)
		if err != nil || got != want {
			t.Errorf("parseDuration(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "abc", "-5m", "xd"} {
		if _, err := parseDuration(bad); err == nil {
			t.Errorf("parseDuration(%q) accepted", bad)
		}
	}
}

func TestLoadConfigWritesTemplate(t *testing.T) {
	t.Setenv("GHOSTSHARE_HOME", t.TempDir())
	p, _ := resolvePaths()
	cfg, warns, err := loadConfig(p)
	if err != nil {
		t.Fatal(err)
	}
	if *cfg.Share.DefaultMaxDownloads != 1 || cfg.Share.DefaultExpiry != "24h" || len(warns) != 0 {
		t.Fatalf("unexpected defaults: %+v %q", cfg, warns)
	}
	if !fileExists(p.Config) {
		t.Fatal("config template not written")
	}
	if fi, _ := os.Stat(p.Config); fi.Mode().Perm() != 0o600 {
		t.Errorf("config mode %v, want 0600", fi.Mode().Perm())
	}

	os.WriteFile(p.Config, []byte("[share]\ndefault_max_downloads = 0\ndefault_expiry = \"2h\"\n"), 0o600)
	cfg, _, err = loadConfig(p)
	if err != nil {
		t.Fatal(err)
	}
	if *cfg.Share.DefaultMaxDownloads != 0 || cfg.Share.DefaultExpiry != "2h" {
		t.Fatalf("config not read: %+v", cfg)
	}
}

// A QuickShare config's [server] section means nothing here; say so.
func TestLoadConfigReportsQuickShareOnlyKeys(t *testing.T) {
	t.Setenv("GHOSTSHARE_HOME", t.TempDir())
	p, _ := resolvePaths()
	p.ensure()
	os.WriteFile(p.Config, []byte("[server]\nwan = \"203.0.113.5:9000\"\n[share]\ndefault_max_downloads = 2\n"), 0o600)
	cfg, warns, err := loadConfig(p)
	if err != nil {
		t.Fatal(err)
	}
	if *cfg.Share.DefaultMaxDownloads != 2 {
		t.Fatalf("[share] not read: %+v", cfg)
	}
	if len(warns) != 1 || !strings.Contains(warns[0], "server.wan") {
		t.Fatalf("warnings = %q, want one about server.wan", warns)
	}
}

func TestLoadConfigBadTOML(t *testing.T) {
	t.Setenv("GHOSTSHARE_HOME", t.TempDir())
	p, _ := resolvePaths()
	p.ensure()
	os.WriteFile(p.Config, []byte("[share\n"), 0o600)
	if _, _, err := loadConfig(p); err == nil || !strings.Contains(err.Error(), p.Config) {
		t.Fatalf("bad TOML: %v, want an error naming the file", err)
	}
}
