// Ported from QuickShare (github.com/computerguymackay/QuickShare).
//
// [diverges from QuickShare] There is no [server] section (bind, wan,
// tls_cert, tls_key): the Tor onion service replaces all of it. Keys that
// ghostshare doesn't use are reported, so a config copied from QuickShare
// doesn't fail silently. The [share] section is unchanged.

package main

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
)

type Config struct {
	Share struct {
		DefaultExpiry       string `toml:"default_expiry"`
		DefaultMaxDownloads *int   `toml:"default_max_downloads"`
	} `toml:"share"`
}

const configTemplate = `# ghostshare configuration

# There are no network settings: ghostshare always shares through a Tor
# onion service. To point it at a Tor control port other than
# 127.0.0.1:9051, set GHOSTSHARE_TOR_CONTROL.

[share]
default_expiry        = "24h"
default_max_downloads = 1
`

// loadConfig reads the config file. A missing file is not an error: a
// commented template is written so the user has something to edit. The
// returned warnings name keys that ghostshare ignores.
func loadConfig(p Paths) (Config, []string, error) {
	var c Config
	data, err := os.ReadFile(p.Config)
	if errors.Is(err, os.ErrNotExist) {
		if p.ensure() == nil {
			os.WriteFile(p.Config, []byte(configTemplate), 0o600)
		}
		data = []byte(configTemplate)
	} else if err != nil {
		return c, nil, err
	}
	md, err := toml.Decode(string(data), &c)
	if err != nil {
		return c, nil, fmt.Errorf("%s: %w", p.Config, err)
	}
	// Report leaf keys only: "server.wan", not also "server".
	unused := md.Undecoded()
	var warns []string
	for i, k := range unused {
		parent := false
		for j, other := range unused {
			if i != j && strings.HasPrefix(other.String(), k.String()+".") {
				parent = true
			}
		}
		if !parent {
			warns = append(warns, fmt.Sprintf("%s: %q is not a ghostshare setting; ignoring it", p.Config, k.String()))
		}
	}
	if c.Share.DefaultExpiry == "" {
		c.Share.DefaultExpiry = "24h"
	}
	if c.Share.DefaultMaxDownloads == nil {
		one := 1
		c.Share.DefaultMaxDownloads = &one
	}
	return c, warns, nil
}

// parseDuration accepts Go durations ("90m", "1h30m") plus whole days ("7d").
func parseDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "0" {
		return 0, nil
	}
	if strings.HasSuffix(s, "d") {
		n, err := strconv.Atoi(strings.TrimSuffix(s, "d"))
		if err != nil || n < 0 {
			return 0, fmt.Errorf("invalid duration %q", s)
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("invalid duration %q (examples: 30m, 24h, 7d)", s)
	}
	if d < 0 {
		return 0, fmt.Errorf("duration %q is negative", s)
	}
	return d, nil
}

// validateLimits enforces that a share always ends somehow.
//
// [diverges from QuickShare] There is no --allow-forever in v1 (CLAUDE.md,
// CLI Surface), so a share with no download limit and no expiry is refused.
func validateLimits(maxDownloads int, expires time.Duration) error {
	if maxDownloads < 0 {
		return errors.New("--max-downloads cannot be negative")
	}
	if expires < 0 {
		return errors.New("--expires cannot be negative")
	}
	if maxDownloads == 0 && expires == 0 {
		return errors.New("--max-downloads 0 with --expires 0 would share forever, which ghostshare does not allow; set a download limit or an expiry")
	}
	if expires > 0 && expires < time.Second {
		return errors.New("--expires must be at least 1s")
	}
	return nil
}
