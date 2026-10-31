// Ported from QuickShare (github.com/computerguymackay/QuickShare).
//
// Phase 3 ports only parseDuration and validateLimits. Loading
// ~/.ghostshare/config.toml arrives in Phase 4 (see CLAUDE.md, Build Order).

package main

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

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
