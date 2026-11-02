// Ported from QuickShare (github.com/computerguymackay/QuickShare).
//
// [diverges from QuickShare] DaemonStatus reports Tor mode and startup
// progress instead of bind/addr/TLS. Each share has its own onion, so
// add-share and list return links, and add-share may take minutes.

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// The control channel carries one JSON request and one JSON response
// per connection.

type ctrlRequest struct {
	Op           string `json:"op"` // status | add-share | list | revoke | stop
	Key          string `json:"key,omitempty"`
	Path         string `json:"path,omitempty"`
	ExpiresAt    int64  `json:"expires_at,omitempty"`
	MaxDownloads int    `json:"max_downloads,omitempty"`
	Token        string `json:"token,omitempty"`
	KeepMetadata bool   `json:"keep_metadata,omitempty"` // add-share: serve the original, unstripped
}

type DaemonStatus struct {
	PID        int    `json:"pid"`
	Ready      bool   `json:"ready"`       // connected to Tor and accepting shares
	Phase      string `json:"phase"`       // what the daemon is doing while not ready
	TorSpawned bool   `json:"tor_spawned"` // we started Tor (vs. using a running one)
	Active     int    `json:"active"`
	Onions     int    `json:"onions"` // onion services currently published
	Version    string `json:"version"`
}

type ctrlResponse struct {
	OK      bool              `json:"ok"`
	Error   string            `json:"error,omitempty"`
	Status  *DaemonStatus     `json:"status,omitempty"`
	Share   *Share            `json:"share,omitempty"`
	Shares  []Share           `json:"shares,omitempty"`
	URL     string            `json:"url,omitempty"`     // add-share: the new share's link
	Warning string            `json:"warning,omitempty"` // add-share: one line for the user's stderr
	URLs    map[string]string `json:"urls,omitempty"`    // list: token -> current link
}

// errDaemonDown means nothing answered on the control channel.
var errDaemonDown = errors.New("daemon is not running")

func ctrlCall(p Paths, req ctrlRequest) (ctrlResponse, error) {
	return ctrlCallTimeout(p, req, 10*time.Second)
}

// ctrlCallTimeout is ctrlCall for requests that can take longer, such as
// add-share, which waits for the share's onion to be reachable.
func ctrlCallTimeout(p Paths, req ctrlRequest, timeout time.Duration) (ctrlResponse, error) {
	conn, key, err := dialControl(p)
	if err != nil {
		return ctrlResponse{}, errDaemonDown
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))
	req.Key = key
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return ctrlResponse{}, errDaemonDown
	}
	var resp ctrlResponse
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return ctrlResponse{}, errDaemonDown
	}
	if !resp.OK {
		return resp, errors.New(resp.Error)
	}
	return resp, nil
}

func daemonStatus(p Paths) (DaemonStatus, error) {
	resp, err := ctrlCall(p, ctrlRequest{Op: "status"})
	if err != nil {
		return DaemonStatus{}, err
	}
	if resp.Status == nil {
		return DaemonStatus{}, errDaemonDown
	}
	return *resp.Status, nil
}

// resolveShare finds a share by its number (as `list` shows it, "4" or
// "#4"), by full token, or by a unique token prefix of at least 6
// characters. An argument of digits only is always a number.
//
// [diverges from QuickShare] Share numbers are new.
func resolveShare(shares []Share, q string) (Share, error) {
	q = strings.TrimSuffix(strings.TrimSpace(q), "…")
	if n, ok := shareNumber(q); ok {
		for _, sh := range shares {
			if sh.Number == n {
				return sh, nil
			}
		}
		return Share{}, fmt.Errorf("no active share #%d; `ghostshare list` shows the current numbers", n)
	}
	var matches []Share
	for _, sh := range shares {
		if sh.Token == q {
			return sh, nil
		}
		if len(q) >= 6 && strings.HasPrefix(sh.Token, q) {
			matches = append(matches, sh)
		}
	}
	switch len(matches) {
	case 0:
		return Share{}, fmt.Errorf("no share matches %q", q)
	case 1:
		return matches[0], nil
	default:
		return Share{}, fmt.Errorf("%q matches %d shares; use more characters", q, len(matches))
	}
}

// shareNumber parses "4" or "#4".
func shareNumber(q string) (int, bool) {
	q = strings.TrimPrefix(q, "#")
	if q == "" || len(q) > 9 || strings.Trim(q, "0123456789") != "" {
		return 0, false
	}
	n, err := strconv.Atoi(q)
	return n, err == nil && n > 0
}

// shareURL is the link for a share on the given onion host. The path is the
// token alone, so the link doesn't reveal the filename; the recipient gets
// the name from Content-Disposition. [diverges from QuickShare]
func shareURL(onion string, sh Share) string {
	return "http://" + onion + "/" + sh.Token
}
