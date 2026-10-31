// Command ghostshare shares a file over a temporary Tor onion service.
// It is based on QuickShare (github.com/computerguymackay/QuickShare).
// See README.md and CLAUDE.md.
package main

import (
	"fmt"
	"io"
	"os"
)

const version = "0.1.0-dev"

// attribution must appear in --help and --version (CLAUDE.md, Lineage & Attribution).
const attribution = "based on QuickShare (github.com/computerguymackay/QuickShare)"

const usage = `ghostshare — share a file over a temporary Tor onion service
` + attribution + `

Usage:
  ghostshare <file> [flags]       share a file and print its .onion link
  ghostshare list [-j|--json]     show active shares
  ghostshare revoke <prefix>      cancel a share (unique prefix of 6+ characters)
  ghostshare stop                 stop the background daemon (shares are kept)
  ghostshare tor-status           report whether Tor is running, spawnable, or missing

Requirements:
  Tor must be running or installed (tor on PATH). There is no clearnet fallback.
  Recipients must use Tor Browser (or curl --socks5-hostname 127.0.0.1:9050).
  A normal browser cannot open a .onion link.
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	switch args[0] {
	case "help", "-h", "-help", "--help":
		fmt.Fprint(stdout, usage)
		return 0
	case "version", "--version":
		fmt.Fprintf(stdout, "ghostshare %s, %s\n", version, attribution)
		return 0
	}
	fmt.Fprintln(stderr, "ghostshare: not implemented yet (Phase 0 scaffolding)")
	return 1
}
