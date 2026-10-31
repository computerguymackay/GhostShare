package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestVersionIncludesAttribution(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run([]string{"--version"}, &out, &errOut); code != 0 {
		t.Fatalf("exit code %d, want 0", code)
	}
	if !strings.Contains(out.String(), attribution) {
		t.Errorf("--version output %q is missing the attribution string", out.String())
	}
	if errOut.Len() != 0 {
		t.Errorf("unexpected stderr: %q", errOut.String())
	}
}

func TestHelpIncludesAttributionAndTorBrowser(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run([]string{"--help"}, &out, &errOut); code != 0 {
		t.Fatalf("exit code %d, want 0", code)
	}
	for _, want := range []string{attribution, "Tor Browser"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("--help output is missing %q", want)
		}
	}
}
