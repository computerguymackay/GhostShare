// Metadata stripping, done by metakill (github.com/computerguymackay/metakill).
//
// [diverges from QuickShare] QuickShare serves files as they are.
//
// GhostShare's part is only the glue: which metakill options to use, where
// the cleaned copy is written, repacking 7z/RAR as zip (archive.go), and the
// one-line messages. A share is never blocked over metadata: if a file
// can't be cleaned, the original is shared with a warning.

package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/computerguymackay/metakill"
	"github.com/computerguymackay/metakill/report"
)

// metakillOptions keeps what makes media useful to the recipient and removes
// what identifies the sender:
//   - KeepTags: title, artist, album, track and year (as YYYY) in audio and
//     video, and the title of documents. Everything else in those tags goes.
//   - KeepICC: colour profiles, so photos look right.
//
// Cover art and thumbnails are removed: metakill keeps both or neither, and
// a photo's EXIF thumbnail can show the picture before it was cropped.
// GPS, timestamps, device identifiers, owner and author names and
// software strings are always removed.
var metakillOptions = metakill.Options{KeepTags: true, KeepICC: true}

type stripResult struct {
	Copied   bool   // a cleaned copy was written to dst; serve it instead of the original
	Stripped bool   // the served file carries none of the metadata metakill looks for
	Filename string // the name to serve under, if it changed (photos.7z → photos.zip)
	Warning  string // one line for stderr, or ""
}

var encryptedExts = map[string]bool{".age": true, ".gpg": true, ".pgp": true}

// stripMetadata writes a cleaned copy of src to dst when there is something
// to remove. It never fails: if the type is unsupported or cleaning goes
// wrong, the result says to share src as-is and carries a warning. dst is
// only created on success.
//
// work is a scratch directory that must not exist yet; everything is
// staged there (never in the system temp directory) and the caller removes
// it afterwards.
func stripMetadata(src, dst, work string) stripResult {
	name := filepath.Base(src)
	asIs := func(format string, a ...any) stripResult {
		return stripResult{Warning: fmt.Sprintf(format, a...) + "; sharing as-is"}
	}

	f, err := os.Open(src)
	if err != nil {
		return asIs("couldn't read %s to remove its metadata (%v)", name, err)
	}
	encrypted := looksEncrypted(f, name)
	format, known := metakill.Detect(f, name)
	f.Close()
	switch {
	case encrypted:
		return asIs("can't remove metadata from encrypted %s (next time, strip metadata before encrypting)", typeName(name))
	case !known:
		return asIs("can't remove metadata from %s", typeName(name))
	}

	if err := os.Mkdir(work, 0o700); err != nil {
		return asIs("couldn't prepare a copy of %s (%v)", name, err)
	}
	served := name
	var in string // the copy metakill cleans in place
	if format == "7z" || format == "rar" {
		served = zipName(name)
		in = filepath.Join(work, served)
		if err := convertToZip(src, format, in); err != nil {
			return asIs("couldn't repack %s as zip to remove its metadata (%v)", name, err)
		}
	} else {
		// Nothing to remove (plain text, an already-clean photo): serve the
		// original rather than copying it.
		pre, err := inspect(src)
		if err != nil {
			return cleanFailed(name, err)
		}
		if pre.Status == report.StatusAlreadyClean {
			if !pre.FullyClean {
				return stripResult{Warning: notFullyClean(name, pre)}
			}
			return stripResult{Stripped: true}
		}
		in = filepath.Join(work, name)
		if err := copyFile(src, in); err != nil {
			return asIs("couldn't copy %s to remove its metadata (%v)", name, err)
		}
	}

	// CleanFile stages its output next to in, so it stays inside work.
	rep, err := metakill.CleanFile(in, metakillOptions)
	if err != nil {
		return cleanFailed(name, err)
	}
	if err := os.Rename(in, dst); err != nil {
		return asIs("couldn't save the cleaned copy of %s (%v)", name, err)
	}
	res := stripResult{Copied: true, Stripped: rep.FullyClean}
	if served != name {
		res.Filename = served
	}
	switch {
	case !rep.FullyClean:
		res.Warning = notFullyClean(name, rep)
	case len(rep.Warnings) > 0:
		// Clean, but metakill saw something it doesn't change, such as
		// archive entries under a home folder ("Users/jane/...").
		res.Warning = fmt.Sprintf("%s: %s", name, firstWarning(rep))
	}
	return res
}

// firstWarning is metakill's first warning, with a count of the rest.
func firstWarning(rep report.Report) string {
	if len(rep.Warnings) == 0 {
		return "metakill gave no reason"
	}
	w := strings.ReplaceAll(rep.Warnings[0], "\n", " ")
	if n := len(rep.Warnings) - 1; n > 0 {
		w += fmt.Sprintf(" (and %d more)", n)
	}
	return w
}

func inspect(path string) (report.Report, error) {
	f, err := os.Open(path)
	if err != nil {
		return report.Report{}, err
	}
	defer f.Close()
	return metakill.Inspect(f, filepath.Base(path), metakillOptions)
}

// cleanFailed is the warning for a file metakill recognised but couldn't
// clean. metakill never writes a copy that fails its own check, so the
// original is shared.
func cleanFailed(name string, err error) stripResult {
	verb := "couldn't"
	if errors.Is(err, metakill.ErrSkipped) || errors.Is(err, metakill.ErrUnsupported) || errors.Is(err, metakill.ErrNeedsTool) {
		verb = "can't" // deliberately left alone (a signed package, an encrypted PDF, ...)
	}
	return stripResult{Warning: fmt.Sprintf("%s remove metadata from %s (%v); sharing as-is", verb, name, err)}
}

// notFullyClean is the warning for a copy that still holds some metadata
// metakill found but couldn't remove (a huge file inside an archive, say).
func notFullyClean(name string, rep report.Report) string {
	return fmt.Sprintf("some metadata in %s couldn't be removed: %s", name, firstWarning(rep))
}

// looksEncrypted spots age and OpenPGP files, which metakill doesn't know:
// their metadata (if any) is inside the ciphertext. f is left at the start.
func looksEncrypted(f *os.File, name string) bool {
	head := make([]byte, 64)
	n, _ := io.ReadFull(f, head)
	f.Seek(0, io.SeekStart)
	head = head[:n]
	return encryptedExts[strings.ToLower(filepath.Ext(name))] ||
		bytes.HasPrefix(head, []byte("age-encryption.org/v1\n")) ||
		bytes.HasPrefix(head, []byte("-----BEGIN AGE ENCRYPTED FILE-----")) ||
		bytes.HasPrefix(head, []byte("-----BEGIN PGP MESSAGE-----"))
}

// typeName is "… .bin files" for messages, or a fallback without an extension.
func typeName(name string) string {
	if ext := strings.ToLower(filepath.Ext(name)); ext != "" {
		return ext + " files"
	}
	return "files of this type"
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}
