// Repacking of 7z and RAR archives as zip, so metakill can clean them.
//
// metakill reads 7z and RAR in pure Go but can only write them with an
// external 7-Zip or rar. GhostShare never runs extra programs besides Tor,
// so it rewrites those archives as zip here, using the same pure-Go
// readers, and lets metakill clean the zip. The entry checks follow
// metakill's (internal/handlers/extarchive.go, sevenzip.go, rar.go).

package main

import (
	"archive/zip"
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
	"time"

	"github.com/bodgit/sevenzip"
	"github.com/nwaples/rardecode/v2"
)

// zipEpoch is the time given to every repacked entry; metakill resets zip
// times to the same value.
var zipEpoch = time.Date(1980, 1, 1, 0, 0, 0, 0, time.UTC)

var sevenZipMagic = []byte{'7', 'z', 0xBC, 0xAF, 0x27, 0x1C}

// archiveEntry is one member of a 7z or RAR archive.
type archiveEntry struct {
	name   string
	isDir  bool
	isLink bool
	exec   bool
	open   func() (io.ReadCloser, error)
}

// zipName is the served name of a repacked archive: photos.7z → photos.zip.
func zipName(name string) string {
	return strings.TrimSuffix(name, path.Ext(name)) + ".zip"
}

// convertToZip rewrites the 7z or RAR archive at src as a zip at dst.
// format is metakill's name for it ("7z" or "rar"). Encrypted,
// multi-volume and incomplete archives, and archives holding links or
// unsafe paths, are refused. dst is removed on failure.
func convertToZip(src, format, dst string) (err error) {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := out.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			os.Remove(dst)
		}
	}()
	zw := newZipRepacker(out)
	switch format {
	case "7z":
		err = walk7z(in, zw.add)
	case "rar":
		err = walkRAR(in, zw.add)
	default:
		err = fmt.Errorf("%s archives can't be repacked", format)
	}
	if err != nil {
		return err
	}
	if zw.n == 0 {
		return errors.New("the archive is empty")
	}
	return zw.w.Close()
}

type zipRepacker struct {
	w    *zip.Writer
	seen map[string]bool
	n    int
}

func newZipRepacker(w io.Writer) *zipRepacker {
	return &zipRepacker{w: zip.NewWriter(w), seen: map[string]bool{}}
}

func (z *zipRepacker) add(e archiveEntry) error {
	if e.isLink {
		return fmt.Errorf("%q is a link, which zip repacking doesn't support", e.name)
	}
	name, err := safeEntryName(e.name)
	if err != nil {
		return err
	}
	h := &zip.FileHeader{Name: name, Modified: zipEpoch}
	if e.isDir {
		h.Name += "/"
		h.SetMode(os.ModeDir | 0o755)
	} else {
		h.Method = zip.Deflate
		h.SetMode(0o644)
		if e.exec {
			h.SetMode(0o755)
		}
	}
	if z.seen[h.Name] {
		if e.isDir {
			return nil
		}
		return fmt.Errorf("%q appears twice", e.name)
	}
	z.seen[h.Name] = true
	z.n++
	w, err := z.w.CreateHeader(h)
	if err != nil || e.isDir {
		return err
	}
	rc, err := e.open()
	if err != nil {
		return fmt.Errorf("%s: %w", e.name, err)
	}
	defer rc.Close()
	if _, err := io.Copy(w, rc); err != nil {
		return fmt.Errorf("%s: %w", e.name, err)
	}
	return nil
}

// safeEntryName rejects names that would land outside the folder a
// recipient extracts into (absolute paths, drive letters, "..").
func safeEntryName(name string) (string, error) {
	n := strings.ReplaceAll(name, "\\", "/")
	if n == "" || strings.HasPrefix(n, "/") || (len(n) > 1 && n[1] == ':') {
		return "", fmt.Errorf("unsafe entry name %q", name)
	}
	clean := path.Clean(n)
	if clean == "." || clean == ".." || strings.HasPrefix(clean, "../") {
		return "", fmt.Errorf("unsafe entry name %q", name)
	}
	return clean, nil
}

func walk7z(f *os.File, add func(archiveEntry) error) error {
	st, err := f.Stat()
	if err != nil {
		return err
	}
	size := st.Size()
	hdr := make([]byte, 32)
	if _, err := f.ReadAt(hdr, 0); err != nil || !bytes.HasPrefix(hdr, sevenZipMagic) {
		return errors.New("not a 7z archive")
	}
	next := binary.LittleEndian.Uint64(hdr[12:])
	nextSize := binary.LittleEndian.Uint64(hdr[20:])
	if end := 32 + next + nextSize; end > uint64(size) || end < next {
		return errors.New("the archive is incomplete (part of a multi-volume set, or truncated)")
	}
	zr, err := sevenzip.NewReader(f, size)
	if err != nil {
		return sevenZipErr(err)
	}
	for _, zf := range zr.File {
		attr := zf.Attributes
		var mode uint32
		if attr&0x8000 != 0 { // 7-Zip's Unix extension: st_mode in the high 16 bits
			mode = attr >> 16
		}
		err := add(archiveEntry{
			name:   zf.Name,
			isDir:  zf.FileInfo().IsDir(),
			isLink: mode&0o170000 == 0o120000 || attr&0x400 != 0, // symlink or Windows reparse point
			exec:   mode&0o111 != 0,
			open: func() (io.ReadCloser, error) {
				rc, err := zf.Open()
				if err != nil {
					return nil, sevenZipErr(err)
				}
				return rc, nil
			},
		})
		if err != nil {
			return sevenZipErr(err)
		}
	}
	return nil
}

func sevenZipErr(err error) error {
	var re *sevenzip.ReadError
	if errors.As(err, &re) && re.Encrypted || strings.Contains(strings.ToLower(err.Error()), "password") {
		return errors.New("the archive is encrypted")
	}
	return err
}

func walkRAR(f *os.File, add func(archiveEntry) error) error {
	rr, err := rardecode.NewReader(bufio.NewReader(f))
	if err != nil {
		return rarErr(err)
	}
	for {
		h, err := rr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return rarErr(err)
		}
		if h.Encrypted || h.HeaderEncrypted {
			return errors.New("the archive is encrypted")
		}
		e := archiveEntry{
			name:   h.Name,
			isDir:  h.IsDir,
			isLink: h.LinkType != 0,
			open:   func() (io.ReadCloser, error) { return io.NopCloser(rr), nil },
		}
		if h.HostOS == rardecode.HostOSUnix {
			e.exec = h.Attributes&0o111 != 0
		}
		if err := add(e); err != nil {
			return rarErr(err)
		}
	}
}

func rarErr(err error) error {
	switch {
	case errors.Is(err, rardecode.ErrArchiveEncrypted), errors.Is(err, rardecode.ErrArchivedFileEncrypted),
		errors.Is(err, rardecode.ErrBadPassword):
		return errors.New("the archive is encrypted")
	case errors.Is(err, rardecode.ErrMultiVolume):
		return errors.New("multi-volume archives can't be repacked")
	}
	return err
}
