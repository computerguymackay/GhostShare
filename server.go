// Ported from QuickShare (github.com/computerguymackay/QuickShare).
//
// [diverges from QuickShare] Log lines never include r.RemoteAddr (CLAUDE.md:
// "Never log IPs"), the download name comes from the stored filename, and
// no Last-Modified header is sent (it would reveal the file's mtime). A
// share with a metadata-stripped copy serves the copy, under the original
// filename. Links are /<token> only, with no filename in the path; the
// name reaches the recipient through Content-Disposition (see
// contentDisposition).
// The download-counting rule is unchanged.

package main

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
	"unicode"
	"unicode/utf8"
)

// FileServer serves shares by token and counts completed downloads.
//
// Counting rule: a GET without a Range header that sends the whole file
// with no write error counts once. Range requests (resumes, partial
// fetches) and HEAD requests never count.
type FileServer struct {
	store *Store
	log   *log.Logger
	now   func() time.Time

	inflight atomic.Int64
	// onChange runs after any request finishes, so the daemon can
	// re-check whether it should shut down.
	onChange func()
}

func (fs *FileServer) InFlight() int64 { return fs.inflight.Load() }

func (fs *FileServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	fs.inflight.Add(1)
	defer func() {
		fs.inflight.Add(-1)
		if fs.onChange != nil {
			fs.onChange()
		}
	}()

	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// URL shape: /<token>, nothing else.
	token, rest, extra := strings.Cut(strings.TrimPrefix(r.URL.Path, "/"), "/")
	gone := func(reason string) {
		fs.log.Printf("%s %s → 410 (%s)", r.Method, shortToken(token), reason)
		http.Error(w, "this link has expired or does not exist", http.StatusGone)
	}
	if token == "" {
		gone("no token")
		return
	}
	if extra || rest != "" {
		gone("unknown path")
		return
	}

	sh, err := fs.store.Get(token)
	if err != nil {
		gone("unknown")
		return
	}
	if !sh.Active(fs.now()) {
		gone("expired, used up, or revoked")
		return
	}

	if !sh.Servable() {
		fs.store.Delete(token)
		gone("file missing")
		return
	}
	f, err := os.Open(sh.ServedPath())
	if err != nil {
		fs.store.Delete(token)
		gone("file missing")
		return
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() {
		fs.store.Delete(token)
		gone("file missing")
		return
	}

	name := sh.Filename
	h := w.Header()
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Content-Disposition", contentDisposition(name))

	cw := &countingWriter{ResponseWriter: w, status: http.StatusOK}
	// A zero modtime means no Last-Modified header, so the file's mtime
	// never reaches the recipient.
	http.ServeContent(cw, r, name, time.Time{}, f)

	counted := r.Method == http.MethodGet &&
		r.Header.Get("Range") == "" &&
		cw.status == http.StatusOK &&
		cw.err == nil &&
		cw.n == fi.Size() &&
		r.Context().Err() == nil

	note := ""
	if counted {
		after, err := fs.store.Increment(token)
		if err != nil {
			fs.log.Printf("count update failed for %s: %v", shortToken(token), err)
		} else {
			note = " counted " + countString(after)
		}
	}
	fs.log.Printf("%s %s → %d %d/%d bytes%s", r.Method, shortToken(token), cw.status, cw.n, fi.Size(), note)
}

func countString(sh Share) string {
	if sh.MaxDownloads == 0 {
		return strconv.Itoa(sh.Count) + "/∞"
	}
	return strconv.Itoa(sh.Count) + "/" + strconv.Itoa(sh.MaxDownloads)
}

// countingWriter records the status, body bytes, and any write error.
type countingWriter struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
	n           int64
	err         error
}

func (c *countingWriter) WriteHeader(code int) {
	if !c.wroteHeader {
		c.status = code
		c.wroteHeader = true
	}
	c.ResponseWriter.WriteHeader(code)
}

func (c *countingWriter) Write(p []byte) (int, error) {
	c.wroteHeader = true
	n, err := c.ResponseWriter.Write(p)
	c.n += int64(n)
	if err != nil && c.err == nil {
		c.err = err
	}
	return n, err
}

// ReadFrom keeps the sendfile fast path of the underlying writer.
func (c *countingWriter) ReadFrom(r io.Reader) (int64, error) {
	c.wroteHeader = true
	rf, ok := c.ResponseWriter.(io.ReaderFrom)
	var n int64
	var err error
	if ok {
		n, err = rf.ReadFrom(r)
	} else {
		n, err = io.Copy(struct{ io.Writer }{c.ResponseWriter}, r)
	}
	c.n += n
	if err != nil && c.err == nil && !errors.Is(err, io.EOF) {
		c.err = err
	}
	return n, err
}

func (c *countingWriter) Unwrap() http.ResponseWriter { return c.ResponseWriter }

// contentDisposition tells the browser to save the file under name, never
// to display it (so a shared HTML or SVG file can't run in the recipient's
// browser). Quotes, backslashes, CR/LF and other control characters are
// removed first, and so are bidi overrides, which can make "photo\u202egpj.exe"
// display as "photoexe.jpg". filename= is an ASCII fallback (other characters become
// "_"); filename*= carries the full UTF-8 name (RFC 6266, RFC 5987).
func contentDisposition(name string) string {
	clean := strings.Map(func(r rune) rune {
		if r == '"' || r == '\\' || r == utf8.RuneError ||
			unicode.IsControl(r) || unicode.Is(unicode.Bidi_Control, r) {
			return -1
		}
		return r
	}, name)
	clean = strings.TrimSpace(clean)
	if clean == "" {
		clean = "download"
	}

	ascii := strings.Map(func(r rune) rune {
		if r > unicode.MaxASCII {
			return '_'
		}
		return r
	}, clean)
	var enc strings.Builder
	for _, b := range []byte(clean) {
		if isAttrChar(b) {
			enc.WriteByte(b)
		} else {
			fmt.Fprintf(&enc, "%%%02X", b)
		}
	}
	return `attachment; filename="` + ascii + `"; filename*=UTF-8''` + enc.String()
}

// isAttrChar reports whether b may appear unescaped in an RFC 5987 value.
func isAttrChar(b byte) bool {
	switch {
	case 'a' <= b && b <= 'z', 'A' <= b && b <= 'Z', '0' <= b && b <= '9':
		return true
	}
	return strings.IndexByte("!#$&+-.^_`|~", b) >= 0
}
