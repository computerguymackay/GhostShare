// metadata.go removes identifying metadata (EXIF, GPS, author names,
// timestamps and similar) from a copy of a shared file, in pure Go. The
// user's original file is only ever read.
//
// Supported: JPEG, PNG, Office Open XML (.docx, .xlsx, .pptx, ...),
// OpenDocument (.odt, .ods, .odp, ...), and plain text (nothing to strip).
// Everything else, including PDF, is shared as-is with a warning: PDF
// metadata can't be removed reliably without a full PDF parser, because
// incremental updates and compressed object streams can keep old copies.

package main

import (
	"archive/zip"
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// stripResult is what happened to a file before sharing.
type stripResult struct {
	Copied   bool   // a stripped copy was written to dst; serve it instead of the original
	Stripped bool   // the served file carries none of the metadata we know how to find
	Warning  string // one line for stderr, or ""
}

// stripMetadata writes a metadata-free copy of src to dst when it can. It
// never fails: if the type is unsupported or stripping goes wrong, the
// result says to share src as-is and carries a warning. dst is only
// created on success.
func stripMetadata(src, dst string) stripResult {
	name := filepath.Base(src)
	kind, err := detectKind(src)
	if err != nil {
		return stripResult{Warning: fmt.Sprintf("couldn't read %s to remove its metadata (%v); sharing as-is", name, err)}
	}
	switch kind {
	case kindText:
		return stripResult{Stripped: true}
	case kindEncrypted:
		return stripResult{Warning: fmt.Sprintf("can't remove metadata from encrypted %s; sharing as-is (next time, strip metadata before encrypting)", typeName(name))}
	case kindUnsupported:
		return stripResult{Warning: fmt.Sprintf("can't remove metadata from %s; sharing as-is", typeName(name))}
	}
	if err := writeStripped(kind, src, dst); err != nil {
		return stripResult{Warning: fmt.Sprintf("couldn't remove metadata from %s (%v); sharing as-is", name, err)}
	}
	return stripResult{Copied: true, Stripped: true}
}

// typeName is "… .mp4 files" for messages, or a fallback without an extension.
func typeName(name string) string {
	if ext := strings.ToLower(filepath.Ext(name)); ext != "" {
		return ext + " files"
	}
	return "files of this type"
}

type fileKind int

const (
	kindUnsupported fileKind = iota
	kindText
	kindEncrypted
	kindJPEG
	kindPNG
	kindOOXML
	kindODF
)

var ooxmlExts = map[string]bool{
	".docx": true, ".docm": true, ".dotx": true, ".dotm": true,
	".xlsx": true, ".xlsm": true, ".xltx": true, ".xltm": true,
	".pptx": true, ".pptm": true, ".potx": true, ".potm": true, ".ppsx": true, ".ppsm": true,
}

var odfExts = map[string]bool{
	".odt": true, ".ott": true, ".ods": true, ".ots": true,
	".odp": true, ".otp": true, ".odg": true, ".otg": true,
}

var encryptedExts = map[string]bool{".age": true, ".gpg": true, ".pgp": true}

// detectKind looks at a file's first bytes, and its extension where the
// bytes alone are ambiguous (every Office file is a zip).
func detectKind(path string) (fileKind, error) {
	f, err := os.Open(path)
	if err != nil {
		return kindUnsupported, err
	}
	defer f.Close()
	head := make([]byte, 512)
	n, err := io.ReadFull(f, head)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		return kindUnsupported, err
	}
	head = head[:n]
	ext := strings.ToLower(filepath.Ext(path))
	switch {
	case bytes.HasPrefix(head, []byte("age-encryption.org/v1\n")),
		bytes.HasPrefix(head, []byte("-----BEGIN AGE ENCRYPTED FILE-----")),
		bytes.HasPrefix(head, []byte("-----BEGIN PGP MESSAGE-----")),
		encryptedExts[ext]:
		return kindEncrypted, nil
	case bytes.HasPrefix(head, []byte{0xFF, 0xD8, 0xFF}):
		return kindJPEG, nil
	case bytes.HasPrefix(head, []byte("\x89PNG\r\n\x1a\n")):
		return kindPNG, nil
	case bytes.HasPrefix(head, []byte("PK\x03\x04")) && ooxmlExts[ext]:
		return kindOOXML, nil
	case bytes.HasPrefix(head, []byte("PK\x03\x04")) && odfExts[ext]:
		return kindODF, nil
	case strings.HasPrefix(http.DetectContentType(head), "text/plain"):
		// HTML, XML and SVG are detected as other text types and can carry
		// metadata, so they count as unsupported.
		return kindText, nil
	}
	return kindUnsupported, nil
}

// writeStripped writes the stripped copy through a temp file, so dst
// either is complete or doesn't exist.
func writeStripped(kind fileKind, src, dst string) (err error) {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp := dst + ".tmp"
	out, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			out.Close()
			os.Remove(tmp)
		}
	}()
	switch kind {
	case kindJPEG:
		bw := bufio.NewWriter(out)
		if err = stripJPEG(bufio.NewReader(in), bw); err == nil {
			err = bw.Flush()
		}
	case kindPNG:
		bw := bufio.NewWriter(out)
		if err = stripPNG(bufio.NewReader(in), bw); err == nil {
			err = bw.Flush()
		}
	case kindOOXML, kindODF:
		err = stripZip(in, out, kind)
	default:
		err = errors.New("unsupported type")
	}
	if err != nil {
		return err
	}
	if err = out.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, dst)
}

// ---- JPEG ----

// stripJPEG copies a JPEG, dropping EXIF, XMP, IPTC (Photoshop APP13),
// comments, thumbnails and other application segments, and anything after
// the end-of-image marker. It keeps what decoding needs: frame and scan
// data, tables, the JFIF header, the ICC color profile, and the Adobe
// color-transform marker. The EXIF orientation is kept in a minimal EXIF
// segment of its own, so photos aren't shown rotated.
func stripJPEG(r *bufio.Reader, w io.Writer) error {
	soi := make([]byte, 2)
	if _, err := io.ReadFull(r, soi); err != nil || soi[0] != 0xFF || soi[1] != 0xD8 {
		return errors.New("not a JPEG")
	}
	w.Write(soi)
	truncated := errors.New("truncated JPEG")
	var pending byte // a marker already read by the scan copier
	for {
		m := pending
		pending = 0
		if m == 0 {
			b, err := r.ReadByte()
			if err != nil {
				return truncated
			}
			if b != 0xFF {
				return errors.New("corrupt JPEG: expected a marker")
			}
			for b == 0xFF { // fill bytes
				if b, err = r.ReadByte(); err != nil {
					return truncated
				}
			}
			m = b
		}
		switch {
		case m == 0xD9: // EOI: done; drop any trailer
			_, err := w.Write([]byte{0xFF, 0xD9})
			return err
		case m == 0x01 || (m >= 0xD0 && m <= 0xD7): // no length
			w.Write([]byte{0xFF, m})
			continue
		}
		var lb [2]byte
		if _, err := io.ReadFull(r, lb[:]); err != nil {
			return truncated
		}
		n := int(binary.BigEndian.Uint16(lb[:]))
		if n < 2 {
			return errors.New("corrupt JPEG: bad segment length")
		}
		data := make([]byte, n-2)
		if _, err := io.ReadFull(r, data); err != nil {
			return truncated
		}
		if m == 0xE1 && bytes.HasPrefix(data, []byte("Exif\x00\x00")) {
			if o := exifOrientation(data[6:]); o > 1 {
				writeSegment(w, 0xE1, minimalExif(o))
			}
			continue
		}
		if !keepJPEGSegment(m, data) {
			continue
		}
		writeSegment(w, m, data)
		if m == 0xDA { // SOS: entropy-coded data follows
			next, err := copyScan(r, w)
			if err != nil {
				return err
			}
			pending = next
		}
	}
}

func keepJPEGSegment(m byte, data []byte) bool {
	switch {
	case m == 0xE0: // APP0: keep JFIF, drop JFXX thumbnails and others
		return bytes.HasPrefix(data, []byte("JFIF\x00"))
	case m == 0xE2: // APP2: keep the ICC profile, drop MPF, FlashPix, ...
		return bytes.HasPrefix(data, []byte("ICC_PROFILE\x00"))
	case m == 0xEE: // APP14: Adobe color transform, needed to decode CMYK/YCCK
		return bytes.HasPrefix(data, []byte("Adobe"))
	case m >= 0xE1 && m <= 0xEF: // other APPn: EXIF, XMP, IPTC, vendor data
		return false
	case m == 0xFE: // COM
		return false
	}
	return true // SOFn, DHT, DQT, DRI, SOS, ...
}

func writeSegment(w io.Writer, m byte, data []byte) {
	var hdr [4]byte
	hdr[0], hdr[1] = 0xFF, m
	binary.BigEndian.PutUint16(hdr[2:], uint16(len(data)+2))
	w.Write(hdr[:])
	w.Write(data)
}

// copyScan copies entropy-coded data up to the next real marker, which it
// returns (already consumed) for the caller to handle.
func copyScan(r *bufio.Reader, w io.Writer) (byte, error) {
	bw, ok := w.(io.ByteWriter)
	if !ok {
		return 0, errors.New("internal: writer is not a ByteWriter")
	}
	for {
		b, err := r.ReadByte()
		if err != nil {
			return 0, errors.New("truncated JPEG")
		}
		if b != 0xFF {
			bw.WriteByte(b)
			continue
		}
		n, err := r.ReadByte()
		for err == nil && n == 0xFF { // fill bytes before a marker
			n, err = r.ReadByte()
		}
		if err != nil {
			return 0, errors.New("truncated JPEG")
		}
		if n == 0x00 || (n >= 0xD0 && n <= 0xD7) { // stuffed byte or restart marker
			bw.WriteByte(0xFF)
			bw.WriteByte(n)
			continue
		}
		return n, nil
	}
}

// exifOrientation reads tag 0x0112 from IFD0 of a TIFF/EXIF block. It
// returns 0 if there is none or the block is malformed.
func exifOrientation(tiff []byte) int {
	if len(tiff) < 8 {
		return 0
	}
	var bo binary.ByteOrder
	switch string(tiff[:2]) {
	case "II":
		bo = binary.LittleEndian
	case "MM":
		bo = binary.BigEndian
	default:
		return 0
	}
	off := int(bo.Uint32(tiff[4:8]))
	if off < 8 || off+2 > len(tiff) {
		return 0
	}
	count := int(bo.Uint16(tiff[off:]))
	for i := 0; i < count; i++ {
		e := off + 2 + i*12
		if e+12 > len(tiff) {
			return 0
		}
		if bo.Uint16(tiff[e:]) == 0x0112 && bo.Uint16(tiff[e+2:]) == 3 {
			if v := int(bo.Uint16(tiff[e+8:])); v >= 1 && v <= 8 {
				return v
			}
			return 0
		}
	}
	return 0
}

// minimalExif is an EXIF block holding only the orientation tag.
func minimalExif(orientation int) []byte {
	b := []byte("Exif\x00\x00" +
		"MM\x00\x2a\x00\x00\x00\x08" + // big-endian TIFF header, IFD0 at offset 8
		"\x00\x01" + // one entry
		"\x01\x12\x00\x03\x00\x00\x00\x01\x00\x00\x00\x00" + // Orientation, SHORT, count 1
		"\x00\x00\x00\x00") // no next IFD
	b[6+8+2+8+1] = byte(orientation)
	return b
}

// ---- PNG ----

// pngDropChunks hold text, EXIF and timestamps. Everything else is image
// data or rendering information and is kept.
var pngDropChunks = map[string]bool{"tEXt": true, "zTXt": true, "iTXt": true, "eXIf": true, "tIME": true}

// stripPNG copies a PNG without its text, EXIF and time chunks, and drops
// anything after IEND.
func stripPNG(r *bufio.Reader, w io.Writer) error {
	sig := make([]byte, 8)
	if _, err := io.ReadFull(r, sig); err != nil || string(sig) != "\x89PNG\r\n\x1a\n" {
		return errors.New("not a PNG")
	}
	w.Write(sig)
	for {
		var hdr [8]byte
		if _, err := io.ReadFull(r, hdr[:]); err != nil {
			return errors.New("truncated PNG")
		}
		n := binary.BigEndian.Uint32(hdr[:4])
		if n > 1<<31-1 {
			return errors.New("corrupt PNG: bad chunk length")
		}
		typ := string(hdr[4:8])
		rest := int64(n) + 4 // data + CRC
		if pngDropChunks[typ] {
			if _, err := io.CopyN(io.Discard, r, rest); err != nil {
				return errors.New("truncated PNG")
			}
			continue
		}
		w.Write(hdr[:])
		if _, err := io.CopyN(w, r, rest); err != nil {
			return errors.New("truncated PNG")
		}
		if typ == "IEND" {
			return nil
		}
	}
}

// ---- Office Open XML and OpenDocument ----

const emptyCoreXML = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" xmlns:dcmitype="http://purl.org/dc/dcmitype/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"></cp:coreProperties>`

const emptyAppXML = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties" xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes"></Properties>`

const emptyCustomXML = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/custom-properties" xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes"></Properties>`

var odfVersion = regexp.MustCompile(`office:version="([0-9.]+)"`)

func emptyODFMeta(orig []byte) string {
	v := "1.2"
	if m := odfVersion.FindSubmatch(orig); m != nil {
		v = string(m[1])
	}
	return `<?xml version="1.0" encoding="UTF-8"?>
<office:document-meta xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" office:version="` + v + `"><office:meta/></office:document-meta>`
}

// dosDate1980 is 1980-01-01, the earliest MS-DOS date, used for every zip
// entry so the copy doesn't reveal when the document's parts were written.
const dosDate1980 = 1<<5 | 1

// stripZip rewrites an Office/ODF zip with empty document properties
// (OOXML docProps/core.xml, app.xml, custom.xml; ODF meta.xml) and with
// entry timestamps, extra fields and comments cleared. Other entries are
// copied byte for byte, in order, without recompressing.
func stripZip(in *os.File, out io.Writer, kind fileKind) error {
	fi, err := in.Stat()
	if err != nil {
		return err
	}
	zr, err := zip.NewReader(in, fi.Size())
	if err != nil {
		return fmt.Errorf("not a valid zip: %w", err)
	}
	marker := "[Content_Types].xml"
	if kind == kindODF {
		marker = "mimetype"
	}
	found := false
	for _, f := range zr.File {
		if f.Name == marker {
			found = true
		}
	}
	if !found {
		return fmt.Errorf("no %s, so not an Office document", marker)
	}

	zw := zip.NewWriter(out)
	for _, f := range zr.File {
		repl, ok, err := zipReplacement(kind, f)
		if err != nil {
			return err
		}
		if ok {
			method := zip.Deflate
			if f.Method == zip.Store {
				method = zip.Store
			}
			w, err := zw.CreateHeader(&zip.FileHeader{Name: f.Name, Method: method, ModifiedDate: dosDate1980})
			if err != nil {
				return err
			}
			if _, err := io.WriteString(w, repl); err != nil {
				return err
			}
			continue
		}
		fh := f.FileHeader
		fh.Modified = time.Time{}
		fh.ModifiedTime, fh.ModifiedDate = 0, dosDate1980
		fh.Extra = nil // extended timestamps, NTFS times, Unix owner IDs
		fh.Comment = ""
		w, err := zw.CreateRaw(&fh)
		if err != nil {
			return err
		}
		rc, err := f.OpenRaw()
		if err != nil {
			return err
		}
		if _, err := io.Copy(w, rc); err != nil {
			return err
		}
	}
	return zw.Close()
}

// zipReplacement returns the stand-in content for a metadata entry.
func zipReplacement(kind fileKind, f *zip.File) (string, bool, error) {
	if kind == kindOOXML {
		switch f.Name {
		case "docProps/core.xml":
			return emptyCoreXML, true, nil
		case "docProps/app.xml":
			return emptyAppXML, true, nil
		case "docProps/custom.xml":
			return emptyCustomXML, true, nil
		}
		return "", false, nil
	}
	if f.Name != "meta.xml" {
		return "", false, nil
	}
	rc, err := f.Open()
	if err != nil {
		return "", false, err
	}
	defer rc.Close()
	orig, err := io.ReadAll(io.LimitReader(rc, 1<<20))
	if err != nil {
		return "", false, err
	}
	return emptyODFMeta(orig), true, nil
}
