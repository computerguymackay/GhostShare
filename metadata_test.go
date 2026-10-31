package main

import (
	"archive/zip"
	"bytes"
	"compress/zlib"
	"crypto/sha256"
	"encoding/binary"
	"hash/crc32"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Fixtures are built in code: small real images and documents with
// metadata planted in every place the stripper is meant to clean.

func testImage() *image.RGBA {
	img := image.NewRGBA(image.Rect(0, 0, 16, 8))
	for y := 0; y < 8; y++ {
		for x := 0; x < 16; x++ {
			img.Set(x, y, color.RGBA{uint8(x * 16), uint8(y * 32), 128, 255})
		}
	}
	return img
}

func jpegSegment(m byte, data []byte) []byte {
	var b bytes.Buffer
	writeSegment(&b, m, data)
	return b.Bytes()
}

// exifBlock is an EXIF APP1 payload with an orientation and a GPS-like
// ImageDescription string.
func exifBlock(orientation int, secret string) []byte {
	desc := secret + "\x00"
	var t bytes.Buffer
	t.WriteString("MM\x00\x2a\x00\x00\x00\x08")
	binary.Write(&t, binary.BigEndian, uint16(2))
	binary.Write(&t, binary.BigEndian, []uint16{0x0112, 3})
	binary.Write(&t, binary.BigEndian, uint32(1))
	binary.Write(&t, binary.BigEndian, []uint16{uint16(orientation), 0})
	binary.Write(&t, binary.BigEndian, []uint16{0x010E, 2})
	binary.Write(&t, binary.BigEndian, uint32(len(desc)))
	binary.Write(&t, binary.BigEndian, uint32(8+2+2*12+4))
	binary.Write(&t, binary.BigEndian, uint32(0))
	t.WriteString(desc)
	return append([]byte("Exif\x00\x00"), t.Bytes()...)
}

var jpegSecrets = []string{"GPSSECRET", "XMPSECRET", "IPTCSECRET", "COMMENTSECRET", "THUMBSECRET", "TRAILERSECRET"}

func jpegFixture(t *testing.T, orientation int) []byte {
	t.Helper()
	var enc bytes.Buffer
	if err := jpeg.Encode(&enc, testImage(), &jpeg.Options{Quality: 90}); err != nil {
		t.Fatal(err)
	}
	b := enc.Bytes()
	var out bytes.Buffer
	out.Write(b[:2]) // SOI
	out.Write(jpegSegment(0xE0, []byte("JFIF\x00\x01\x02\x00\x00\x01\x00\x01\x00\x00")))
	out.Write(jpegSegment(0xE0, []byte("JFXX\x00\x10THUMBSECRET")))
	out.Write(jpegSegment(0xE1, exifBlock(orientation, "GPSSECRET 51.5007 N, 0.1246 W")))
	out.Write(jpegSegment(0xE1, []byte("http://ns.adobe.com/xap/1.0/\x00<x:xmpmeta><dc:creator>XMPSECRET</dc:creator></x:xmpmeta>")))
	out.Write(jpegSegment(0xE2, []byte("ICC_PROFILE\x00\x01\x01fake-icc-profile")))
	out.Write(jpegSegment(0xED, []byte("Photoshop 3.0\x008BIM\x04\x04\x00\x00\x00\x00\x00\x0aIPTCSECRET")))
	out.Write(jpegSegment(0xFE, []byte("COMMENTSECRET")))
	out.Write(b[2:])
	out.WriteString("TRAILERSECRET")
	return out.Bytes()
}

func pngChunk(typ string, data []byte) []byte {
	var b bytes.Buffer
	binary.Write(&b, binary.BigEndian, uint32(len(data)))
	b.WriteString(typ)
	b.Write(data)
	crc := crc32.NewIEEE()
	crc.Write([]byte(typ))
	crc.Write(data)
	binary.Write(&b, binary.BigEndian, crc.Sum32())
	return b.Bytes()
}

func pngFixture(t *testing.T) []byte {
	t.Helper()
	var enc bytes.Buffer
	if err := png.Encode(&enc, testImage()); err != nil {
		t.Fatal(err)
	}
	b := enc.Bytes()
	const afterIHDR = 8 + 4 + 4 + 13 + 4
	var z bytes.Buffer
	zw := zlib.NewWriter(&z)
	io.WriteString(zw, "ZTXTSECRET")
	zw.Close()
	var out bytes.Buffer
	out.Write(b[:afterIHDR])
	out.Write(pngChunk("tEXt", []byte("Author\x00TEXTSECRET")))
	out.Write(pngChunk("zTXt", append([]byte("Comment\x00\x00"), z.Bytes()...)))
	out.Write(pngChunk("iTXt", []byte("XML:com.adobe.xmp\x00\x00\x00\x00\x00ITXTSECRET")))
	out.Write(pngChunk("eXIf", []byte("MM\x00\x2a\x00\x00\x00\x08EXIFSECRET")))
	out.Write(pngChunk("tIME", []byte{0x07, 0xE5, 6, 1, 12, 0, 0}))
	out.Write(b[afterIHDR:])
	out.WriteString("TRAILERSECRET")
	return out.Bytes()
}

// zipEntry is one file in a fixture zip.
type zipEntry struct {
	name, body string
	store      bool
}

func zipFixture(t *testing.T, entries []zipEntry) []byte {
	t.Helper()
	var b bytes.Buffer
	zw := zip.NewWriter(&b)
	when := time.Date(2021, 6, 1, 9, 30, 0, 0, time.UTC)
	for _, e := range entries {
		m := zip.Deflate
		if e.store {
			m = zip.Store
		}
		w, err := zw.CreateHeader(&zip.FileHeader{Name: e.name, Method: m, Modified: when, Comment: "ZIPCOMMENTSECRET"})
		if err != nil {
			t.Fatal(err)
		}
		io.WriteString(w, e.body)
	}
	zw.SetComment("ARCHIVECOMMENTSECRET")
	zw.Close()
	return b.Bytes()
}

const docxBody = `<w:document><w:body><w:p><w:r><w:t>Hello from the body</w:t></w:r></w:p></w:body></w:document>`

func docxFixture(t *testing.T) []byte {
	return zipFixture(t, []zipEntry{
		{name: "[Content_Types].xml", body: `<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>`},
		{name: "_rels/.rels", body: `<Relationships/>`},
		{name: "word/document.xml", body: docxBody},
		{name: "docProps/core.xml", body: `<cp:coreProperties><dc:creator>AUTHORSECRET</dc:creator><cp:lastModifiedBy>EDITORSECRET</cp:lastModifiedBy><dcterms:created>2021-06-01T09:30:00Z</dcterms:created></cp:coreProperties>`},
		{name: "docProps/app.xml", body: `<Properties><Company>COMPANYSECRET</Company><Manager>MANAGERSECRET</Manager></Properties>`},
		{name: "docProps/custom.xml", body: `<Properties><property name="Client"><vt:lpwstr>CUSTOMSECRET</vt:lpwstr></property></Properties>`},
	})
}

var docxSecrets = []string{"AUTHORSECRET", "EDITORSECRET", "2021-06-01", "COMPANYSECRET", "MANAGERSECRET", "CUSTOMSECRET", "ZIPCOMMENTSECRET", "ARCHIVECOMMENTSECRET"}

func odtFixture(t *testing.T) []byte {
	return zipFixture(t, []zipEntry{
		{name: "mimetype", body: "application/vnd.oasis.opendocument.text", store: true},
		{name: "META-INF/manifest.xml", body: `<manifest:manifest/>`},
		{name: "content.xml", body: `<office:document-content><office:text>Hello ODF body</office:text></office:document-content>`},
		{name: "meta.xml", body: `<office:document-meta office:version="1.3"><office:meta><meta:initial-creator>ODFAUTHORSECRET</meta:initial-creator><dc:creator>ODFEDITORSECRET</dc:creator></office:meta></office:document-meta>`},
	})
}

// strip writes data to a file named name, strips it, and checks that the
// original was not touched.
func strip(t *testing.T, name string, data []byte) (stripResult, []byte, string) {
	t.Helper()
	dir := t.TempDir()
	src := filepath.Join(dir, name)
	if err := os.WriteFile(src, data, 0o644); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(dir, "stripped")
	before := sha256.Sum256(data)
	res := stripMetadata(src, dst)
	after, _ := os.ReadFile(src)
	if sha256.Sum256(after) != before {
		t.Fatal("the original file was modified")
	}
	if _, err := os.Stat(dst + ".tmp"); err == nil {
		t.Fatal("temp file left behind")
	}
	out, err := os.ReadFile(dst)
	if res.Copied && err != nil {
		t.Fatalf("result says copied, but %v", err)
	}
	if !res.Copied && err == nil {
		t.Fatal("a copy was written although the result says to share as-is")
	}
	return res, out, dst
}

func assertNoSecrets(t *testing.T, out []byte, secrets []string) {
	t.Helper()
	for _, s := range secrets {
		if bytes.Contains(out, []byte(s)) {
			t.Errorf("stripped copy still contains %q", s)
		}
	}
}

func TestStripJPEG(t *testing.T) {
	data := jpegFixture(t, 6)
	for _, s := range jpegSecrets { // the fixture really has them
		if !bytes.Contains(data, []byte(s)) {
			t.Fatalf("fixture lacks %q", s)
		}
	}
	res, out, _ := strip(t, "photo.jpg", data)
	if !res.Copied || !res.Stripped || res.Warning != "" {
		t.Fatalf("result %+v, want a clean stripped copy", res)
	}
	assertNoSecrets(t, out, jpegSecrets)
	img, err := jpeg.Decode(bytes.NewReader(out))
	if err != nil {
		t.Fatalf("stripped JPEG doesn't decode: %v", err)
	}
	if img.Bounds() != testImage().Bounds() {
		t.Fatalf("bounds %v", img.Bounds())
	}
	orig, _ := jpeg.Decode(bytes.NewReader(data))
	if !sameImage(orig, img) {
		t.Fatal("stripped JPEG decodes to different pixels")
	}
	if !bytes.Contains(out, []byte("ICC_PROFILE")) || !bytes.Contains(out, []byte("JFIF")) {
		t.Error("the ICC profile and JFIF header should be kept")
	}
	// The orientation survives in a minimal EXIF block, so the photo isn't shown rotated.
	i := bytes.Index(out, []byte("Exif\x00\x00"))
	if i < 0 || exifOrientation(out[i+6:]) != 6 {
		t.Fatal("orientation 6 was not kept")
	}
}

func TestStripJPEGWithoutOrientationHasNoExif(t *testing.T) {
	_, out, _ := strip(t, "photo.jpeg", jpegFixture(t, 1))
	if bytes.Contains(out, []byte("Exif")) {
		t.Fatal("an EXIF block was written for the default orientation")
	}
	if _, err := jpeg.Decode(bytes.NewReader(out)); err != nil {
		t.Fatal(err)
	}
}

func TestStripPNG(t *testing.T) {
	data := pngFixture(t)
	res, out, _ := strip(t, "screenshot.png", data)
	if !res.Copied || !res.Stripped || res.Warning != "" {
		t.Fatalf("result %+v", res)
	}
	assertNoSecrets(t, out, []string{"TEXTSECRET", "ITXTSECRET", "EXIFSECRET", "TRAILERSECRET"})
	for _, typ := range []string{"tEXt", "zTXt", "iTXt", "eXIf", "tIME"} {
		if bytes.Contains(out, []byte(typ)) {
			t.Errorf("%s chunk still present", typ)
		}
	}
	img, err := png.Decode(bytes.NewReader(out))
	if err != nil {
		t.Fatalf("stripped PNG doesn't decode: %v", err)
	}
	if !sameImage(testImage(), img) {
		t.Fatal("stripped PNG decodes to different pixels")
	}
}

func TestStripDOCX(t *testing.T) {
	data := docxFixture(t)
	res, out, _ := strip(t, "report.docx", data)
	if !res.Copied || !res.Stripped || res.Warning != "" {
		t.Fatalf("result %+v", res)
	}
	assertNoSecrets(t, out, docxSecrets)
	zr, err := zip.NewReader(bytes.NewReader(out), int64(len(out)))
	if err != nil {
		t.Fatalf("stripped DOCX is not a valid zip: %v", err)
	}
	var names []string
	for _, f := range zr.File {
		names = append(names, f.Name)
		if f.Modified.Year() > 1980 || len(f.Extra) != 0 {
			t.Errorf("%s: modified %v, %d extra bytes; want 1980 and none", f.Name, f.Modified, len(f.Extra))
		}
		body := readZipEntry(t, f)
		if f.Name == "word/document.xml" && body != docxBody {
			t.Errorf("document body changed: %q", body)
		}
		if strings.HasPrefix(f.Name, "docProps/") && strings.Contains(body, "SECRET") {
			t.Errorf("%s still has metadata: %q", f.Name, body)
		}
	}
	if strings.Join(names, ",") != "[Content_Types].xml,_rels/.rels,word/document.xml,docProps/core.xml,docProps/app.xml,docProps/custom.xml" {
		t.Errorf("entries changed: %v", names)
	}
}

func TestStripODT(t *testing.T) {
	res, out, _ := strip(t, "notes.odt", odtFixture(t))
	if !res.Copied || !res.Stripped {
		t.Fatalf("result %+v", res)
	}
	assertNoSecrets(t, out, []string{"ODFAUTHORSECRET", "ODFEDITORSECRET", "ZIPCOMMENTSECRET"})
	zr, err := zip.NewReader(bytes.NewReader(out), int64(len(out)))
	if err != nil {
		t.Fatal(err)
	}
	first := zr.File[0]
	if first.Name != "mimetype" || first.Method != zip.Store || len(first.Extra) != 0 {
		t.Fatalf("ODF needs mimetype first, stored, with no extra field; got %s method %d extra %d", first.Name, first.Method, len(first.Extra))
	}
	for _, f := range zr.File {
		if f.Name == "meta.xml" && !strings.Contains(readZipEntry(t, f), `office:version="1.3"`) {
			t.Error("meta.xml lost its office:version")
		}
		if f.Name == "content.xml" && !strings.Contains(readZipEntry(t, f), "Hello ODF body") {
			t.Error("content changed")
		}
	}
}

func TestPlainTextNeedsNoCopy(t *testing.T) {
	res, _, _ := strip(t, "notes.txt", []byte("just some notes\n"))
	if res.Copied || !res.Stripped || res.Warning != "" {
		t.Fatalf("result %+v, want stripped with no copy and no warning", res)
	}
}

func TestUnsupportedTypesShareAsIsWithWarning(t *testing.T) {
	for _, tc := range []struct {
		name, data, want string
	}{
		{"clip.mp4", "\x00\x00\x00\x18ftypmp42\x00\x00\x00\x00mp42isom", "can't remove metadata from .mp4 files; sharing as-is"},
		{"paper.pdf", "%PDF-1.7\n1 0 obj << /Author (PDFSECRET) >> endobj\n", "can't remove metadata from .pdf files; sharing as-is"},
		{"page.html", "<!DOCTYPE html><html><head><meta name=author content=x></head></html>", "can't remove metadata from .html files"},
		{"archive.zip", "PK\x03\x04plainzip", "can't remove metadata from .zip files"},
		{"noext", "\x00\x01\x02\x03binary", "can't remove metadata from files of this type"},
	} {
		res, _, _ := strip(t, tc.name, []byte(tc.data))
		if res.Copied || res.Stripped || !strings.Contains(res.Warning, tc.want) || strings.Contains(res.Warning, "\n") {
			t.Errorf("%s: %+v, want a one-line warning containing %q", tc.name, res, tc.want)
		}
	}
}

func TestEncryptedFilesWarnToStripFirst(t *testing.T) {
	for name, data := range map[string]string{
		"secret.age":  "age-encryption.org/v1\n-> X25519 abc\n",
		"armored.txt": "-----BEGIN AGE ENCRYPTED FILE-----\nYWdl\n-----END AGE ENCRYPTED FILE-----\n",
		"message.gpg": "\x85\x01\x0c\x03binary-pgp",
	} {
		res, _, _ := strip(t, name, []byte(data))
		if res.Copied || res.Stripped || !strings.Contains(res.Warning, "strip metadata before encrypting") {
			t.Errorf("%s: %+v", name, res)
		}
	}
}

func TestStripFailureSharesAsIsWithWarning(t *testing.T) {
	for name, data := range map[string][]byte{
		"broken.jpg":  {0xFF, 0xD8, 0xFF, 0xE1, 0x7F, 0xFF, 'E', 'x'}, // segment runs past EOF
		"broken.png":  []byte("\x89PNG\r\n\x1a\n\x00\x00\x00\x0dIHD"),
		"broken.docx": []byte("PK\x03\x04this is not really a zip"),
		"plain.docx":  zipFixture(t, []zipEntry{{name: "readme.txt", body: "no content types"}}),
	} {
		res, _, _ := strip(t, name, data)
		if res.Copied || res.Stripped || !strings.Contains(res.Warning, "couldn't remove metadata from "+name) || !strings.Contains(res.Warning, "sharing as-is") {
			t.Errorf("%s: %+v", name, res)
		}
	}
}

func readZipEntry(t *testing.T, f *zip.File) string {
	t.Helper()
	rc, err := f.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	b, err := io.ReadAll(rc)
	if err != nil {
		t.Fatalf("%s: %v", f.Name, err)
	}
	return string(b)
}

func sameImage(a, b image.Image) bool {
	if a.Bounds() != b.Bounds() {
		return false
	}
	for y := a.Bounds().Min.Y; y < a.Bounds().Max.Y; y++ {
		for x := a.Bounds().Min.X; x < a.Bounds().Max.X; x++ {
			r1, g1, b1, a1 := a.At(x, y).RGBA()
			r2, g2, b2, a2 := b.At(x, y).RGBA()
			if r1 != r2 || g1 != g2 || b1 != b2 || a1 != a2 {
				return false
			}
		}
	}
	return true
}

// Garbage behind a valid signature must never crash the daemon: stripping
// either succeeds or warns.
func TestStripNeverPanicsOnGarbage(t *testing.T) {
	seeds := map[string][]byte{
		"x.jpg":  jpegFixture(t, 3),
		"x.png":  pngFixture(t),
		"x.docx": docxFixture(t),
		"x.odt":  odtFixture(t),
	}
	rng := uint32(1)
	next := func() uint32 { rng = rng*1664525 + 1013904223; return rng }
	for name, seed := range seeds {
		for i := 0; i < 200; i++ {
			data := append([]byte(nil), seed...)
			switch i % 3 {
			case 0: // truncate
				data = data[:8+int(next())%(len(data)-8)]
			case 1: // flip bytes after the signature
				for j := 0; j < 8; j++ {
					p := 8 + int(next())%(len(data)-8)
					data[p] = byte(next())
				}
			case 2: // random tail
				for j := 8; j < len(data); j++ {
					data[j] = byte(next())
				}
			}
			res, _, _ := strip(t, name, data)
			if !res.Copied && res.Warning == "" {
				t.Fatalf("%s variant %d: not copied but no warning", name, i)
			}
		}
	}
}
