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

// These tests check GhostShare's use of metakill (options, copies,
// messages, 7z/RAR repacking), not metakill itself. Most fixtures are
// built in code with metadata planted where it is easy to find; the files
// in testdata come from metakill (see testdata/README.md).

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
	b := []byte{0xFF, m, 0, 0}
	binary.BigEndian.PutUint16(b[2:], uint16(len(data)+2))
	return append(b, data...)
}

// exifBlock is an EXIF APP1 payload with an orientation and an
// ImageDescription holding secret.
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

const docxBody = `<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>Hello from the body</w:t></w:r></w:p></w:body></w:document>`

func docxFixture(t *testing.T) []byte {
	return zipFixture(t, []zipEntry{
		{name: "[Content_Types].xml", body: `<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="xml" ContentType="application/xml"/><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/><Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/><Override PartName="/docProps/app.xml" ContentType="application/vnd.openxmlformats-officedocument.extended-properties+xml"/></Types>`},
		{name: "_rels/.rels", body: `<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/><Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/extended-properties" Target="docProps/app.xml"/></Relationships>`},
		{name: "word/document.xml", body: docxBody},
		{name: "docProps/core.xml", body: `<?xml version="1.0" encoding="UTF-8"?><cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><dc:creator>AUTHORSECRET</dc:creator><cp:lastModifiedBy>EDITORSECRET</cp:lastModifiedBy><dcterms:created xsi:type="dcterms:W3CDTF">2021-06-01T09:30:00Z</dcterms:created></cp:coreProperties>`},
		{name: "docProps/app.xml", body: `<?xml version="1.0" encoding="UTF-8"?><Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties"><Company>COMPANYSECRET</Company><Manager>MANAGERSECRET</Manager></Properties>`},
	})
}

var docxSecrets = []string{"AUTHORSECRET", "EDITORSECRET", "2021-06-01", "COMPANYSECRET", "MANAGERSECRET", "ZIPCOMMENTSECRET", "ARCHIVECOMMENTSECRET"}

// strip copies data to a file named name, strips it, and checks that the
// original was not touched and that nothing was left in the work dir.
func strip(t *testing.T, name string, data []byte) (stripResult, []byte) {
	t.Helper()
	dir := t.TempDir()
	src := filepath.Join(dir, name)
	if err := os.WriteFile(src, data, 0o644); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(dir, "stripped")
	work := filepath.Join(dir, "work")
	before := sha256.Sum256(data)
	res := stripMetadata(src, dst, work)
	if after, _ := os.ReadFile(src); sha256.Sum256(after) != before {
		t.Fatal("the original file was modified")
	}
	if left, _ := os.ReadDir(work); len(left) != 0 {
		t.Fatalf("files left in the work dir: %v", left)
	}
	out, err := os.ReadFile(dst)
	if res.Copied && err != nil {
		t.Fatalf("result says copied, but %v", err)
	}
	if !res.Copied && err == nil {
		t.Fatal("a copy was written although the result says to share as-is")
	}
	if strings.Contains(res.Warning, "\n") {
		t.Fatalf("warning is not one line: %q", res.Warning)
	}
	return res, out
}

func stripTestdata(t *testing.T, name string) (stripResult, []byte, []byte) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	res, out := strip(t, name, data)
	return res, out, data
}

func assertNoSecrets(t *testing.T, out []byte, secrets []string) {
	t.Helper()
	for _, s := range secrets {
		if bytes.Contains(out, []byte(s)) {
			t.Errorf("stripped copy still contains %q", s)
		}
	}
}

func assertHas(t *testing.T, data []byte, wants ...string) {
	t.Helper()
	for _, s := range wants {
		if !bytes.Contains(data, []byte(s)) {
			t.Errorf("missing %q", s)
		}
	}
}

func assertClean(t *testing.T, res stripResult) {
	t.Helper()
	if !res.Copied || !res.Stripped || res.Warning != "" {
		t.Fatalf("result %+v, want a clean copy with no warning", res)
	}
}

func TestStripJPEG(t *testing.T) {
	data := jpegFixture(t, 6)
	assertHas(t, data, jpegSecrets...) // the fixture really has them
	res, out := strip(t, "photo.jpg", data)
	assertClean(t, res)
	assertNoSecrets(t, out, jpegSecrets)
	img, err := jpeg.Decode(bytes.NewReader(out))
	if err != nil {
		t.Fatalf("stripped JPEG doesn't decode: %v", err)
	}
	orig, _ := jpeg.Decode(bytes.NewReader(data))
	if !sameImage(orig, img) {
		t.Fatal("stripped JPEG decodes to different pixels")
	}
	// The orientation survives, so the photo isn't shown rotated.
	i := bytes.Index(out, []byte("Exif\x00\x00"))
	if i < 0 || exifOrientation(out[i+6:]) != 6 {
		t.Fatal("orientation 6 was not kept")
	}
}

// exifOrientation reads tag 0x0112 from a TIFF block (0 if absent).
func exifOrientation(tiff []byte) int {
	if len(tiff) < 8 {
		return 0
	}
	var bo binary.ByteOrder = binary.BigEndian
	if string(tiff[:2]) == "II" {
		bo = binary.LittleEndian
	}
	off := int(bo.Uint32(tiff[4:]))
	if off+2 > len(tiff) {
		return 0
	}
	n := int(bo.Uint16(tiff[off:]))
	for i := 0; i < n; i++ {
		e := off + 2 + 12*i
		if e+12 > len(tiff) {
			return 0
		}
		if bo.Uint16(tiff[e:]) == 0x0112 {
			return int(bo.Uint16(tiff[e+8:]))
		}
	}
	return 0
}

func TestStripPNG(t *testing.T) {
	res, out := strip(t, "screenshot.png", pngFixture(t))
	assertClean(t, res)
	assertNoSecrets(t, out, []string{"TEXTSECRET", "ITXTSECRET", "TRAILERSECRET", "tIME"})
	img, err := png.Decode(bytes.NewReader(out))
	if err != nil {
		t.Fatalf("stripped PNG doesn't decode: %v", err)
	}
	if !sameImage(testImage(), img) {
		t.Fatal("stripped PNG decodes to different pixels")
	}
}

func TestStripDOCX(t *testing.T) {
	res, out := strip(t, "report.docx", docxFixture(t))
	assertClean(t, res)
	assertNoSecrets(t, out, docxSecrets)
	zr, err := zip.NewReader(bytes.NewReader(out), int64(len(out)))
	if err != nil {
		t.Fatalf("stripped DOCX is not a valid zip: %v", err)
	}
	for _, f := range zr.File {
		if f.Modified.Year() > 1980 {
			t.Errorf("%s: modified %v, want 1980", f.Name, f.Modified)
		}
		body := readZipEntry(t, f)
		if f.Name == "word/document.xml" && !strings.Contains(body, "Hello from the body") {
			t.Errorf("document body changed: %q", body)
		}
		if strings.Contains(body, "SECRET") {
			t.Errorf("%s still has metadata: %q", f.Name, body)
		}
	}
}

// Audio keeps what a music player shows (title, artist, album, track,
// year) and loses the rest: comments, encoder, purchase IDs, cover art.
func TestStripMP3KeepsUsefulTags(t *testing.T) {
	res, out, data := stripTestdata(t, "song.mp3")
	assertClean(t, res)
	assertHas(t, data, "Jane Photographer", "secret comment", "SecretEncoder", "SN-0042-SECRET", "APIC")
	assertHas(t, out, "Test Song", "Test Artist", "Test Album", "2023")
	assertNoSecrets(t, out, []string{"Jane Photographer", "secret comment", "SecretEncoder", "SN-0042-SECRET", "APIC", "iPhone"})
}

func TestStripMP4KeepsUsefulTags(t *testing.T) {
	res, out, _ := stripTestdata(t, "clip.mp4")
	assertClean(t, res)
	assertHas(t, out, "Test Song", "Test Artist")
	assertNoSecrets(t, out, []string{"Jane Photographer", "iPhone 14 Pro", "SecretEncoder", "SN-0042-SECRET", "secret comment"})
}

func TestStripPDF(t *testing.T) {
	res, out, _ := stripTestdata(t, "report.pdf")
	assertClean(t, res)
	assertNoSecrets(t, out, []string{"Jane Photographer", "Old Author Name", "iOS 16.4", "SecretEncoder", "D:2023"})
}

// 7z and RAR are repacked as zip, then cleaned: member times reset, OS
// clutter dropped, the photo inside cleaned, executable bits kept.
func TestStripRepacksArchivesAsZip(t *testing.T) {
	for _, name := range []string{"bundle.7z", "bundle.rar"} {
		t.Run(name, func(t *testing.T) {
			res, out, _ := stripTestdata(t, name)
			if !res.Copied || !res.Stripped {
				t.Fatalf("result %+v", res)
			}
			// The fixture has Users/jane/notes.txt; entry names are kept,
			// but the sender is told.
			if !strings.Contains(res.Warning, "home-directory") || !strings.Contains(res.Warning, "Users/jane") {
				t.Errorf("warning %q doesn't point out the home-folder path", res.Warning)
			}
			if res.Filename != "bundle.zip" {
				t.Fatalf("served name %q, want bundle.zip", res.Filename)
			}
			zr, err := zip.NewReader(bytes.NewReader(out), int64(len(out)))
			if err != nil {
				t.Fatalf("not a zip: %v", err)
			}
			got := map[string]*zip.File{}
			for _, f := range zr.File {
				got[f.Name] = f
				if f.Modified.Year() > 1980 {
					t.Errorf("%s: modified %v", f.Name, f.Modified)
				}
			}
			for _, want := range []string{"docs/readme.txt", "docs/photo.jpg", "docs/run.sh"} {
				if got[want] == nil {
					t.Errorf("%s missing; have %v", want, keys(got))
				}
			}
			if got["docs/.DS_Store"] != nil {
				t.Error(".DS_Store was kept")
			}
			if f := got["docs/run.sh"]; f != nil && f.Mode()&0o111 == 0 {
				t.Errorf("run.sh lost its executable bit: %v", f.Mode())
			}
			if f := got["docs/photo.jpg"]; f != nil {
				photo := []byte(readZipEntry(t, f))
				assertNoSecrets(t, photo, []string{"iPhone", "Jane Photographer", "SN-0042-SECRET"})
				if _, err := jpeg.Decode(bytes.NewReader(photo)); err != nil {
					t.Errorf("photo inside doesn't decode: %v", err)
				}
			}
		})
	}
}

func keys(m map[string]*zip.File) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestEncryptedArchiveSharesAsIs(t *testing.T) {
	res, _, _ := stripTestdata(t, "locked.7z")
	if res.Copied || res.Stripped || res.Filename != "" || !strings.Contains(res.Warning, "encrypted") || !strings.Contains(res.Warning, "sharing as-is") {
		t.Fatalf("%+v", res)
	}
}

func TestRepackRefusesLinksAndUnsafeNames(t *testing.T) {
	z := newZipRepacker(io.Discard)
	if err := z.add(archiveEntry{name: "link", isLink: true}); err == nil {
		t.Error("a link was accepted")
	}
	for _, n := range []string{"/etc/passwd", "../up", "a/../../up", `C:\x`, `..\up`, ""} {
		if _, err := safeEntryName(n); err == nil {
			t.Errorf("%q accepted", n)
		}
	}
	if n, err := safeEntryName(`dir\file.txt`); err != nil || n != "dir/file.txt" {
		t.Errorf("dir\\file.txt → %q, %v", n, err)
	}
	if got := zipName("holiday.photos.7z"); got != "holiday.photos.zip" {
		t.Errorf("zipName = %q", got)
	}
}

func TestPlainTextNeedsNoCopy(t *testing.T) {
	res, _ := strip(t, "notes.txt", []byte("just some notes\n"))
	if res.Copied || !res.Stripped || res.Warning != "" {
		t.Fatalf("result %+v, want stripped with no copy and no warning", res)
	}
}

func TestAlreadyCleanFileNeedsNoCopy(t *testing.T) {
	_, clean := strip(t, "photo.jpg", jpegFixture(t, 1))
	res, _ := strip(t, "photo.jpg", clean)
	if res.Copied || !res.Stripped || res.Warning != "" {
		t.Fatalf("result %+v, want the already-clean original served", res)
	}
}

func TestUnknownTypesShareAsIsWithWarning(t *testing.T) {
	for _, tc := range []struct{ name, data, want string }{
		{"blob.bin", "\x00\x01\x02\x03binary", "can't remove metadata from .bin files; sharing as-is"},
		{"noext", "\x00\x01\x02\x03binary", "can't remove metadata from files of this type; sharing as-is"},
	} {
		res, _ := strip(t, tc.name, []byte(tc.data))
		if res.Copied || res.Stripped || res.Warning != tc.want {
			t.Errorf("%s: %+v, want warning %q", tc.name, res, tc.want)
		}
	}
}

func TestEncryptedFilesWarnToStripFirst(t *testing.T) {
	for name, data := range map[string]string{
		"secret.age":  "age-encryption.org/v1\n-> X25519 abc\n",
		"armored.txt": "-----BEGIN AGE ENCRYPTED FILE-----\nYWdl\n-----END AGE ENCRYPTED FILE-----\n",
		"message.gpg": "\x85\x01\x0c\x03binary-pgp",
	} {
		res, _ := strip(t, name, []byte(data))
		if res.Copied || res.Stripped || !strings.Contains(res.Warning, "strip metadata before encrypting") {
			t.Errorf("%s: %+v", name, res)
		}
	}
}

func TestStripFailureSharesAsIsWithWarning(t *testing.T) {
	for name, data := range map[string][]byte{
		"broken.jpg": {0xFF, 0xD8, 0xFF, 0xE1, 0x7F, 0xFF, 'E', 'x'}, // segment runs past EOF
		"broken.png": []byte("\x89PNG\r\n\x1a\n\x00\x00\x00\x0dIHD"),
		"broken.7z":  append([]byte{'7', 'z', 0xBC, 0xAF, 0x27, 0x1C}, make([]byte, 40)...),
	} {
		res, _ := strip(t, name, data)
		if res.Copied || res.Stripped || !strings.Contains(res.Warning, name) || !strings.HasSuffix(res.Warning, "sharing as-is") {
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

// Garbage behind a valid signature must never crash the daemon or leave
// files behind: stripping succeeds, finds nothing to do, or warns.
func TestStripNeverPanicsOnGarbage(t *testing.T) {
	seeds := map[string][]byte{
		"x.jpg":  jpegFixture(t, 3),
		"x.png":  pngFixture(t),
		"x.docx": docxFixture(t),
	}
	for _, n := range []string{"bundle.7z", "bundle.rar", "song.mp3"} {
		b, _ := os.ReadFile(filepath.Join("testdata", n))
		seeds[n] = b
	}
	rng := uint32(1)
	next := func() uint32 { rng = rng*1664525 + 1013904223; return rng }
	for name, seed := range seeds {
		for i := 0; i < 60; i++ {
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
			res, _ := strip(t, name, data)
			if !res.Copied && !res.Stripped && res.Warning == "" {
				t.Fatalf("%s variant %d: shared as-is with no warning", name, i)
			}
		}
	}
}
