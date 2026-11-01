package imagedecode

// Tests for the RAW path. These are structural rather than vendor-specific on
// purpose: we have no Canon or Nikon files to test against, so the tests assert
// the PROPERTIES that make the feature work for any camera —
//
//   - the largest preview wins (never the 160×120 thumbnail);
//   - the preview comes back byte-identical, not re-encoded;
//   - a container we cannot parse still yields its JPEG via the scan;
//   - a plain TIFF is never mistaken for a RAW;
//   - and a hostile file cannot hang, panic or allocate wildly.
//
// That last group is not padding. This parser reads attacker-shaped input in
// the same process that holds the onion service, so a panic or an OOM here
// costs the user a multi-minute onion republish, not just a failed image.

import (
	"bytes"
	"encoding/binary"
	"image"
	"image/color"
	"image/jpeg"
	"testing"
	"time"
)

// makeJPEG returns a real, decodable JPEG of the given size, filled with a
// colour derived from the dimensions so two fixtures are never byte-identical.
func makeJPEG(t *testing.T, w, h int) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			img.SetRGBA(x, y, color.RGBA{uint8(w), uint8(h), uint8(x ^ y), 255})
		}
	}
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, img, &jpeg.Options{Quality: 80}); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// tiffBuilder assembles a little-endian TIFF with explicit control over tags
// and offsets, which is what makes it possible to reproduce the shapes real RAW
// files take (a thumbnail in IFD0, the real preview in a SubIFD, sensor data
// tagged as CFA).
type tiffBuilder struct {
	entries []tiffEntry
	blobs   []byte // appended after the IFD; offsets are fixed up on build
	magic   uint16
}

type tiffEntry struct {
	tag, typ  uint16
	count     uint32
	val       uint32
	blobIndex int // >0 means val is a placeholder for blob N's final offset
}

func (b *tiffBuilder) addBlob(data []byte) (ref int, size uint32) {
	b.blobs = append(b.blobs, data...)
	// ref encodes the blob's start within the blob area, offset by one so zero
	// stays available as "not a blob reference".
	return len(b.blobs) - len(data) + 1, uint32(len(data))
}

func (b *tiffBuilder) add(tag, typ uint16, count, val uint32) {
	b.entries = append(b.entries, tiffEntry{tag: tag, typ: typ, count: count, val: val})
}

func (b *tiffBuilder) addPointer(tag uint16, ref int) {
	b.entries = append(b.entries, tiffEntry{tag: tag, typ: 4, count: 1, blobIndex: ref})
}

func (b *tiffBuilder) build() []byte {
	magic := b.magic
	if magic == 0 {
		magic = 42
	}
	ifdSize := 2 + len(b.entries)*12 + 4
	blobBase := uint32(8 + ifdSize)
	out := make([]byte, 8+ifdSize)
	copy(out, "II")
	binary.LittleEndian.PutUint16(out[2:], magic)
	binary.LittleEndian.PutUint32(out[4:], 8)
	binary.LittleEndian.PutUint16(out[8:], uint16(len(b.entries)))
	for i, e := range b.entries {
		p := 10 + i*12
		binary.LittleEndian.PutUint16(out[p:], e.tag)
		binary.LittleEndian.PutUint16(out[p+2:], e.typ)
		binary.LittleEndian.PutUint32(out[p+4:], e.count)
		v := e.val
		if e.blobIndex > 0 {
			v = blobBase + uint32(e.blobIndex-1)
		}
		binary.LittleEndian.PutUint32(out[p+8:], v)
	}
	return append(out, b.blobs...)
}

func TestRawPreviewFromTaggedJPEG(t *testing.T) {
	jpg := makeJPEG(t, 800, 600)
	var b tiffBuilder
	ref, size := b.addBlob(jpg)
	b.add(tagPhotometric, 3, 1, photometricCFA) // marks it as sensor data → RAW
	b.addPointer(tagJPEGIFOffset, ref)
	b.add(tagJPEGIFByteCount, 4, 1, size)
	data := b.build()

	if f := Sniff(data); f != RawTIFF {
		t.Fatalf("sniffed %q, want raw-tiff — a CFA photometric means sensor data", f)
	}
	got, w, h, err := extractEmbeddedJPEG(data)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if w != 800 || h != 600 {
		t.Fatalf("preview dimensions %dx%d, want 800x600 (read from the JPEG's own SOF)", w, h)
	}
	if !bytes.Equal(got, jpg) {
		t.Fatalf("preview is not byte-identical: got %d bytes, want %d — it must not be re-encoded",
			len(got), len(jpg))
	}
}

func TestRawPrefersTheLargestPreviewNotTheThumbnail(t *testing.T) {
	// The shape nearly every real RAW takes: a small thumbnail is the one with
	// a tidy tag pointing at it, while the full-size preview sits somewhere the
	// tags do not describe (typically a MakerNote). Sending the thumbnail would
	// be the single most annoying way for this feature to "work".
	thumb := makeJPEG(t, 160, 120)
	full := makeJPEG(t, 3000, 2000)
	var b tiffBuilder
	tref, tsize := b.addBlob(thumb)
	b.addBlob(full) // present in the file, deliberately NOT tagged
	b.add(tagPhotometric, 3, 1, photometricCFA)
	b.addPointer(tagJPEGIFOffset, tref)
	b.add(tagJPEGIFByteCount, 4, 1, tsize)
	data := b.build()

	got, w, h, err := extractEmbeddedJPEG(data)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if w != 3000 || h != 2000 {
		t.Fatalf("picked the %dx%d preview, want the 3000x2000 one", w, h)
	}
	if !bytes.Equal(got, full) {
		t.Fatal("picked a different stream than the full-size preview")
	}
}

func TestRawPreviewInSubIFD(t *testing.T) {
	// DNG and NEF keep the real preview in a SubIFD, so the walk has to
	// recurse rather than only reading IFD0.
	jpg := makeJPEG(t, 1600, 1200)
	// Build the SubIFD by hand and park it in the blob area of the outer file.
	var sub tiffBuilder
	sref, ssize := sub.addBlob(jpg)
	sub.addPointer(tagJPEGIFOffset, sref)
	sub.add(tagJPEGIFByteCount, 4, 1, ssize)
	subBytes := sub.build()

	// The SubIFD's internal offsets are relative to ITS header, so it has to be
	// placed at a known absolute offset and its pointers rebased. Simpler and
	// just as faithful: concatenate, then point at the sub-IFD's directory.
	var outer tiffBuilder
	outer.add(tagPhotometric, 3, 1, photometricCFA)
	outer.add(tagSubIFDs, 4, 1, 0) // fixed up below
	head := outer.build()
	subOffset := uint32(len(head))
	// Inside subBytes the directory starts at byte 8, and its pointer values
	// are relative to the start of subBytes.
	fixed := append([]byte{}, subBytes...)
	// Rebase the JPEG pointer inside the SubIFD.
	n := binary.LittleEndian.Uint16(fixed[8:])
	for i := 0; i < int(n); i++ {
		p := 10 + i*12
		if binary.LittleEndian.Uint16(fixed[p:]) == tagJPEGIFOffset {
			old := binary.LittleEndian.Uint32(fixed[p+8:])
			binary.LittleEndian.PutUint32(fixed[p+8:], old+subOffset)
		}
	}
	data := append(head, fixed...)
	// Point the outer SubIFDs tag at the sub-directory (offset 8 within it).
	for i := 0; i < 2; i++ {
		p := 10 + i*12
		if binary.LittleEndian.Uint16(data[p:]) == tagSubIFDs {
			binary.LittleEndian.PutUint32(data[p+8:], subOffset+8)
		}
	}

	got, w, h, err := extractEmbeddedJPEG(data)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if w != 1600 || h != 1200 {
		t.Fatalf("SubIFD preview came back %dx%d, want 1600x1200", w, h)
	}
	if !bytes.Equal(got, jpg) {
		t.Fatal("SubIFD preview bytes differ from the original")
	}
}

func TestRawNonTIFFContainersViaScan(t *testing.T) {
	// RAF, X3F, CRW, MRW and CR3 have nothing resembling a TIFF IFD at the
	// front. One scan handles all of them, which is why there is no per-brand
	// parser in this package.
	for _, tc := range []struct {
		name   string
		header []byte
		want   Format
	}{
		{"Fujifilm RAF", []byte("FUJIFILMCCD-RAW 0201FF383501"), RawFuji},
		{"Sigma X3F", []byte("FOVb\x00\x00\x00\x00"), RawSigma},
		{"Minolta MRW", []byte("\x00MRM\x00\x00\x00\x00"), RawMRW},
	} {
		t.Run(tc.name, func(t *testing.T) {
			jpg := makeJPEG(t, 1024, 768)
			data := append(append([]byte{}, tc.header...), make([]byte, 512)...)
			data = append(data, jpg...)
			if f := Sniff(data); f != tc.want {
				t.Fatalf("sniffed %q, want %q", f, tc.want)
			}
			res, err := Decode(data, Options{})
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if !bytes.Equal(res.Data, jpg) {
				t.Fatalf("extracted %d bytes, want the %d-byte embedded JPEG", len(res.Data), len(jpg))
			}
			if res.Mime != "image/jpeg" {
				t.Fatalf("mime %q, want image/jpeg", res.Mime)
			}
			if res.Width != 1024 || res.Height != 768 {
				t.Fatalf("dimensions %dx%d, want 1024x768", res.Width, res.Height)
			}
		})
	}
}

func TestRawCR3IsRecognisedByBrand(t *testing.T) {
	// CR3 is an ISO base media file, sharing its container with HEIF and AVIF.
	// The brand is the only thing that separates them.
	jpg := makeJPEG(t, 2000, 1500)
	data := append([]byte("\x00\x00\x00\x18ftypcrx \x00\x00\x00\x01crx isom"), make([]byte, 64)...)
	data = append(data, jpg...)
	if f := Sniff(data); f != RawISO {
		t.Fatalf("sniffed %q, want raw-iso", f)
	}
	res, err := Decode(data, Options{})
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !bytes.Equal(res.Data, jpg) {
		t.Fatal("CR3 preview extraction returned different bytes")
	}
}

func TestPlainTIFFIsNotTakenForRaw(t *testing.T) {
	// The failure this guards against: classifying an ordinary TIFF as RAW
	// would send its embedded thumbnail in place of the actual image.
	jpg := makeJPEG(t, 64, 64)
	var b tiffBuilder
	ref, size := b.addBlob(jpg)
	b.add(tagPhotometric, 3, 1, 2) // RGB, not CFA
	b.add(tagCompression, 3, 1, 7) // JPEG-in-TIFF is a normal TIFF
	b.addPointer(tagJPEGIFOffset, ref)
	b.add(tagJPEGIFByteCount, 4, 1, size)
	if f := Sniff(b.build()); f != TIFF {
		t.Fatalf("sniffed %q, want tiff", f)
	}
}

func TestCR2MarkerIsEnoughOnItsOwn(t *testing.T) {
	// A CR2 declares itself in the header, before any tag is read.
	data := make([]byte, 64)
	copy(data, "II")
	binary.LittleEndian.PutUint16(data[2:], 42)
	binary.LittleEndian.PutUint32(data[4:], 16)
	copy(data[8:], "CR\x02\x00")
	if f := Sniff(data); f != RawTIFF {
		t.Fatalf("sniffed %q, want raw-tiff from the CR2 header marker", f)
	}
}

func TestNestedJPEGPrefersTheOuterImage(t *testing.T) {
	// A full-size preview carries its own EXIF thumbnail INSIDE it. A scan
	// that took the first or the smallest match would send the thumbnail.
	inner := makeJPEG(t, 120, 90)
	outer := makeJPEG(t, 2400, 1600)
	// Splice the inner JPEG into the outer one's trailing bytes, which models a
	// thumbnail stored in an APP segment well enough for the scanner.
	data := append(append([]byte{}, outer...), inner...)
	_, w, h, err := extractEmbeddedJPEG(data)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if w != 2400 || h != 1600 {
		t.Fatalf("chose the %dx%d stream, want 2400x1600", w, h)
	}
}

func TestValidateJPEGRejectsRubbish(t *testing.T) {
	good := makeJPEG(t, 32, 32)
	for _, tc := range []struct {
		name string
		data []byte
	}{
		{"truncated mid-stream", good[:len(good)/2]},
		{"SOI with no frame header", []byte{0xff, 0xd8, 0xff, 0xd9}},
		{"random bytes after SOI", append([]byte{0xff, 0xd8, 0xff}, bytes.Repeat([]byte{0x41}, 64)...)},
		{"length field past the end", []byte{0xff, 0xd8, 0xff, 0xc0, 0xff, 0xff, 0x08}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, ok := validateJPEGAt(tc.data, 0); ok {
				t.Fatal("accepted a stream that is not a complete JPEG")
			}
		})
	}
	if c, ok := validateJPEGAt(good, 0); !ok || c.size != len(good) || c.w != 32 {
		t.Fatalf("rejected or mismeasured a valid JPEG: ok=%v %+v", ok, c)
	}
}

func TestHostileTIFFCannotHangOrPanic(t *testing.T) {
	// Each of these is a one-line denial of service against a naive IFD walker.
	// The assertion is simply that we return, quickly, without panicking.
	cases := map[string][]byte{}

	// A directory whose "next IFD" pointer points at itself.
	loop := make([]byte, 64)
	copy(loop, "II")
	binary.LittleEndian.PutUint16(loop[2:], 42)
	binary.LittleEndian.PutUint32(loop[4:], 8)
	binary.LittleEndian.PutUint16(loop[8:], 1)
	binary.LittleEndian.PutUint32(loop[10+8:], 0)
	binary.LittleEndian.PutUint32(loop[22:], 8) // next = this directory
	cases["self-referential IFD chain"] = loop

	// A SubIFD pointing back at IFD0.
	selfSub := make([]byte, 64)
	copy(selfSub, "II")
	binary.LittleEndian.PutUint16(selfSub[2:], 42)
	binary.LittleEndian.PutUint32(selfSub[4:], 8)
	binary.LittleEndian.PutUint16(selfSub[8:], 1)
	binary.LittleEndian.PutUint16(selfSub[10:], tagSubIFDs)
	binary.LittleEndian.PutUint16(selfSub[12:], 4)
	binary.LittleEndian.PutUint32(selfSub[14:], 1)
	binary.LittleEndian.PutUint32(selfSub[18:], 8)
	cases["SubIFD pointing at itself"] = selfSub

	// An entry count of 65535 in a 32-byte file.
	huge := make([]byte, 32)
	copy(huge, "II")
	binary.LittleEndian.PutUint16(huge[2:], 42)
	binary.LittleEndian.PutUint32(huge[4:], 8)
	binary.LittleEndian.PutUint16(huge[8:], 0xffff)
	cases["entry count far beyond the file"] = huge

	// A value count of four billion, which a naive uints() would allocate for.
	bigCount := make([]byte, 64)
	copy(bigCount, "II")
	binary.LittleEndian.PutUint16(bigCount[2:], 42)
	binary.LittleEndian.PutUint32(bigCount[4:], 8)
	binary.LittleEndian.PutUint16(bigCount[8:], 1)
	binary.LittleEndian.PutUint16(bigCount[10:], tagSubIFDs)
	binary.LittleEndian.PutUint16(bigCount[12:], 4)
	binary.LittleEndian.PutUint32(bigCount[14:], 0xffffffff)
	binary.LittleEndian.PutUint32(bigCount[18:], 20)
	cases["value count of four billion"] = bigCount

	// Offsets pointing past the end of the file.
	oob := make([]byte, 64)
	copy(oob, "II")
	binary.LittleEndian.PutUint16(oob[2:], 42)
	binary.LittleEndian.PutUint32(oob[4:], 0xfffffff0)
	cases["IFD offset past the end"] = oob

	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			done := make(chan struct{})
			go func() {
				defer close(done)
				defer func() {
					if r := recover(); r != nil {
						t.Errorf("panicked on hostile input: %v", r)
					}
				}()
				_ = Sniff(data)
				_, _, _, _ = extractEmbeddedJPEG(data)
				_, _ = Decode(data, Options{})
			}()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("did not finish in 5s — the walk does not terminate on this input")
			}
		})
	}
}

func TestDecodeRejectsPixelBombBeforeAllocating(t *testing.T) {
	// A 30000×30000 image is 3.6 GB as RGBA. The guard has to fire from the
	// HEADER, before any buffer exists — in this process an OOM kill drops the
	// onion service, which costs the user minutes, not milliseconds.
	var buf bytes.Buffer
	buf.WriteString("farbfeld")
	buf.Write([]byte{0, 0, 0x75, 0x30, 0, 0, 0x75, 0x30}) // 30000 x 30000
	// Deliberately NO pixel data: a guard that fires correctly never reads it.
	_, err := Decode(buf.Bytes(), Options{})
	if err == nil {
		t.Fatal("a 900-megapixel image was accepted")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("too big")) {
		t.Fatalf("error %q does not explain that the image is too large", err)
	}
}

func TestDecodePassesBrowserNativeFormatsThrough(t *testing.T) {
	// The page only calls us after its own decode failed, so handing JPEG bytes
	// back untouched (rather than re-encoding) keeps quality and lets it retry.
	jpg := makeJPEG(t, 100, 80)
	res, err := Decode(jpg, Options{})
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !bytes.Equal(res.Data, jpg) {
		t.Fatal("a JPEG was re-encoded instead of passed through")
	}
	if res.Width != 100 || res.Height != 80 {
		t.Fatalf("dimensions %dx%d, want 100x80", res.Width, res.Height)
	}
}

func TestDecodeNamesFormatsItCannotRead(t *testing.T) {
	// "Molepipe can't read JPEG XL" sends someone to export a JPEG;
	// "couldn't read that image" sends them to file a bug.
	for _, tc := range []struct {
		name   string
		data   []byte
		expect string
	}{
		{"JPEG XL", []byte{0xff, 0x0a, 0x00, 0x00, 0x00, 0x00}, "JPEG XL"},
		{"JPEG 2000", append([]byte("\x00\x00\x00\x0cjP  "), make([]byte, 16)...), "JPEG 2000"},
		{"OpenEXR", append([]byte{0x76, 0x2f, 0x31, 0x01}, make([]byte, 16)...), "OpenEXR"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Decode(tc.data, Options{})
			if err == nil {
				t.Fatalf("%s decoded, but no decoder for it exists", tc.name)
			}
			if !bytes.Contains([]byte(err.Error()), []byte(tc.expect)) {
				t.Fatalf("error %q does not name %s", err, tc.expect)
			}
		})
	}
}

func TestDecodeConvertsAndBoundsOutput(t *testing.T) {
	// A large non-native format must come back inside MaxDim, re-encoded to a
	// wire-legal type.
	big := image.NewRGBA(image.Rect(0, 0, 5000, 2500))
	var buf bytes.Buffer
	buf.WriteString("farbfeld")
	buf.Write([]byte{0, 0, 0x13, 0x88, 0, 0, 0x09, 0xc4})
	row := make([]byte, 5000*8)
	for i := 0; i < 2500; i++ {
		buf.Write(row)
	}
	_ = big
	res, err := Decode(buf.Bytes(), Options{MaxDim: 1024})
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if res.Width > 1024 || res.Height > 1024 {
		t.Fatalf("output %dx%d exceeds the requested MaxDim of 1024", res.Width, res.Height)
	}
	switch res.Mime {
	case "image/jpeg", "image/png", "image/webp", "image/gif":
	default:
		t.Fatalf("output mime %q is not one of the four wire-legal types", res.Mime)
	}
}

func TestDecodeKeepsTransparencyAsPNG(t *testing.T) {
	// JPEG has no alpha channel, so a transparent source must come back as PNG
	// or the transparent areas turn black.
	var buf bytes.Buffer
	buf.WriteString("farbfeld")
	buf.Write([]byte{0, 0, 0, 2, 0, 0, 0, 1})
	buf.Write([]byte{0xff, 0xff, 0, 0, 0, 0, 0, 0}) // opaque red
	buf.Write([]byte{0, 0, 0, 0, 0, 0, 0, 0})       // fully transparent
	res, err := Decode(buf.Bytes(), Options{})
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if res.Mime != "image/png" {
		t.Fatalf("mime %q, want image/png for an image with transparency", res.Mime)
	}
}

func TestDecodeSendsOpaqueImagesAsJPEG(t *testing.T) {
	// The other half of the rule: a fully opaque RGBA source must not be sent
	// as PNG, which would multiply the size of every screenshot.
	var buf bytes.Buffer
	buf.WriteString("farbfeld")
	buf.Write([]byte{0, 0, 0, 2, 0, 0, 0, 1})
	buf.Write([]byte{0xff, 0xff, 0, 0, 0, 0, 0xff, 0xff})
	buf.Write([]byte{0, 0, 0xff, 0xff, 0, 0, 0xff, 0xff})
	res, err := Decode(buf.Bytes(), Options{})
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if res.Mime != "image/jpeg" {
		t.Fatalf("mime %q, want image/jpeg for a fully opaque image", res.Mime)
	}
}

// FuzzDecode exists because every decoder in this package parses hostile input
// in the process that holds the onion service. The property under test is the
// weakest useful one and the only one that matters: Decode must never panic.
func FuzzDecode(f *testing.F) {
	f.Add([]byte("P6\n2 2\n255\n"))
	f.Add([]byte("qoif\x00\x00\x00\x02\x00\x00\x00\x02\x04\x00"))
	f.Add([]byte("farbfeld\x00\x00\x00\x01\x00\x00\x00\x01"))
	f.Add([]byte("8BPS\x00\x01\x00\x00\x00\x00\x00\x00\x00\x03\x00\x00\x00\x02\x00\x00\x00\x02\x00\x08\x00\x03"))
	f.Add([]byte("DDS \x7c\x00\x00\x00"))
	f.Add([]byte("#?RADIANCE\n\n-Y 2 +X 2\n"))
	f.Add([]byte("II*\x00\x08\x00\x00\x00\x01\x00"))
	f.Add([]byte("\x01\xda\x00\x01\x00\x03\x00\x02\x00\x02\x00\x03"))
	f.Add([]byte("\x00\x00\x01\x00\x01\x00"))
	f.Fuzz(func(t *testing.T, data []byte) {
		// A small pixel budget keeps the fuzzer from spending its time on
		// legitimately large allocations instead of on finding crashes.
		_, _ = Decode(data, Options{MaxPixels: 1 << 16})
	})
}

// TestTIFFOrientationIsApplied covers the one path where the browser cannot help
// us: x/image/tiff ignores the Orientation tag, so an upright-looking scan
// would arrive on its side. All eight EXIF cases are checked, because the
// mirrored ones produce a mirror image rather than an obviously sideways one —
// the error that survives review.
func TestTIFFOrientationIsApplied(t *testing.T) {
	// A 4x2 image with a single marked pixel at the top-left, which pins both
	// the axis swap and the mirroring.
	src := image.NewNRGBA(image.Rect(0, 0, 4, 2))
	for y := 0; y < 2; y++ {
		for x := 0; x < 4; x++ {
			src.SetNRGBA(x, y, color.NRGBA{10, 10, 10, 255})
		}
	}
	src.SetNRGBA(0, 0, color.NRGBA{255, 0, 0, 255})

	// Where the marked pixel must end up, and the resulting dimensions.
	cases := map[int]struct {
		x, y, w, h int
	}{
		1: {0, 0, 4, 2},
		2: {3, 0, 4, 2},
		3: {3, 1, 4, 2},
		4: {0, 1, 4, 2},
		5: {0, 0, 2, 4},
		6: {1, 0, 2, 4},
		7: {1, 3, 2, 4},
		8: {0, 3, 2, 4},
	}
	for o, want := range cases {
		t.Run("orientation "+itoa(o), func(t *testing.T) {
			got := applyOrientation(src, o)
			b := got.Bounds()
			if b.Dx() != want.w || b.Dy() != want.h {
				t.Fatalf("orientation %d gave %dx%d, want %dx%d", o, b.Dx(), b.Dy(), want.w, want.h)
			}
			r, _, _, _ := got.At(want.x, want.y).RGBA()
			if r>>8 != 255 {
				t.Fatalf("orientation %d: the marked pixel is not at (%d,%d) — found red=%d there",
					o, want.x, want.y, r>>8)
			}
		})
	}
}

func TestTIFFOrientationTagIsRead(t *testing.T) {
	var b tiffBuilder
	b.add(tagOrientation, 3, 1, 6)
	if got := orientationOf(b.build()); got != 6 {
		t.Fatalf("orientationOf = %d, want 6", got)
	}
	// Absent, and out of range, both mean "leave it alone".
	var empty tiffBuilder
	empty.add(tagCompression, 3, 1, 1)
	if got := orientationOf(empty.build()); got != 1 {
		t.Fatalf("orientationOf with no tag = %d, want 1", got)
	}
	var bogus tiffBuilder
	bogus.add(tagOrientation, 3, 1, 99)
	if got := orientationOf(bogus.build()); got != 1 {
		t.Fatalf("orientationOf with a bogus value = %d, want 1", got)
	}
}

// rawFrame builds a JPEG-shaped stream our header walk will happily parse: SOI,
// one frame header with the given marker, sample precision and dimensions, then
// EOI. Deliberately no entropy-coded data — the walk returns at EOI, and the
// point of these fixtures is which candidates are accepted at all, not pixels.
func rawFrame(marker byte, precision, w, h int) []byte {
	seg := []byte{
		0x00, 0x11, // length: 8 + 3 components
		byte(precision),
		byte(h >> 8), byte(h), byte(w >> 8), byte(w),
		0x03,
		0x01, 0x22, 0x00,
		0x02, 0x11, 0x01,
		0x03, 0x11, 0x01,
	}
	out := []byte{0xff, 0xd8, 0xff, marker}
	out = append(out, seg...)
	return append(out, 0xff, 0xd9)
}

func TestRawMosaicIsNeverMistakenForAPreview(t *testing.T) {
	// A CR2 or a compressed DNG stores the undemosaiced sensor data as a
	// LOSSLESS JPEG (SOF3). It is a real, well-formed JPEG stream at full
	// sensor resolution, so on pixel count it beats every preview in the file —
	// and no decoder outside LibRaw can turn it into a picture. Picking it
	// would hand the recipient a .jpg that nothing opens, which is a worse
	// outcome than refusing the file.
	preview := makeJPEG(t, 1620, 1080)
	mosaic := rawFrame(0xc3, 14, 6000, 4000) // SOF3, 14-bit: a sensor frame
	var b tiffBuilder
	pref, psize := b.addBlob(preview)
	b.addBlob(mosaic)
	b.add(tagPhotometric, 3, 1, photometricCFA)
	b.addPointer(tagJPEGIFOffset, pref)
	b.add(tagJPEGIFByteCount, 4, 1, psize)
	data := b.build()

	got, w, h, err := extractEmbeddedJPEG(data)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if w != 1620 || h != 1080 {
		t.Fatalf("picked a %dx%d stream; the only real preview is 1620x1080 "+
			"(6000x4000 means the sensor mosaic was chosen)", w, h)
	}
	if !bytes.Equal(got, preview) {
		t.Fatal("returned bytes are not the preview")
	}
	// And the bytes handed over must decode, not merely measure.
	if _, err := jpeg.DecodeConfig(bytes.NewReader(got)); err != nil {
		t.Fatalf("the extracted preview does not decode: %v", err)
	}
}

func TestRawFallsBackWhenTheLargestPreviewCannotBeDecoded(t *testing.T) {
	// Some cameras write a 12-bit preview. It parses as a perfectly ordinary
	// baseline frame — our header walk measures it without complaint — and then
	// every 8-bit JPEG decoder in existence refuses it, Go's and the browser's
	// included. Taking it on size alone would fail the send with "couldn't read
	// that image" while a usable preview sat untouched further down the file.
	deep := rawFrame(0xc0, 12, 4000, 3000) // SOF0, but 12 bits per sample
	usable := makeJPEG(t, 1024, 768)
	var b tiffBuilder
	b.addBlob(deep)
	b.addBlob(usable)
	b.add(tagPhotometric, 3, 1, photometricCFA)
	data := b.build()

	got, w, h, err := extractEmbeddedJPEG(data)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if w != 1024 || h != 768 {
		t.Fatalf("picked a %dx%d stream, want the decodable 1024x768 one", w, h)
	}
	if !bytes.Equal(got, usable) {
		t.Fatal("returned bytes are not the decodable preview")
	}
}

func TestRawScansEvenWhenATaggedPreviewIsRespectable(t *testing.T) {
	// The tags are a hint, not an inventory. A camera that tags a half-size
	// preview can still carry a bigger one in a MakerNote, and the old gate
	// only looked past the tags when what they described was tiny — so a
	// 1200px tagged preview stopped the search and the full-size image in the
	// same file was never found.
	tagged := makeJPEG(t, 1200, 800)
	bigger := makeJPEG(t, 2400, 1600)
	var b tiffBuilder
	tref, tsize := b.addBlob(tagged)
	b.addBlob(bigger) // untagged, as a MakerNote preview would be
	b.add(tagPhotometric, 3, 1, photometricCFA)
	b.addPointer(tagJPEGIFOffset, tref)
	b.add(tagJPEGIFByteCount, 4, 1, tsize)
	data := b.build()

	_, w, h, err := extractEmbeddedJPEG(data)
	if err != nil {
		t.Fatalf("extract: %v", err)
	}
	if w != 2400 || h != 1600 {
		t.Fatalf("picked the %dx%d preview, want the 2400x1600 one found by scanning", w, h)
	}
}

func TestValidateJPEGRejectsFrameTypesNothingCanDecode(t *testing.T) {
	// Only baseline, extended sequential and progressive are JPEGs anything
	// downstream will open. The other twelve frame types — lossless,
	// differential, arithmetic-coded — are what a RAW stores its sensor data
	// as, so they turn up in these files constantly and at the largest
	// dimensions in them. Rejecting them here is the early-out; the decode
	// check in extractEmbeddedJPEG is the guarantee. Tested directly because
	// that backstop otherwise masks this filter entirely.
	for _, m := range []byte{0xc3, 0xc5, 0xc6, 0xc7, 0xc9, 0xca, 0xcb, 0xcd, 0xce, 0xcf} {
		if _, ok := validateJPEGAt(rawFrame(m, 8, 6000, 4000), 0); ok {
			t.Fatalf("accepted an SOF%#x frame: a sensor mosaic would outrank every real preview", m)
		}
	}
	for _, m := range []byte{0xc0, 0xc1, 0xc2} {
		c, ok := validateJPEGAt(rawFrame(m, 8, 640, 480), 0)
		if !ok {
			t.Fatalf("rejected an SOF%#x frame, which is a readable JPEG", m)
		}
		if c.w != 640 || c.h != 480 {
			t.Fatalf("SOF%#x measured %dx%d, want 640x480", m, c.w, c.h)
		}
	}
}
