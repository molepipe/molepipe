package imagedecode

// Per-format round-trip tests.
//
// Every fixture is SYNTHESIZED here, in Go, from a known pixel pattern, and the
// test asserts the decoded pixels match that pattern. The distinction matters:
// a test that merely checked "decode returned no error" would pass with a
// decoder that produced a black rectangle, and black rectangles are exactly how
// these formats fail — a wrong row stride, a swapped colour order or an
// off-by-one palette index all decode "successfully".
//
// What synthesized fixtures prove and do not prove: they prove the parsers
// handle the format as specified. They do NOT prove compatibility with any
// particular camera or editor, which only real files can show. The RAW tests in
// raw_test.go are the ones built to survive that gap, because they assert on
// structure (the largest preview wins) rather than on one vendor's layout.

import (
	"bytes"
	"image"
	"image/color"
	"image/png"
	"testing"

	"golang.org/x/image/bmp"
	"golang.org/x/image/tiff"
)

// pattern is the reference image: four colours chosen so that a channel swap
// (RGB read as BGR) and a row flip are both immediately visible.
var pattern = [4][4]color.NRGBA{
	{{255, 0, 0, 255}, {0, 255, 0, 255}, {0, 0, 255, 255}, {255, 255, 255, 255}},
	{{0, 0, 0, 255}, {255, 255, 0, 255}, {0, 255, 255, 255}, {255, 0, 255, 255}},
	{{128, 0, 0, 255}, {0, 128, 0, 255}, {0, 0, 128, 255}, {128, 128, 128, 255}},
	{{32, 64, 96, 255}, {96, 64, 32, 255}, {10, 200, 30, 255}, {200, 10, 30, 255}},
}

func patternImage() *image.NRGBA {
	img := image.NewNRGBA(image.Rect(0, 0, 4, 4))
	for y := 0; y < 4; y++ {
		for x := 0; x < 4; x++ {
			img.SetNRGBA(x, y, pattern[y][x])
		}
	}
	return img
}

// assertPattern compares a decoded image against the reference within tol per
// channel. Tolerance exists for formats that genuinely quantise (5-6-5 colour
// in DXT and 16-bit TGA); it is 0 for everything lossless.
func assertPattern(t *testing.T, img image.Image, tol int) {
	t.Helper()
	b := img.Bounds()
	if b.Dx() != 4 || b.Dy() != 4 {
		t.Fatalf("decoded %dx%d, want 4x4", b.Dx(), b.Dy())
	}
	for y := 0; y < 4; y++ {
		for x := 0; x < 4; x++ {
			r, g, bl, a := img.At(b.Min.X+x, b.Min.Y+y).RGBA()
			want := pattern[y][x]
			got := color.NRGBA{uint8(r >> 8), uint8(g >> 8), uint8(bl >> 8), uint8(a >> 8)}
			if !near(got, want, tol) {
				t.Fatalf("pixel (%d,%d) = %v, want %v (tolerance %d)", x, y, got, want, tol)
			}
		}
	}
}

func near(a, b color.NRGBA, tol int) bool {
	d := func(x, y uint8) bool {
		v := int(x) - int(y)
		if v < 0 {
			v = -v
		}
		return v <= tol
	}
	return d(a.R, b.R) && d(a.G, b.G) && d(a.B, b.B) && d(a.A, b.A)
}

// ---- Netpbm ----

func TestNetpbmBinaryRGB(t *testing.T) {
	var buf bytes.Buffer
	buf.WriteString("P6\n# a comment, which the parser must skip\n4 4\n255\n")
	for y := 0; y < 4; y++ {
		for x := 0; x < 4; x++ {
			c := pattern[y][x]
			buf.Write([]byte{c.R, c.G, c.B})
		}
	}
	if f := Sniff(buf.Bytes()); f != PNM {
		t.Fatalf("sniffed %q, want PNM", f)
	}
	img, err := pnmDecode(buf.Bytes())
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	assertPattern(t, img, 0)
}

func TestNetpbmASCIIRGB(t *testing.T) {
	var buf bytes.Buffer
	buf.WriteString("P3 4 4 255\n")
	for y := 0; y < 4; y++ {
		for x := 0; x < 4; x++ {
			c := pattern[y][x]
			fmtInto(&buf, int(c.R), int(c.G), int(c.B))
		}
	}
	img, err := pnmDecode(buf.Bytes())
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	assertPattern(t, img, 0)
}

func TestNetpbmBitmapPolarity(t *testing.T) {
	// P1/P4's 1 means BLACK, the opposite of every other format here. A
	// decoder that misses that inverts the image, which this pins.
	src := []byte("P1\n2 2\n1 0\n0 1\n")
	img, err := pnmDecode(src)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	r, _, _, _ := img.At(0, 0).RGBA()
	if r>>8 != 0 {
		t.Fatalf("P1 bit 1 decoded as %d, want 0 (black)", r>>8)
	}
	r, _, _, _ = img.At(1, 0).RGBA()
	if r>>8 != 255 {
		t.Fatalf("P1 bit 0 decoded as %d, want 255 (white)", r>>8)
	}
}

func TestNetpbm16Bit(t *testing.T) {
	// maxval > 255 means two bytes per sample, big-endian.
	var buf bytes.Buffer
	buf.WriteString("P5\n2 1\n65535\n")
	buf.Write([]byte{0xff, 0xff, 0x00, 0x00})
	img, err := pnmDecode(buf.Bytes())
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if r, _, _, _ := img.At(0, 0).RGBA(); r>>8 != 255 {
		t.Fatalf("16-bit white decoded as %d", r>>8)
	}
	if r, _, _, _ := img.At(1, 0).RGBA(); r>>8 != 0 {
		t.Fatalf("16-bit black decoded as %d", r>>8)
	}
}

func TestNetpbmPAMWithAlpha(t *testing.T) {
	var buf bytes.Buffer
	buf.WriteString("P7\nWIDTH 2\nHEIGHT 1\nDEPTH 4\nMAXVAL 255\nTUPLTYPE RGB_ALPHA\nENDHDR\n")
	buf.Write([]byte{255, 0, 0, 128, 0, 255, 0, 255})
	img, err := pnmDecode(buf.Bytes())
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if _, _, _, a := img.At(0, 0).RGBA(); a>>8 != 128 {
		t.Fatalf("PAM alpha = %d, want 128", a>>8)
	}
}

// ---- farbfeld ----

func TestFarbfeld(t *testing.T) {
	var buf bytes.Buffer
	buf.WriteString("farbfeld")
	buf.Write([]byte{0, 0, 0, 4, 0, 0, 0, 4})
	for y := 0; y < 4; y++ {
		for x := 0; x < 4; x++ {
			c := pattern[y][x]
			for _, v := range []uint8{c.R, c.G, c.B, c.A} {
				// 8-bit value replicated into 16 bits, as farbfeld expects.
				buf.Write([]byte{v, v})
			}
		}
	}
	if f := Sniff(buf.Bytes()); f != FARBFELD {
		t.Fatalf("sniffed %q, want farbfeld", f)
	}
	img, err := farbfeldDecode(buf.Bytes())
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	assertPattern(t, img, 0)
}

// ---- QOI ----

func TestQOI(t *testing.T) {
	var buf bytes.Buffer
	buf.WriteString("qoif")
	buf.Write([]byte{0, 0, 0, 4, 0, 0, 0, 4, 4, 0})
	for y := 0; y < 4; y++ {
		for x := 0; x < 4; x++ {
			c := pattern[y][x]
			buf.Write([]byte{0xff, c.R, c.G, c.B, c.A}) // QOI_OP_RGBA
		}
	}
	buf.Write([]byte{0, 0, 0, 0, 0, 0, 0, 1})
	if f := Sniff(buf.Bytes()); f != QOI {
		t.Fatalf("sniffed %q, want qoi", f)
	}
	img, err := qoiDecode(buf.Bytes())
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	assertPattern(t, img, 0)
}

func TestQOIRunAndIndexOps(t *testing.T) {
	// Exercises QOI_OP_RUN and QOI_OP_INDEX, which the all-RGBA fixture above
	// never reaches — a decoder can pass that test with both opcodes broken.
	var buf bytes.Buffer
	buf.WriteString("qoif")
	buf.Write([]byte{0, 0, 0, 4, 0, 0, 0, 1, 4, 0})
	red := color.NRGBA{200, 50, 25, 255}
	buf.Write([]byte{0xff, red.R, red.G, red.B, red.A}) // pixel 0, seeds the index
	buf.Write([]byte{0xc0 | 1})                         // RUN of 2 → pixels 1,2
	buf.Write([]byte{byte(qoiHash(red))})               // INDEX → pixel 3
	buf.Write([]byte{0, 0, 0, 0, 0, 0, 0, 1})
	img, err := qoiDecode(buf.Bytes())
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	for x := 0; x < 4; x++ {
		r, g, b, _ := img.At(x, 0).RGBA()
		got := color.NRGBA{uint8(r >> 8), uint8(g >> 8), uint8(b >> 8), 255}
		if !near(got, red, 0) {
			t.Fatalf("pixel %d = %v, want %v (RUN/INDEX opcode mishandled)", x, got, red)
		}
	}
}

// ---- TGA ----

func tgaFixture(bpp byte, rle bool, topDown bool) []byte {
	var buf bytes.Buffer
	imgType := byte(2)
	if rle {
		imgType = 10
	}
	desc := byte(0)
	if topDown {
		desc |= 0x20
	}
	if bpp == 32 {
		desc |= 8 // alpha bit count
	}
	buf.Write([]byte{0, 0, imgType, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 4, 0, bpp, desc})
	px := func(c color.NRGBA) []byte {
		if bpp == 32 {
			return []byte{c.B, c.G, c.R, c.A}
		}
		return []byte{c.B, c.G, c.R}
	}
	for y := 0; y < 4; y++ {
		sy := y
		if !topDown {
			sy = 3 - y // stored bottom-up
		}
		for x := 0; x < 4; x++ {
			c := pattern[sy][x]
			if rle {
				buf.WriteByte(0) // a literal packet of one pixel
			}
			buf.Write(px(c))
		}
	}
	return buf.Bytes()
}

func TestTGAVariants(t *testing.T) {
	for _, tc := range []struct {
		name    string
		bpp     byte
		rle     bool
		topDown bool
	}{
		{"24-bit bottom-up", 24, false, false},
		{"32-bit bottom-up", 32, false, false},
		{"24-bit top-down", 24, false, true},
		{"24-bit RLE", 24, true, false},
		{"32-bit RLE top-down", 32, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := tgaFixture(tc.bpp, tc.rle, tc.topDown)
			img, err := tgaDecode(data)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			assertPattern(t, img, 0)
		})
	}
}

func TestTGARunLengthPacket(t *testing.T) {
	// A real run packet (high bit set), which the one-pixel-literal fixture
	// above never produces.
	var buf bytes.Buffer
	buf.Write([]byte{0, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 0, 1, 0, 24, 0x20})
	buf.WriteByte(0x80 | 3) // run of 4
	buf.Write([]byte{0x11, 0x22, 0x33})
	img, err := tgaDecode(buf.Bytes())
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	for x := 0; x < 4; x++ {
		r, g, b, _ := img.At(x, 0).RGBA()
		if uint8(r>>8) != 0x33 || uint8(g>>8) != 0x22 || uint8(b>>8) != 0x11 {
			t.Fatalf("run pixel %d = %02x%02x%02x, want 332211", x, r>>8, g>>8, b>>8)
		}
	}
}

// ---- PCX ----

func TestPCX8BitPalette(t *testing.T) {
	var buf bytes.Buffer
	hdr := make([]byte, 128)
	hdr[0] = 0x0a
	hdr[1] = 5
	hdr[2] = 1 // RLE
	hdr[3] = 8 // bits per plane
	putLE16(hdr[8:], 3)
	putLE16(hdr[10:], 3)
	hdr[65] = 1 // one plane
	putLE16(hdr[66:], 4)
	buf.Write(hdr)
	// 16 palette entries used as indices 0..15, one per reference pixel.
	for y := 0; y < 4; y++ {
		for x := 0; x < 4; x++ {
			// Uncompressed literal bytes: any value under 0xc0 is a literal.
			buf.WriteByte(byte(y*4 + x))
		}
	}
	buf.WriteByte(0x0c)
	pal := make([]byte, 768)
	for y := 0; y < 4; y++ {
		for x := 0; x < 4; x++ {
			i := y*4 + x
			c := pattern[y][x]
			pal[i*3], pal[i*3+1], pal[i*3+2] = c.R, c.G, c.B
		}
	}
	buf.Write(pal)
	if f := Sniff(buf.Bytes()); f != PCX {
		t.Fatalf("sniffed %q, want pcx", f)
	}
	img, err := pcxDecode(buf.Bytes())
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	assertPattern(t, img, 0)
}

func TestPCXPlanar24Bit(t *testing.T) {
	var buf bytes.Buffer
	hdr := make([]byte, 128)
	hdr[0] = 0x0a
	hdr[1] = 5
	hdr[2] = 1
	hdr[3] = 8
	putLE16(hdr[8:], 3)
	putLE16(hdr[10:], 3)
	hdr[65] = 3 // three planes: all reds, then greens, then blues
	putLE16(hdr[66:], 4)
	buf.Write(hdr)
	// PCX RLE reserves the top two bits as a repeat marker, so a LITERAL byte
	// of 0xC0 or above must itself be written as a one-long run. The reference
	// pattern contains 0xFF, which makes this mandatory rather than academic —
	// writing it raw would have the decoder read a colour as a run length.
	pcxLit := func(v byte) {
		if v >= 0xc0 {
			buf.WriteByte(0xc1)
		}
		buf.WriteByte(v)
	}
	for y := 0; y < 4; y++ {
		for _, ch := range []int{0, 1, 2} {
			for x := 0; x < 4; x++ {
				c := pattern[y][x]
				pcxLit([]byte{c.R, c.G, c.B}[ch])
			}
		}
	}
	img, err := pcxDecode(buf.Bytes())
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	assertPattern(t, img, 0)
}

// ---- SGI ----

func TestSGIVerbatim(t *testing.T) {
	var buf bytes.Buffer
	hdr := make([]byte, 512)
	hdr[0], hdr[1] = 0x01, 0xda
	hdr[2] = 0 // verbatim
	hdr[3] = 1 // one byte per channel
	putBE16(hdr[4:], 3)
	putBE16(hdr[6:], 4)
	putBE16(hdr[8:], 4)
	putBE16(hdr[10:], 3)
	buf.Write(hdr)
	// Channel-major, each channel's rows bottom-up.
	for _, ch := range []int{0, 1, 2} {
		for y := 3; y >= 0; y-- {
			for x := 0; x < 4; x++ {
				c := pattern[y][x]
				buf.WriteByte([]byte{c.R, c.G, c.B}[ch])
			}
		}
	}
	if f := Sniff(buf.Bytes()); f != SGI {
		t.Fatalf("sniffed %q, want sgi", f)
	}
	img, err := sgiDecode(buf.Bytes())
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	assertPattern(t, img, 0)
}

// ---- Sun raster ----

func TestSunRaster24(t *testing.T) {
	var buf bytes.Buffer
	hdr := make([]byte, 32)
	putBE32(hdr[0:], 0x59a66a95)
	putBE32(hdr[4:], 4)
	putBE32(hdr[8:], 4)
	putBE32(hdr[12:], 24)
	putBE32(hdr[20:], 1) // standard, so BGR
	buf.Write(hdr)
	for y := 0; y < 4; y++ {
		row := make([]byte, 0, 16)
		for x := 0; x < 4; x++ {
			c := pattern[y][x]
			row = append(row, c.B, c.G, c.R)
		}
		for len(row)%2 != 0 { // rows pad to 16 bits
			row = append(row, 0)
		}
		buf.Write(row)
	}
	if f := Sniff(buf.Bytes()); f != SUNRAS {
		t.Fatalf("sniffed %q, want sunras", f)
	}
	img, err := sunrasDecode(buf.Bytes())
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	assertPattern(t, img, 0)
}

// ---- ICO ----

func icoWrap(entries [][]byte, widths []int) []byte {
	var buf bytes.Buffer
	buf.Write([]byte{0, 0, 1, 0})
	putLE16Buf(&buf, uint16(len(entries)))
	off := 6 + 16*len(entries)
	for i, e := range entries {
		w := widths[i]
		b := byte(w)
		if w >= 256 {
			b = 0
		}
		buf.Write([]byte{b, b, 0, 0, 1, 0, 32, 0})
		putLE32Buf(&buf, uint32(len(e)))
		putLE32Buf(&buf, uint32(off))
		off += len(e)
	}
	for _, e := range entries {
		buf.Write(e)
	}
	return buf.Bytes()
}

func TestICOWithPNGEntry(t *testing.T) {
	var pbuf bytes.Buffer
	if err := png.Encode(&pbuf, patternImage()); err != nil {
		t.Fatal(err)
	}
	data := icoWrap([][]byte{pbuf.Bytes()}, []int{4})
	if f := Sniff(data); f != ICO {
		t.Fatalf("sniffed %q, want ico", f)
	}
	img, err := icoDecode(data)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	assertPattern(t, img, 0)
}

func TestICOWithBMPEntry(t *testing.T) {
	// A classic 32-bit DIB entry: no file header, bottom-up rows, BGRA order,
	// and a stored height of double the real one for the AND mask.
	var dib bytes.Buffer
	hdr := make([]byte, 40)
	putLE32(hdr[0:], 40)
	putLE32(hdr[4:], 4)
	putLE32(hdr[8:], 8) // 4 rows of colour + 4 of mask
	putLE16(hdr[12:], 1)
	putLE16(hdr[14:], 32)
	dib.Write(hdr)
	for y := 3; y >= 0; y-- {
		for x := 0; x < 4; x++ {
			c := pattern[y][x]
			dib.Write([]byte{c.B, c.G, c.R, c.A})
		}
	}
	dib.Write(make([]byte, 4*4)) // zeroed AND mask
	data := icoWrap([][]byte{dib.Bytes()}, []int{4})
	img, err := icoDecode(data)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	assertPattern(t, img, 0)
}

func TestICOPicksTheLargestEntry(t *testing.T) {
	// A favicon holds many sizes. Sending the 16×16 when a 64×64 is present
	// would be the most annoying possible outcome, so this is pinned.
	small := image.NewNRGBA(image.Rect(0, 0, 2, 2))
	var sbuf, lbuf bytes.Buffer
	if err := png.Encode(&sbuf, small); err != nil {
		t.Fatal(err)
	}
	if err := png.Encode(&lbuf, patternImage()); err != nil {
		t.Fatal(err)
	}
	data := icoWrap([][]byte{sbuf.Bytes(), lbuf.Bytes()}, []int{2, 4})
	w, h, err := icoConfig(data)
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	if w != 4 || h != 4 {
		t.Fatalf("icoConfig chose %dx%d, want the 4x4 entry", w, h)
	}
	img, err := icoDecode(data)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	assertPattern(t, img, 0)
}

// ---- PSD ----

func psdFixture(t *testing.T, compression int) []byte {
	t.Helper()
	var buf bytes.Buffer
	buf.WriteString("8BPS")
	putBE16Buf(&buf, 1) // version 1 = PSD
	buf.Write(make([]byte, 6))
	putBE16Buf(&buf, 3) // three channels
	putBE32Buf(&buf, 4) // height
	putBE32Buf(&buf, 4) // width
	putBE16Buf(&buf, 8) // 8 bits
	putBE16Buf(&buf, 3) // RGB
	putBE32Buf(&buf, 0) // no colour mode data
	putBE32Buf(&buf, 0) // no image resources
	putBE32Buf(&buf, 0) // no layers
	putBE16Buf(&buf, uint16(compression))
	planes := [3][]byte{}
	for ch := 0; ch < 3; ch++ {
		for y := 0; y < 4; y++ {
			for x := 0; x < 4; x++ {
				c := pattern[y][x]
				planes[ch] = append(planes[ch], []byte{c.R, c.G, c.B}[ch])
			}
		}
	}
	switch compression {
	case 0:
		for _, p := range planes {
			buf.Write(p)
		}
	case 1:
		// PackBits per row, with the row-length table first.
		var rows [][]byte
		for ch := 0; ch < 3; ch++ {
			for y := 0; y < 4; y++ {
				rows = append(rows, packBits(planes[ch][y*4:(y+1)*4]))
			}
		}
		for _, r := range rows {
			putBE16Buf(&buf, uint16(len(r)))
		}
		for _, r := range rows {
			buf.Write(r)
		}
	}
	return buf.Bytes()
}

// packBits emits literal runs only, which is a valid PackBits stream.
func packBits(src []byte) []byte {
	out := []byte{byte(len(src) - 1)}
	return append(out, src...)
}

func TestPSDRawAndRLE(t *testing.T) {
	for _, tc := range []struct {
		name string
		comp int
	}{{"raw", 0}, {"PackBits RLE", 1}} {
		t.Run(tc.name, func(t *testing.T) {
			data := psdFixture(t, tc.comp)
			if f := Sniff(data); f != PSD {
				t.Fatalf("sniffed %q, want psd", f)
			}
			img, err := psdDecode(data)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			assertPattern(t, img, 0)
		})
	}
}

func TestPSDCMYKIsNotInverted(t *testing.T) {
	// Photoshop stores CMYK inverted (0 = full ink). A decoder that misses
	// that produces a photographic negative, which still "decodes fine", so
	// the polarity gets its own test: pure cyan ink must come out cyan-ish,
	// never red-ish.
	var buf bytes.Buffer
	buf.WriteString("8BPS")
	putBE16Buf(&buf, 1)
	buf.Write(make([]byte, 6))
	putBE16Buf(&buf, 4)
	putBE32Buf(&buf, 1)
	putBE32Buf(&buf, 1)
	putBE16Buf(&buf, 8)
	putBE16Buf(&buf, 4) // CMYK
	putBE32Buf(&buf, 0)
	putBE32Buf(&buf, 0)
	putBE32Buf(&buf, 0)
	putBE16Buf(&buf, 0)
	// Inverted: C=0 means FULL cyan; M=Y=K=255 means none.
	buf.Write([]byte{0, 255, 255, 255})
	img, err := psdDecode(buf.Bytes())
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	r, g, b, _ := img.At(0, 0).RGBA()
	if r>>8 > 80 || g>>8 < 150 || b>>8 < 150 {
		t.Fatalf("full cyan decoded as rgb(%d,%d,%d) — CMYK polarity is inverted", r>>8, g>>8, b>>8)
	}
}

// ---- DDS ----

func TestDDSUncompressedBGRA(t *testing.T) {
	var buf bytes.Buffer
	buf.WriteString("DDS ")
	hdr := make([]byte, 124)
	putLE32(hdr[0:], 124)
	putLE32(hdr[8:], 4)  // height
	putLE32(hdr[12:], 4) // width
	putLE32(hdr[72:], 32)
	putLE32(hdr[76:], 0x41) // DDPF_RGB | DDPF_ALPHAPIXELS
	putLE32(hdr[84:], 32)   // bit count
	putLE32(hdr[88:], 0x00ff0000)
	putLE32(hdr[92:], 0x0000ff00)
	putLE32(hdr[96:], 0x000000ff)
	putLE32(hdr[100:], 0xff000000)
	buf.Write(hdr)
	for y := 0; y < 4; y++ {
		for x := 0; x < 4; x++ {
			c := pattern[y][x]
			buf.Write([]byte{c.B, c.G, c.R, c.A})
		}
	}
	if f := Sniff(buf.Bytes()); f != DDS {
		t.Fatalf("sniffed %q, want dds", f)
	}
	img, err := ddsDecode(buf.Bytes())
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	assertPattern(t, img, 0)
}

func ddsBlockFixture(fourCC string, block []byte) []byte {
	var buf bytes.Buffer
	buf.WriteString("DDS ")
	hdr := make([]byte, 124)
	putLE32(hdr[0:], 124)
	putLE32(hdr[8:], 4)
	putLE32(hdr[12:], 4)
	putLE32(hdr[76:], 0x4) // DDPF_FOURCC
	copy(hdr[80:84], fourCC)
	buf.Write(hdr)
	buf.Write(block)
	return buf.Bytes()
}

func TestDDSDXT1SolidBlock(t *testing.T) {
	// One 4×4 block whose indices all select endpoint 0, so every pixel must
	// come out as that endpoint colour (within 5-6-5 quantisation).
	want := color.NRGBA{255, 0, 0, 255}
	block := make([]byte, 8)
	putLE16(block[0:], 0xf800) // red in 5-6-5
	putLE16(block[2:], 0x0000)
	data := ddsBlockFixture("DXT1", block)
	img, err := ddsDecode(data)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	for y := 0; y < 4; y++ {
		for x := 0; x < 4; x++ {
			r, g, b, a := img.At(x, y).RGBA()
			got := color.NRGBA{uint8(r >> 8), uint8(g >> 8), uint8(b >> 8), uint8(a >> 8)}
			if !near(got, want, 8) {
				t.Fatalf("DXT1 pixel (%d,%d) = %v, want ~%v", x, y, got, want)
			}
		}
	}
}

func TestDDSDXT5AlphaRamp(t *testing.T) {
	// BC3's alpha block is interpolated, not explicit, and its two endpoint
	// orderings select different ramps. a0 > a1 with index 0 must give a0.
	block := make([]byte, 16)
	block[0] = 255 // a0
	block[1] = 0   // a1
	putLE16(block[8:], 0x001f)
	data := ddsBlockFixture("DXT5", block)
	img, err := ddsDecode(data)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if _, _, _, a := img.At(0, 0).RGBA(); a>>8 != 255 {
		t.Fatalf("DXT5 alpha index 0 = %d, want 255", a>>8)
	}
}

func TestDDSBC7IsNamedNotJustRefused(t *testing.T) {
	// BC7 is genuinely not implemented. The error must say so, because
	// "couldn't read that image" would send the user to a bug report.
	var buf bytes.Buffer
	buf.WriteString("DDS ")
	hdr := make([]byte, 124)
	putLE32(hdr[0:], 124)
	putLE32(hdr[8:], 4)
	putLE32(hdr[12:], 4)
	putLE32(hdr[76:], 0x4)
	copy(hdr[80:84], "DX10")
	buf.Write(hdr)
	ext := make([]byte, 20)
	putLE32(ext[0:], 98) // DXGI_FORMAT_BC7_UNORM
	buf.Write(ext)
	buf.Write(make([]byte, 16))
	_, err := ddsDecode(buf.Bytes())
	if err == nil {
		t.Fatal("BC7 decoded, but no BC7 decoder exists")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("BC7")) {
		t.Fatalf("error %q does not name BC7", err)
	}
}

// ---- Radiance HDR ----

func TestHDRFlatScanlines(t *testing.T) {
	var buf bytes.Buffer
	buf.WriteString("#?RADIANCE\nFORMAT=32-bit_rle_rgbe\n\n-Y 2 +X 2\n")
	// Exponent 128 with mantissa m gives a linear value of m/256.
	for i := 0; i < 4; i++ {
		buf.Write([]byte{200, 100, 50, 128})
	}
	if f := Sniff(buf.Bytes()); f != HDR {
		t.Fatalf("sniffed %q, want hdr", f)
	}
	img, err := hdrDecode(buf.Bytes())
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	b := img.Bounds()
	if b.Dx() != 2 || b.Dy() != 2 {
		t.Fatalf("decoded %dx%d, want 2x2", b.Dx(), b.Dy())
	}
	// Tone mapping makes exact values meaningless, but the channel ORDER and
	// relative brightness must survive: R was the largest input, so it must be
	// the largest output.
	r, g, bl, _ := img.At(0, 0).RGBA()
	if !(r > g && g > bl) {
		t.Fatalf("channel order lost: rgb(%d,%d,%d) from input 200/100/50", r>>8, g>>8, bl>>8)
	}
	if r>>8 == 0 || r>>8 == 255 {
		t.Fatalf("tone mapping produced a degenerate red channel (%d)", r>>8)
	}
}

func TestHDRNewStyleRLE(t *testing.T) {
	var buf bytes.Buffer
	buf.WriteString("#?RADIANCE\n\n-Y 1 +X 8\n")
	buf.Write([]byte{2, 2, 0, 8}) // new-RLE marker for a width of 8
	for c := 0; c < 4; c++ {
		v := byte(200)
		if c == 3 {
			v = 128 // exponent
		}
		buf.Write([]byte{128 + 8, v}) // a run of 8
	}
	img, err := hdrDecode(buf.Bytes())
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if img.Bounds().Dx() != 8 {
		t.Fatalf("width %d, want 8", img.Bounds().Dx())
	}
	r0, _, _, _ := img.At(0, 0).RGBA()
	r7, _, _, _ := img.At(7, 0).RGBA()
	if r0 != r7 || r0 == 0 {
		t.Fatalf("RLE run did not fill the row evenly: first=%d last=%d", r0>>8, r7>>8)
	}
}

// ---- XBM / WBMP / XPM ----

func TestXBM(t *testing.T) {
	src := []byte(`#define t_width 8
#define t_height 2
static unsigned char t_bits[] = { 0x01, 0x80 };
`)
	if f := Sniff(src); f != XBM {
		t.Fatalf("sniffed %q, want xbm", f)
	}
	img, err := xbmDecode(src)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	// XBM is LSB-first: 0x01 sets the LEFTMOST pixel of row 0.
	if r, _, _, _ := img.At(0, 0).RGBA(); r>>8 != 0 {
		t.Fatalf("XBM bit 0 of 0x01 = %d, want 0 (set = black, LSB first)", r>>8)
	}
	if r, _, _, _ := img.At(7, 1).RGBA(); r>>8 != 0 {
		t.Fatalf("XBM bit 7 of 0x80 = %d, want 0", r>>8)
	}
}

func TestWBMP(t *testing.T) {
	data := []byte{0, 0, 8, 1, 0b10000001}
	img, err := wbmpDecode(data)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if img.Bounds().Dx() != 8 || img.Bounds().Dy() != 1 {
		t.Fatalf("decoded %v, want 8x1", img.Bounds())
	}
	// WBMP is MSB-first and 1 is WHITE — the opposite polarity to XBM.
	if r, _, _, _ := img.At(0, 0).RGBA(); r>>8 != 255 {
		t.Fatalf("WBMP set bit = %d, want 255 (white)", r>>8)
	}
	if r, _, _, _ := img.At(1, 0).RGBA(); r>>8 != 0 {
		t.Fatalf("WBMP clear bit = %d, want 0", r>>8)
	}
}

func TestXPM(t *testing.T) {
	src := []byte(`/* XPM */
static char *t[] = {
"2 2 3 1",
"a c #ff0000",
"b c #00ff00",
"c c None",
"ab",
"cb"
};
`)
	if f := Sniff(src); f != XPM {
		t.Fatalf("sniffed %q, want xpm", f)
	}
	img, err := xpmDecode(src)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	r, _, _, _ := img.At(0, 0).RGBA()
	if r>>8 != 255 {
		t.Fatalf("XPM colour 'a' red = %d, want 255", r>>8)
	}
	if _, _, _, a := img.At(0, 1).RGBA(); a != 0 {
		t.Fatalf("XPM 'None' alpha = %d, want 0 (transparent)", a>>8)
	}
}

// ---- the x/image-backed formats, through the same harness ----

func TestTIFFAndBMPViaXImage(t *testing.T) {
	t.Run("tiff", func(t *testing.T) {
		var buf bytes.Buffer
		if err := tiff.Encode(&buf, patternImage(), nil); err != nil {
			t.Fatal(err)
		}
		if f := Sniff(buf.Bytes()); f != TIFF {
			t.Fatalf("sniffed %q, want tiff — a plain TIFF must not be taken for a RAW", f)
		}
		img, err := stdDecode(buf.Bytes())
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		assertPattern(t, img, 0)
	})
	t.Run("bmp", func(t *testing.T) {
		var buf bytes.Buffer
		if err := bmp.Encode(&buf, patternImage()); err != nil {
			t.Fatal(err)
		}
		if f := Sniff(buf.Bytes()); f != BMP {
			t.Fatalf("sniffed %q, want bmp", f)
		}
		img, err := stdDecode(buf.Bytes())
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		assertPattern(t, img, 0)
	})
}

// ---- little helpers for building fixtures ----

func fmtInto(buf *bytes.Buffer, vals ...int) {
	for _, v := range vals {
		buf.WriteString(itoa(v))
		buf.WriteByte(' ')
	}
}

func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	var b [8]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	return string(b[i:])
}

func putLE16(b []byte, v uint16) { b[0] = byte(v); b[1] = byte(v >> 8) }
func putBE16(b []byte, v uint16) { b[0] = byte(v >> 8); b[1] = byte(v) }
func putLE32(b []byte, v uint32) {
	b[0], b[1], b[2], b[3] = byte(v), byte(v>>8), byte(v>>16), byte(v>>24)
}
func putBE32(b []byte, v uint32) {
	b[0], b[1], b[2], b[3] = byte(v>>24), byte(v>>16), byte(v>>8), byte(v)
}
func putLE16Buf(buf *bytes.Buffer, v uint16) { var t [2]byte; putLE16(t[:], v); buf.Write(t[:]) }
func putBE16Buf(buf *bytes.Buffer, v uint16) { var t [2]byte; putBE16(t[:], v); buf.Write(t[:]) }
func putLE32Buf(buf *bytes.Buffer, v uint32) { var t [4]byte; putLE32(t[:], v); buf.Write(t[:]) }
func putBE32Buf(buf *bytes.Buffer, v uint32) { var t [4]byte; putBE32(t[:], v); buf.Write(t[:]) }
