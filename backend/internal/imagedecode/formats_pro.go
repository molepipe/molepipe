package imagedecode

// Decoders for the three "professional tool" formats worth real codec work:
// Photoshop documents, DirectDraw textures, and Radiance HDR.
//
// What each one gives the user:
//   PSD — someone sends a mockup straight out of Photoshop. We read the
//         flattened composite Photoshop stores for exactly this purpose, so no
//         layer compositing is needed.
//   DDS — game and 3D texture assets, which are block-compressed. BC1-BC5 are
//         implemented here; the block maths is the whole job.
//   HDR — 32-bit floating-point photographs from bracketing or rendering.
//         These have no "correct" 8-bit appearance, so a tone-mapper decides,
//         and the one here is chosen to be unsurprising rather than artistic.

import (
	"bytes"
	"compress/zlib"
	"errors"
	"fmt"
	"image"
	"image/color"
	"io"
	"math"
	"strconv"
	"strings"
)

// ---- PSD / PSB ----

type psdHeader struct {
	channels int
	w, h     int
	depth    int
	mode     int
	psb      bool
}

func psdHeaderOf(data []byte) (psdHeader, error) {
	var p psdHeader
	if len(data) < 26 || !has(data, 0, "8BPS") {
		return p, errors.New("not a Photoshop file")
	}
	ver := int(be16(data[4:]))
	if ver != 1 && ver != 2 {
		return p, fmt.Errorf("Photoshop version %d not supported", ver)
	}
	p.psb = ver == 2
	p.channels = int(be16(data[12:]))
	p.h = int(be32(data[14:]))
	p.w = int(be32(data[18:]))
	p.depth = int(be16(data[22:]))
	p.mode = int(be16(data[24:]))
	return p, nil
}

func psdConfig(data []byte) (int, int, error) {
	h, err := psdHeaderOf(data)
	if err != nil {
		return 0, 0, err
	}
	return h.w, h.h, nil
}

func psdDecode(data []byte) (image.Image, error) {
	h, err := psdHeaderOf(data)
	if err != nil {
		return nil, err
	}
	if err := checkDims(h.w, h.h); err != nil {
		return nil, err
	}
	if h.depth != 8 && h.depth != 16 && h.depth != 32 {
		return nil, fmt.Errorf("Photoshop bit depth %d not supported", h.depth)
	}

	p := 26
	// Colour mode data (the palette, for indexed and duotone files).
	if p+4 > len(data) {
		return nil, errTruncated
	}
	cmdLen := int(be32(data[p:]))
	p += 4
	if p+cmdLen > len(data) {
		return nil, errTruncated
	}
	cmData := data[p : p+cmdLen]
	p += cmdLen
	// Image resources.
	if p+4 > len(data) {
		return nil, errTruncated
	}
	p += 4 + int(be32(data[p:]))
	// Layer and mask information — a 64-bit length in PSB.
	if h.psb {
		if p+8 > len(data) {
			return nil, errTruncated
		}
		n := int(be32(data[p+4:])) // the high word is zero for any real file
		p += 8 + n
	} else {
		if p+4 > len(data) {
			return nil, errTruncated
		}
		p += 4 + int(be32(data[p:]))
	}
	if p+2 > len(data) {
		return nil, errTruncated
	}
	comp := int(be16(data[p:]))
	p += 2

	bytesPerSample := h.depth / 8
	if h.depth == 1 {
		bytesPerSample = 1
	}
	planeSize := h.w * h.h * bytesPerSample
	// Only the channels that contribute to the composite are read; a PSD can
	// carry dozens of spot and mask channels after them.
	want := psdWantChannels(h)
	if want > h.channels {
		want = h.channels
	}

	var planes [][]byte
	switch comp {
	case 0: // raw
		if p+planeSize*want > len(data) {
			return nil, errTruncated
		}
		for c := 0; c < want; c++ {
			planes = append(planes, data[p+c*planeSize:p+(c+1)*planeSize])
		}
	case 1: // PackBits per row, preceded by a table of row byte counts
		cw := 2
		if h.psb {
			cw = 4
		}
		rows := h.h * h.channels
		if p+rows*cw > len(data) {
			return nil, errTruncated
		}
		counts := make([]int, rows)
		for i := range counts {
			if cw == 2 {
				counts[i] = int(be16(data[p+i*2:]))
			} else {
				counts[i] = int(be32(data[p+i*4:]))
			}
		}
		p += rows * cw
		for c := 0; c < want; c++ {
			plane := make([]byte, 0, planeSize)
			for y := 0; y < h.h; y++ {
				n := counts[c*h.h+y]
				if p+n > len(data) {
					return nil, errTruncated
				}
				row, err := unpackBits(data[p:p+n], h.w*bytesPerSample)
				if err != nil {
					return nil, err
				}
				plane = append(plane, row...)
				p += n
			}
			planes = append(planes, plane)
		}
	case 2, 3: // zlib, optionally with per-row delta prediction
		zr, err := zlib.NewReader(bytes.NewReader(data[p:]))
		if err != nil {
			return nil, fmt.Errorf("Photoshop ZIP data is unreadable: %w", err)
		}
		defer zr.Close()
		flat := make([]byte, planeSize*want)
		if _, err := io.ReadFull(zr, flat); err != nil {
			return nil, errTruncated
		}
		if comp == 3 {
			psdUndelta(flat, h, want, bytesPerSample)
		}
		for c := 0; c < want; c++ {
			planes = append(planes, flat[c*planeSize:(c+1)*planeSize])
		}
	default:
		return nil, fmt.Errorf("Photoshop compression %d not supported", comp)
	}

	return psdCompose(h, planes, cmData, bytesPerSample)
}

// psdWantChannels is how many stored channels the composite actually needs for
// each colour mode, ignoring extra alpha and spot channels.
func psdWantChannels(h psdHeader) int {
	switch h.mode {
	case 0, 1, 2: // bitmap, grayscale, indexed
		return 1
	case 3, 9: // RGB, Lab
		if h.channels >= 4 {
			return 4
		}
		return 3
	case 4: // CMYK
		return 4
	}
	if h.channels >= 3 {
		return 3
	}
	return 1
}

// psdUndelta reverses the horizontal delta filter used by "ZIP with
// prediction": each sample is stored as its difference from the one to its left.
func psdUndelta(flat []byte, h psdHeader, channels, bps int) {
	rowBytes := h.w * bps
	for c := 0; c < channels; c++ {
		for y := 0; y < h.h; y++ {
			row := flat[(c*h.h+y)*rowBytes:]
			if len(row) < rowBytes {
				return
			}
			if bps == 1 {
				for x := 1; x < h.w; x++ {
					row[x] += row[x-1]
				}
			} else if bps == 2 {
				for x := 1; x < h.w; x++ {
					v := be16(row[x*2:]) + be16(row[(x-1)*2:])
					row[x*2] = byte(v >> 8)
					row[x*2+1] = byte(v)
				}
			}
		}
	}
}

// psdCompose turns the channel planes into an image, applying each colour
// mode's own interpretation. The CMYK case is the one with a trap: Photoshop
// stores CMYK INVERTED (0 means full ink), so a naive read produces a negative.
func psdCompose(h psdHeader, planes [][]byte, cmData []byte, bps int) (image.Image, error) {
	if len(planes) == 0 {
		return nil, errors.New("Photoshop file has no image data")
	}
	at := func(c, i int) uint8 {
		if c >= len(planes) {
			return 255
		}
		p := planes[c]
		switch bps {
		case 1:
			if i < len(p) {
				return p[i]
			}
		case 2:
			if i*2+1 < len(p) {
				return p[i*2] // high byte of a 16-bit sample
			}
		case 4:
			if i*4+3 < len(p) {
				// 32-bit float samples, nominally 0..1.
				u := be32(p[i*4:])
				f := math.Float32frombits(u)
				return clamp8(float64(f) * 255)
			}
		}
		return 0
	}

	img := image.NewNRGBA(image.Rect(0, 0, h.w, h.h))
	n := h.w * h.h
	for i := 0; i < n; i++ {
		var c color.NRGBA
		switch h.mode {
		case 0: // bitmap: 1 bit per pixel, 1 = black
			stride := (h.w + 7) / 8
			x, y := i%h.w, i/h.w
			var v uint8 = 255
			if len(planes[0]) > y*stride+x/8 && planes[0][y*stride+x/8]>>(7-uint(x%8))&1 == 1 {
				v = 0
			}
			c = color.NRGBA{v, v, v, 255}
		case 1: // grayscale
			v := at(0, i)
			c = color.NRGBA{v, v, v, 255}
			if len(planes) > 1 {
				c.A = at(1, i)
			}
		case 2: // indexed, palette in the colour mode data block
			idx := int(at(0, i))
			if len(cmData) >= 768 {
				c = color.NRGBA{cmData[idx], cmData[256+idx], cmData[512+idx], 255}
			} else {
				v := uint8(idx)
				c = color.NRGBA{v, v, v, 255}
			}
		case 4: // CMYK, stored inverted
			cy, m, ye, k := 255-at(0, i), 255-at(1, i), 255-at(2, i), 255-at(3, i)
			c = color.NRGBA{
				R: clamp8(float64(255-cy) * float64(255-k) / 255),
				G: clamp8(float64(255-m) * float64(255-k) / 255),
				B: clamp8(float64(255-ye) * float64(255-k) / 255),
				A: 255,
			}
		case 9: // Lab
			c = labToRGBA(at(0, i), at(1, i), at(2, i))
		default: // RGB and anything else with three planes
			c = color.NRGBA{at(0, i), at(1, i), at(2, i), 255}
			if len(planes) > 3 {
				c.A = at(3, i)
			}
		}
		img.SetNRGBA(i%h.w, i/h.w, c)
	}
	return img, nil
}

// labToRGBA converts Photoshop's 8-bit Lab encoding (L 0..255 for 0..100,
// a/b offset by 128) to sRGB, via XYZ with a D50 white point.
func labToRGBA(l8, a8, b8 uint8) color.NRGBA {
	l := float64(l8) * 100 / 255
	a := float64(a8) - 128
	b := float64(b8) - 128
	fy := (l + 16) / 116
	fx := fy + a/500
	fz := fy - b/200
	inv := func(t float64) float64 {
		if t*t*t > 0.008856 {
			return t * t * t
		}
		return (t - 16.0/116) / 7.787
	}
	x := 0.96422 * inv(fx)
	y := 1.00000 * inv(fy)
	z := 0.82521 * inv(fz)
	r := 3.1338561*x - 1.6168667*y - 0.4906146*z
	g := -0.9787684*x + 1.9161415*y + 0.0334540*z
	bl := 0.0719453*x - 0.2289914*y + 1.4052427*z
	enc := func(v float64) uint8 {
		if v <= 0.0031308 {
			v *= 12.92
		} else {
			v = 1.055*math.Pow(v, 1/2.4) - 0.055
		}
		return clamp8(v * 255)
	}
	return color.NRGBA{enc(r), enc(g), enc(bl), 255}
}

// unpackBits expands Apple PackBits, which both PSD and TIFF use: a signed
// count byte selects a literal run (0..127 means n+1 bytes follow) or a repeat
// (-1..-127 means 1-n copies of the next byte). -128 is a no-op.
func unpackBits(src []byte, want int) ([]byte, error) {
	out := make([]byte, 0, want)
	for i := 0; i < len(src) && len(out) < want; {
		n := int(int8(src[i]))
		i++
		switch {
		case n >= 0:
			cnt := n + 1
			if i+cnt > len(src) {
				return nil, errTruncated
			}
			out = append(out, src[i:i+cnt]...)
			i += cnt
		case n > -128:
			if i >= len(src) {
				return nil, errTruncated
			}
			v := src[i]
			i++
			for k := 0; k < 1-n; k++ {
				out = append(out, v)
			}
		}
	}
	if len(out) < want {
		// Pad rather than fail: a single short row in an otherwise good
		// Photoshop file should not cost the user the whole image.
		out = append(out, make([]byte, want-len(out))...)
	}
	return out[:want], nil
}

func clamp8(v float64) uint8 {
	if v <= 0 {
		return 0
	}
	if v >= 255 {
		return 255
	}
	return uint8(v + 0.5)
}

// ---- DDS (DirectDraw Surface) ----

func ddsConfig(data []byte) (int, int, error) {
	if len(data) < 128 || !has(data, 0, "DDS ") {
		return 0, 0, errors.New("not a DDS file")
	}
	return int(le32(data[16:])), int(le32(data[12:])), nil
}

func ddsDecode(data []byte) (image.Image, error) {
	w, h, err := ddsConfig(data)
	if err != nil {
		return nil, err
	}
	if err := checkDims(w, h); err != nil {
		return nil, err
	}
	pfFlags := le32(data[80:])
	fourCC := string(data[84:88])
	body := data[128:]

	// DX10 files put the real format in an extra header, as a DXGI enum.
	if fourCC == "DX10" {
		if len(data) < 148 {
			return nil, errTruncated
		}
		dxgi := le32(data[128:])
		body = data[148:]
		switch dxgi {
		case 70, 71, 72: // BC1 typeless/unorm/unorm_srgb
			fourCC = "DXT1"
		case 73, 74, 75: // BC2
			fourCC = "DXT3"
		case 76, 77, 78: // BC3
			fourCC = "DXT5"
		case 79, 80: // BC4
			fourCC = "ATI1"
		case 82, 83: // BC5
			fourCC = "ATI2"
		case 28, 29: // R8G8B8A8_UNORM / _SRGB
			return ddsUncompressed(body, w, h, 32, 0x000000ff, 0x0000ff00, 0x00ff0000, 0xff000000)
		case 87, 88: // B8G8R8A8
			return ddsUncompressed(body, w, h, 32, 0x00ff0000, 0x0000ff00, 0x000000ff, 0xff000000)
		case 98, 99: // BC7 — eight block modes, a decoder in its own right
			return nil, errors.New("this DDS uses BC7 texture compression, which Molepipe can't read")
		default:
			return nil, fmt.Errorf("this DDS uses DXGI format %d, which Molepipe can't read", dxgi)
		}
	}

	switch fourCC {
	case "DXT1":
		return ddsBlocks(body, w, h, 8, decodeBC1Block)
	case "DXT2", "DXT3":
		return ddsBlocks(body, w, h, 16, decodeBC2Block)
	case "DXT4", "DXT5":
		return ddsBlocks(body, w, h, 16, decodeBC3Block)
	case "ATI1", "BC4U", "BC4S":
		return ddsBlocks(body, w, h, 8, decodeBC4Block)
	case "ATI2", "BC5U", "BC5S":
		return ddsBlocks(body, w, h, 16, decodeBC5Block)
	}
	// Uncompressed, described by channel bit masks.
	if pfFlags&0x40 != 0 { // DDPF_RGB
		bits := int(le32(data[88:]))
		return ddsUncompressed(body, w, h, bits,
			le32(data[92:]), le32(data[96:]), le32(data[100:]), le32(data[104:]))
	}
	if fourCC != "" && fourCC[0] != 0 {
		return nil, fmt.Errorf("this DDS uses %q texture compression, which Molepipe can't read", fourCC)
	}
	return nil, errors.New("this DDS has no pixel format this app recognises")
}

// ddsUncompressed reads pixels described by arbitrary channel bit masks, which
// is how DDS expresses every uncompressed layout (BGRA, RGB565, X8R8G8B8, …)
// rather than naming them.
func ddsUncompressed(body []byte, w, h, bits int, rm, gm, bm, am uint32) (image.Image, error) {
	bpp := bits / 8
	if bpp < 1 || bpp > 4 {
		return nil, fmt.Errorf("DDS colour depth %d not supported", bits)
	}
	if len(body) < w*h*bpp {
		return nil, errTruncated
	}
	ex := func(v, mask uint32) uint8 {
		if mask == 0 {
			return 255
		}
		shift := 0
		for mask&1 == 0 {
			mask >>= 1
			shift++
		}
		width := 0
		for m := mask; m&1 == 1; m >>= 1 {
			width++
		}
		val := (v >> uint(shift)) & mask
		if width == 0 || width >= 8 {
			return uint8(val >> uint(width-8))
		}
		// Scale a narrow channel to 8 bits so 5-bit 31 becomes 255, not 248.
		return uint8(val * 255 / ((1 << uint(width)) - 1))
	}
	img := image.NewNRGBA(image.Rect(0, 0, w, h))
	for i := 0; i < w*h; i++ {
		var v uint32
		for b := 0; b < bpp; b++ {
			v |= uint32(body[i*bpp+b]) << uint(8*b)
		}
		img.SetNRGBA(i%w, i/w, color.NRGBA{ex(v, rm), ex(v, gm), ex(v, bm), ex(v, am)})
	}
	return img, nil
}

// ddsBlocks walks the 4×4 block grid common to every BC format. Blocks are
// stored left-to-right, top-to-bottom, and the image's dimensions need not be
// multiples of four — the trailing partial blocks are simply clipped.
func ddsBlocks(body []byte, w, h, blockBytes int, fn func([]byte, *[16]color.NRGBA)) (image.Image, error) {
	bw, bh := (w+3)/4, (h+3)/4
	if len(body) < bw*bh*blockBytes {
		return nil, errTruncated
	}
	img := image.NewNRGBA(image.Rect(0, 0, w, h))
	var px [16]color.NRGBA
	for by := 0; by < bh; by++ {
		for bx := 0; bx < bw; bx++ {
			fn(body[(by*bw+bx)*blockBytes:], &px)
			for i := 0; i < 16; i++ {
				x, y := bx*4+i%4, by*4+i/4
				if x < w && y < h {
					img.SetNRGBA(x, y, px[i])
				}
			}
		}
	}
	return img, nil
}

// rgb565 expands a packed 5-6-5 colour.
func rgb565(v uint16) color.NRGBA {
	r := uint8((v >> 11 & 0x1f) * 255 / 31)
	g := uint8((v >> 5 & 0x3f) * 255 / 63)
	b := uint8((v & 0x1f) * 255 / 31)
	return color.NRGBA{r, g, b, 255}
}

// decodeBC1Block expands a DXT1 block: two endpoint colours and 2-bit indices.
// When the first endpoint is not greater than the second the block switches to a
// 3-colour mode whose fourth index means transparent — that mode is why a DXT1
// texture can have (1-bit) alpha at all.
func decodeBC1Block(b []byte, out *[16]color.NRGBA) {
	c0, c1 := le16(b), le16(b[2:])
	p0, p1 := rgb565(c0), rgb565(c1)
	var pal [4]color.NRGBA
	pal[0], pal[1] = p0, p1
	if c0 > c1 {
		pal[2] = lerpRGB(p0, p1, 1, 3)
		pal[3] = lerpRGB(p0, p1, 2, 3)
	} else {
		pal[2] = lerpRGB(p0, p1, 1, 2)
		pal[3] = color.NRGBA{0, 0, 0, 0}
	}
	bits := le32(b[4:])
	for i := 0; i < 16; i++ {
		out[i] = pal[bits>>uint(2*i)&3]
	}
}

// decodeBC2Block is a DXT1 colour block preceded by 4 bits of explicit alpha
// per pixel.
func decodeBC2Block(b []byte, out *[16]color.NRGBA) {
	decodeBC1BlockOpaque(b[8:], out)
	for i := 0; i < 16; i++ {
		nib := b[i/2] >> (4 * uint(i%2)) & 0x0f
		out[i].A = nib * 17
	}
}

// decodeBC3Block is a DXT1 colour block with a BC4-style interpolated alpha
// block in front of it — the format almost every game texture with smooth
// transparency uses.
func decodeBC3Block(b []byte, out *[16]color.NRGBA) {
	decodeBC1BlockOpaque(b[8:], out)
	var a [16]uint8
	decodeAlphaBlock(b, &a)
	for i := 0; i < 16; i++ {
		out[i].A = a[i]
	}
}

// decodeBC4Block is a single interpolated channel, rendered as grayscale.
func decodeBC4Block(b []byte, out *[16]color.NRGBA) {
	var a [16]uint8
	decodeAlphaBlock(b, &a)
	for i := 0; i < 16; i++ {
		out[i] = color.NRGBA{a[i], a[i], a[i], 255}
	}
}

// decodeBC5Block is two BC4 channels, which is how normal maps are stored: red
// and green hold X and Y. Shown as R/G with blue at mid-grey, so the user sees
// the texture rather than an error.
func decodeBC5Block(b []byte, out *[16]color.NRGBA) {
	var r, g [16]uint8
	decodeAlphaBlock(b, &r)
	decodeAlphaBlock(b[8:], &g)
	for i := 0; i < 16; i++ {
		out[i] = color.NRGBA{r[i], g[i], 128, 255}
	}
}

// decodeBC1BlockOpaque is the colour half of BC2/BC3, where the 3-colour mode
// does not apply: alpha always comes from the separate alpha block.
func decodeBC1BlockOpaque(b []byte, out *[16]color.NRGBA) {
	p0, p1 := rgb565(le16(b)), rgb565(le16(b[2:]))
	pal := [4]color.NRGBA{p0, p1, lerpRGB(p0, p1, 1, 3), lerpRGB(p0, p1, 2, 3)}
	bits := le32(b[4:])
	for i := 0; i < 16; i++ {
		out[i] = pal[bits>>uint(2*i)&3]
	}
}

// decodeAlphaBlock expands the 8-byte interpolated single-channel block used by
// BC3's alpha, BC4 and both halves of BC5: two endpoints plus 3-bit indices,
// with the endpoint ordering selecting a 6- or 8-value ramp.
func decodeAlphaBlock(b []byte, out *[16]uint8) {
	a0, a1 := b[0], b[1]
	var ramp [8]uint8
	ramp[0], ramp[1] = a0, a1
	if a0 > a1 {
		for i := 0; i < 6; i++ {
			ramp[i+2] = uint8((int(a0)*(6-i) + int(a1)*(1+i)) / 7)
		}
	} else {
		for i := 0; i < 4; i++ {
			ramp[i+2] = uint8((int(a0)*(4-i) + int(a1)*(1+i)) / 5)
		}
		ramp[6], ramp[7] = 0, 255
	}
	// The 16 three-bit indices are packed into six bytes, read as two 24-bit
	// little-endian groups of eight.
	for half := 0; half < 2; half++ {
		bits := uint32(b[2+half*3]) | uint32(b[3+half*3])<<8 | uint32(b[4+half*3])<<16
		for i := 0; i < 8; i++ {
			out[half*8+i] = ramp[bits>>uint(3*i)&7]
		}
	}
}

func lerpRGB(a, b color.NRGBA, num, den int) color.NRGBA {
	m := den - num
	return color.NRGBA{
		uint8((int(a.R)*m + int(b.R)*num) / den),
		uint8((int(a.G)*m + int(b.G)*num) / den),
		uint8((int(a.B)*m + int(b.B)*num) / den),
		255,
	}
}

// ---- Radiance HDR (.hdr / .pic) ----

type hdrHeader struct {
	w, h   int
	bodyAt int
	flipX  bool
	flipY  bool
	swapXY bool
}

func hdrHeaderOf(data []byte) (hdrHeader, error) {
	var h hdrHeader
	s := string(data)
	// The header is text lines, terminated by a blank line, then a resolution
	// line such as "-Y 512 +X 768".
	end := strings.Index(s, "\n\n")
	if end < 0 {
		return h, errors.New("Radiance header has no terminator")
	}
	rest := s[end+2:]
	nl := strings.Index(rest, "\n")
	if nl < 0 {
		return h, errTruncated
	}
	res := strings.Fields(rest[:nl])
	if len(res) != 4 {
		return h, fmt.Errorf("Radiance resolution line %q is malformed", rest[:nl])
	}
	a, _ := strconv.Atoi(res[1])
	b, _ := strconv.Atoi(res[3])
	switch {
	case res[0] == "-Y" && res[2] == "+X":
		h.h, h.w = a, b
	case res[0] == "+Y" && res[2] == "+X":
		h.h, h.w, h.flipY = a, b, true
	case res[0] == "-Y" && res[2] == "-X":
		h.h, h.w, h.flipX = a, b, true
	case res[0] == "+Y" && res[2] == "-X":
		h.h, h.w, h.flipY, h.flipX = a, b, true, true
	default:
		// The -X/+Y major-axis variants store columns first.
		h.w, h.h, h.swapXY = a, b, true
	}
	h.bodyAt = end + 2 + nl + 1
	return h, nil
}

func hdrConfig(data []byte) (int, int, error) {
	h, err := hdrHeaderOf(data)
	if err != nil {
		return 0, 0, err
	}
	return h.w, h.h, nil
}

func hdrDecode(data []byte) (image.Image, error) {
	h, err := hdrHeaderOf(data)
	if err != nil {
		return nil, err
	}
	if err := checkDims(h.w, h.h); err != nil {
		return nil, err
	}
	if h.swapXY {
		return nil, errors.New("this Radiance file uses a row order Molepipe can't read")
	}
	rgbe := make([]byte, h.w*h.h*4)
	p := h.bodyAt
	for y := 0; y < h.h; y++ {
		row := rgbe[y*h.w*4:]
		if p+4 > len(data) {
			return nil, errTruncated
		}
		// New-style RLE announces itself with 2,2 and the row width split
		// across the next two bytes.
		if data[p] == 2 && data[p+1] == 2 && int(data[p+2])<<8|int(data[p+3]) == h.w && h.w >= 8 && h.w < 0x8000 {
			p += 4
			for c := 0; c < 4; c++ {
				x := 0
				for x < h.w {
					if p >= len(data) {
						return nil, errTruncated
					}
					n := int(data[p])
					p++
					if n > 128 { // a run
						if p >= len(data) {
							return nil, errTruncated
						}
						v := data[p]
						p++
						for k := 0; k < n-128 && x < h.w; k++ {
							row[x*4+c] = v
							x++
						}
					} else { // literals
						if p+n > len(data) {
							return nil, errTruncated
						}
						for k := 0; k < n && x < h.w; k++ {
							row[x*4+c] = data[p+k]
							x++
						}
						p += n
					}
				}
			}
			continue
		}
		// Flat scanline.
		if p+h.w*4 > len(data) {
			return nil, errTruncated
		}
		copy(row, data[p:p+h.w*4])
		p += h.w * 4
	}

	// RGBE is a shared exponent: the mantissas are 8-bit, the exponent biased
	// by 128, and e == 0 means the pixel is exactly black.
	lin := make([]float64, h.w*h.h*3)
	var logSum float64
	var logN int
	for i := 0; i < h.w*h.h; i++ {
		e := rgbe[i*4+3]
		if e == 0 {
			continue
		}
		f := math.Ldexp(1, int(e)-136)
		r := float64(rgbe[i*4]) * f
		g := float64(rgbe[i*4+1]) * f
		b := float64(rgbe[i*4+2]) * f
		lin[i*3], lin[i*3+1], lin[i*3+2] = r, g, b
		if lum := 0.2126*r + 0.7152*g + 0.0722*b; lum > 0 {
			logSum += math.Log(lum + 1e-6)
			logN++
		}
	}

	// Reinhard tone mapping against the log-average luminance. An HDR file has
	// no single correct 8-bit rendering, so the goal here is "recognisable and
	// never blown out", not an artistic grade: a plain clamp turns every
	// bracketed sunset into a white rectangle.
	key := 0.18
	scale := 1.0
	if logN > 0 {
		if avg := math.Exp(logSum / float64(logN)); avg > 0 {
			scale = key / avg
		}
	}
	img := image.NewNRGBA(image.Rect(0, 0, h.w, h.h))
	for y := 0; y < h.h; y++ {
		dy := y
		if h.flipY {
			dy = h.h - 1 - y
		}
		for x := 0; x < h.w; x++ {
			dx := x
			if h.flipX {
				dx = h.w - 1 - x
			}
			i := y*h.w + x
			enc := func(v float64) uint8 {
				v *= scale
				v = v / (1 + v) // Reinhard
				if v <= 0.0031308 {
					v *= 12.92
				} else {
					v = 1.055*math.Pow(v, 1/2.4) - 0.055
				}
				return clamp8(v * 255)
			}
			img.SetNRGBA(dx, dy, color.NRGBA{enc(lin[i*3]), enc(lin[i*3+1]), enc(lin[i*3+2]), 255})
		}
	}
	return img, nil
}
