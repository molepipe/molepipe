package imagedecode

// Decoders for the older desktop and workstation formats: Targa, PCX, SGI,
// Sun raster, and the Windows icon container. These turn up in game assets,
// scanned archives, clip-art collections and anything that has been through a
// 1990s toolchain — exactly the files that are hardest to convert today,
// because the tools that wrote them are gone.

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"image"
	"image/color"
	"image/png"
)

func le16(b []byte) uint16 { return binary.LittleEndian.Uint16(b) }
func le32(b []byte) uint32 { return binary.LittleEndian.Uint32(b) }

// ---- TGA / Targa ----

type tgaHeader struct {
	idLen      byte
	cmapType   byte
	imgType    byte
	cmapLen    int
	cmapBits   byte
	w, h       int
	bpp        byte
	descriptor byte
}

func tgaHeaderOf(data []byte) (tgaHeader, error) {
	var t tgaHeader
	if len(data) < 18 {
		return t, errors.New("not a TGA file")
	}
	t.idLen = data[0]
	t.cmapType = data[1]
	t.imgType = data[2]
	t.cmapLen = int(le16(data[5:]))
	t.cmapBits = data[7]
	t.w = int(le16(data[12:]))
	t.h = int(le16(data[14:]))
	t.bpp = data[16]
	t.descriptor = data[17]
	return t, nil
}

func tgaConfig(data []byte) (int, int, error) {
	t, err := tgaHeaderOf(data)
	if err != nil {
		return 0, 0, err
	}
	return t.w, t.h, nil
}

func tgaDecode(data []byte) (image.Image, error) {
	t, err := tgaHeaderOf(data)
	if err != nil {
		return nil, err
	}
	if t.w <= 0 || t.h <= 0 {
		return nil, errors.New("empty image")
	}
	p := 18 + int(t.idLen)
	// Colour map, when present.
	var cmap []color.RGBA
	if t.cmapType == 1 && t.cmapLen > 0 {
		entryBytes := int(t.cmapBits+7) / 8
		if p+t.cmapLen*entryBytes > len(data) {
			return nil, errTruncated
		}
		cmap = make([]color.RGBA, t.cmapLen)
		for i := range cmap {
			cmap[i] = tgaPixel(data[p+i*entryBytes:], t.cmapBits)
		}
		p += t.cmapLen * entryBytes
	}
	bytesPer := int(t.bpp+7) / 8
	if bytesPer == 0 {
		return nil, fmt.Errorf("TGA pixel depth %d is not usable", t.bpp)
	}
	total := t.w * t.h
	px := make([]color.RGBA, total)

	rle := t.imgType >= 9
	readOne := func(at int) (color.RGBA, error) {
		if at+bytesPer > len(data) {
			return color.RGBA{}, errTruncated
		}
		if t.imgType == 1 || t.imgType == 9 { // colour-mapped
			idx := int(data[at])
			if bytesPer == 2 {
				idx = int(le16(data[at:]))
			}
			if idx < 0 || idx >= len(cmap) {
				return color.RGBA{}, fmt.Errorf("TGA palette index %d out of range", idx)
			}
			return cmap[idx], nil
		}
		return tgaPixel(data[at:], t.bpp), nil
	}

	if !rle {
		if p+total*bytesPer > len(data) {
			return nil, errTruncated
		}
		for i := 0; i < total; i++ {
			c, err := readOne(p + i*bytesPer)
			if err != nil {
				return nil, err
			}
			px[i] = c
		}
	} else {
		// RLE packets: the high bit of the count byte selects run-length
		// (one pixel value repeated) or literal (count pixels follow).
		i := 0
		for i < total {
			if p >= len(data) {
				return nil, errTruncated
			}
			n := int(data[p]&0x7f) + 1
			runLen := data[p]&0x80 != 0
			p++
			if i+n > total {
				n = total - i
			}
			if runLen {
				c, err := readOne(p)
				if err != nil {
					return nil, err
				}
				p += bytesPer
				for k := 0; k < n; k++ {
					px[i+k] = c
				}
			} else {
				for k := 0; k < n; k++ {
					c, err := readOne(p)
					if err != nil {
						return nil, err
					}
					p += bytesPer
					px[i+k] = c
				}
			}
			i += n
		}
	}

	// Bit 5 of the descriptor is the origin: unset means the rows were stored
	// bottom-up, which is the common case and the classic way to decode a TGA
	// upside down.
	topDown := t.descriptor&0x20 != 0
	rightToLeft := t.descriptor&0x10 != 0
	img := image.NewNRGBA(image.Rect(0, 0, t.w, t.h))
	for y := 0; y < t.h; y++ {
		sy := y
		if !topDown {
			sy = t.h - 1 - y
		}
		for x := 0; x < t.w; x++ {
			sx := x
			if rightToLeft {
				sx = t.w - 1 - x
			}
			c := px[sy*t.w+sx]
			img.SetNRGBA(x, y, color.NRGBA(c))
		}
	}
	return img, nil
}

// tgaPixel reads one pixel. TGA stores colour as BGR(A), and its 16-bit form is
// 5-5-5 with a single attribute bit.
func tgaPixel(b []byte, bits byte) color.RGBA {
	switch bits {
	case 8:
		return color.RGBA{b[0], b[0], b[0], 255}
	case 15, 16:
		v := le16(b)
		r := uint8((v >> 10 & 0x1f) * 255 / 31)
		g := uint8((v >> 5 & 0x1f) * 255 / 31)
		bl := uint8((v & 0x1f) * 255 / 31)
		a := uint8(255)
		if bits == 16 && v&0x8000 == 0 {
			// The attribute bit is widely written as 0 on fully opaque images,
			// so treating it as alpha would make whole files invisible. Only
			// 15-bit-with-attribute files mean it, and they are vanishingly
			// rare; opaque is the safe reading.
			a = 255
		}
		return color.RGBA{r, g, bl, a}
	case 24:
		return color.RGBA{b[2], b[1], b[0], 255}
	case 32:
		return color.RGBA{b[2], b[1], b[0], b[3]}
	}
	return color.RGBA{}
}

// ---- PCX ----

func pcxConfig(data []byte) (int, int, error) {
	if len(data) < 128 || data[0] != 0x0a {
		return 0, 0, errors.New("not a PCX file")
	}
	xmin, ymin := int(le16(data[4:])), int(le16(data[6:]))
	xmax, ymax := int(le16(data[8:])), int(le16(data[10:]))
	return xmax - xmin + 1, ymax - ymin + 1, nil
}

func pcxDecode(data []byte) (image.Image, error) {
	w, h, err := pcxConfig(data)
	if err != nil {
		return nil, err
	}
	if err := checkDims(w, h); err != nil {
		return nil, err
	}
	bpp := data[3]
	planes := data[65]
	bpl := int(le16(data[66:]))
	if bpl <= 0 || planes == 0 || planes > 4 {
		return nil, fmt.Errorf("PCX layout not supported (%d bits, %d planes)", bpp, planes)
	}
	rowBytes := bpl * int(planes)

	// Unpack the RLE body: a byte with its top two bits set is a repeat count
	// for the byte that follows.
	body := data[128:]
	out := make([]byte, 0, rowBytes*h)
	if data[2] == 0 { // uncompressed variant
		if len(body) < rowBytes*h {
			return nil, errTruncated
		}
		out = body[:rowBytes*h]
	} else {
		for i := 0; i < len(body) && len(out) < rowBytes*h; {
			b := body[i]
			if b&0xc0 == 0xc0 {
				n := int(b & 0x3f)
				if i+1 >= len(body) {
					return nil, errTruncated
				}
				v := body[i+1]
				i += 2
				for k := 0; k < n && len(out) < rowBytes*h; k++ {
					out = append(out, v)
				}
			} else {
				out = append(out, b)
				i++
			}
		}
		if len(out) < rowBytes*h {
			return nil, errTruncated
		}
	}

	// Palette: 256 colours live in a trailing block introduced by 0x0C; the
	// 16-colour EGA palette is inline in the header.
	var pal []color.RGBA
	if bpp == 8 && planes == 1 {
		if len(data) >= 769 && data[len(data)-769] == 0x0c {
			t := data[len(data)-768:]
			pal = make([]color.RGBA, 256)
			for i := range pal {
				pal[i] = color.RGBA{t[i*3], t[i*3+1], t[i*3+2], 255}
			}
		} else {
			pal = make([]color.RGBA, 256)
			for i := range pal {
				pal[i] = color.RGBA{uint8(i), uint8(i), uint8(i), 255}
			}
		}
	} else {
		pal = make([]color.RGBA, 16)
		for i := range pal {
			pal[i] = color.RGBA{data[16+i*3], data[17+i*3], data[18+i*3], 255}
		}
	}

	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		row := out[y*rowBytes:]
		for x := 0; x < w; x++ {
			var c color.RGBA
			switch {
			case bpp == 8 && planes == 1:
				c = pal[row[x]]
			case bpp == 8 && planes >= 3:
				// Planar 24-bit: all the reds, then all the greens, then blues.
				c = color.RGBA{row[x], row[bpl+x], row[2*bpl+x], 255}
			case bpp == 1:
				idx := 0
				for p := 0; p < int(planes); p++ {
					bit := row[p*bpl+x/8] >> (7 - uint(x%8)) & 1
					idx |= int(bit) << uint(p)
				}
				if idx < len(pal) {
					c = pal[idx]
				}
			default:
				return nil, fmt.Errorf("PCX layout not supported (%d bits, %d planes)", bpp, planes)
			}
			img.SetRGBA(x, y, c)
		}
	}
	return img, nil
}

// ---- SGI (.rgb / .bw / .sgi) ----

func sgiConfig(data []byte) (int, int, error) {
	if len(data) < 512 || data[0] != 0x01 || data[1] != 0xda {
		return 0, 0, errors.New("not an SGI image")
	}
	return int(be16(data[6:])), int(be16(data[8:])), nil
}

func sgiDecode(data []byte) (image.Image, error) {
	w, h, err := sgiConfig(data)
	if err != nil {
		return nil, err
	}
	if err := checkDims(w, h); err != nil {
		return nil, err
	}
	storage := data[2]
	bpc := int(data[3])
	zsize := int(be16(data[10:]))
	if bpc != 1 && bpc != 2 {
		return nil, fmt.Errorf("SGI bytes-per-channel %d not supported", bpc)
	}
	if zsize < 1 || zsize > 4 {
		return nil, fmt.Errorf("SGI channel count %d not supported", zsize)
	}

	// Channel-major planes, each row stored bottom-up.
	planes := make([][]byte, zsize)
	for z := range planes {
		planes[z] = make([]byte, w*h*bpc)
	}

	if storage == 0 { // verbatim
		need := 512 + w*h*zsize*bpc
		if len(data) < need {
			return nil, errTruncated
		}
		for z := 0; z < zsize; z++ {
			copy(planes[z], data[512+z*w*h*bpc:])
		}
	} else { // RLE, with per-row offset and length tables
		nrows := h * zsize
		tabEnd := 512 + nrows*8
		if len(data) < tabEnd {
			return nil, errTruncated
		}
		for z := 0; z < zsize; z++ {
			for y := 0; y < h; y++ {
				i := z*h + y
				off := int(be32(data[512+i*4:]))
				ln := int(be32(data[512+nrows*4+i*4:]))
				if off < 0 || ln < 0 || off+ln > len(data) {
					return nil, errTruncated
				}
				dst := planes[z][y*w*bpc:]
				if err := sgiUnRLE(data[off:off+ln], dst, bpc); err != nil {
					return nil, err
				}
			}
		}
	}

	img := image.NewNRGBA(image.Rect(0, 0, w, h))
	sample := func(z, x, y int) uint8 {
		p := planes[z]
		if bpc == 1 {
			return p[y*w+x]
		}
		return p[(y*w+x)*2] // take the high byte of 16-bit samples
	}
	for y := 0; y < h; y++ {
		sy := h - 1 - y // SGI rows run bottom-up
		for x := 0; x < w; x++ {
			var c color.NRGBA
			switch zsize {
			case 1:
				v := sample(0, x, sy)
				c = color.NRGBA{v, v, v, 255}
			case 2:
				v := sample(0, x, sy)
				c = color.NRGBA{v, v, v, sample(1, x, sy)}
			case 3:
				c = color.NRGBA{sample(0, x, sy), sample(1, x, sy), sample(2, x, sy), 255}
			case 4:
				c = color.NRGBA{sample(0, x, sy), sample(1, x, sy), sample(2, x, sy), sample(3, x, sy)}
			}
			img.SetNRGBA(x, y, c)
		}
	}
	return img, nil
}

// sgiUnRLE expands one RLE row. The count byte's high bit means "literal run";
// a zero count ends the row.
func sgiUnRLE(src, dst []byte, bpc int) error {
	di := 0
	for i := 0; i < len(src); {
		b := src[i]
		i++
		n := int(b & 0x7f)
		if n == 0 {
			return nil
		}
		if b&0x80 != 0 {
			need := n * bpc
			if i+need > len(src) || di+need > len(dst) {
				return errTruncated
			}
			copy(dst[di:], src[i:i+need])
			di += need
			i += need
		} else {
			if i+bpc > len(src) {
				return errTruncated
			}
			v := src[i : i+bpc]
			i += bpc
			for k := 0; k < n; k++ {
				if di+bpc > len(dst) {
					return errTruncated
				}
				copy(dst[di:], v)
				di += bpc
			}
		}
	}
	return nil
}

// ---- Sun raster (.ras / .sun) ----

func sunrasConfig(data []byte) (int, int, error) {
	if len(data) < 32 || be32(data) != 0x59a66a95 {
		return 0, 0, errors.New("not a Sun raster file")
	}
	return int(be32(data[4:])), int(be32(data[8:])), nil
}

func sunrasDecode(data []byte) (image.Image, error) {
	w, h, err := sunrasConfig(data)
	if err != nil {
		return nil, err
	}
	if err := checkDims(w, h); err != nil {
		return nil, err
	}
	depth := int(be32(data[12:]))
	typ := be32(data[20:])
	mapType := be32(data[24:])
	mapLen := int(be32(data[28:]))
	p := 32
	if p+mapLen > len(data) {
		return nil, errTruncated
	}
	cmapRaw := data[p : p+mapLen]
	p += mapLen

	// Rows are padded to a 16-bit boundary.
	stride := (w*depth + 15) / 16 * 2
	body := data[p:]
	if typ == 2 { // byte-encoded RLE
		body, err = sunrasUnRLE(body, stride*h)
		if err != nil {
			return nil, err
		}
	}
	if len(body) < stride*h {
		return nil, errTruncated
	}

	var pal []color.RGBA
	if mapType == 1 && mapLen >= 3 {
		n := mapLen / 3
		pal = make([]color.RGBA, n)
		for i := 0; i < n; i++ {
			pal[i] = color.RGBA{cmapRaw[i], cmapRaw[n+i], cmapRaw[2*n+i], 255}
		}
	}

	img := image.NewNRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		row := body[y*stride:]
		for x := 0; x < w; x++ {
			var c color.NRGBA
			switch depth {
			case 1:
				bit := row[x/8] >> (7 - uint(x%8)) & 1
				v := uint8(255)
				if bit == 1 {
					v = 0
				}
				c = color.NRGBA{v, v, v, 255}
			case 8:
				if pal != nil && int(row[x]) < len(pal) {
					q := pal[row[x]]
					c = color.NRGBA{q.R, q.G, q.B, 255}
				} else {
					c = color.NRGBA{row[x], row[x], row[x], 255}
				}
			case 24:
				// RT_FORMAT_RGB (type 3) is RGB; everything else is BGR.
				if typ == 3 {
					c = color.NRGBA{row[x*3], row[x*3+1], row[x*3+2], 255}
				} else {
					c = color.NRGBA{row[x*3+2], row[x*3+1], row[x*3], 255}
				}
			case 32:
				if typ == 3 {
					c = color.NRGBA{row[x*4+1], row[x*4+2], row[x*4+3], 255}
				} else {
					c = color.NRGBA{row[x*4+3], row[x*4+2], row[x*4+1], 255}
				}
			default:
				return nil, fmt.Errorf("Sun raster depth %d not supported", depth)
			}
			img.SetNRGBA(x, y, c)
		}
	}
	return img, nil
}

// sunrasUnRLE expands Sun's run encoding: 0x80 is an escape — followed by 0x00
// it means a literal 0x80, otherwise count+1 copies of the next byte.
func sunrasUnRLE(src []byte, want int) ([]byte, error) {
	out := make([]byte, 0, want)
	for i := 0; i < len(src) && len(out) < want; {
		if src[i] != 0x80 {
			out = append(out, src[i])
			i++
			continue
		}
		if i+1 >= len(src) {
			return nil, errTruncated
		}
		n := src[i+1]
		if n == 0 {
			out = append(out, 0x80)
			i += 2
			continue
		}
		if i+2 >= len(src) {
			return nil, errTruncated
		}
		v := src[i+2]
		for k := 0; k <= int(n) && len(out) < want; k++ {
			out = append(out, v)
		}
		i += 3
	}
	if len(out) < want {
		return nil, errTruncated
	}
	return out, nil
}

// ---- ICO / CUR ----

// icoBest picks the entry to decode: the largest by area. A favicon file often
// holds 16×16 through 256×256, and the big one is the only one worth sending.
func icoBest(data []byte) (off, size, w, h int, err error) {
	if len(data) < 6 {
		return 0, 0, 0, 0, errors.New("not an icon file")
	}
	n := int(le16(data[4:]))
	if n == 0 || 6+n*16 > len(data) {
		return 0, 0, 0, 0, errors.New("icon directory is empty or truncated")
	}
	bestArea := -1
	for i := 0; i < n; i++ {
		e := data[6+i*16:]
		ew, eh := int(e[0]), int(e[1])
		if ew == 0 {
			ew = 256 // 0 means 256 in the icon directory
		}
		if eh == 0 {
			eh = 256
		}
		sz := int(le32(e[8:]))
		of := int(le32(e[12:]))
		if of < 0 || sz <= 0 || of+sz > len(data) {
			continue
		}
		if ew*eh > bestArea {
			bestArea, off, size, w, h = ew*eh, of, sz, ew, eh
		}
	}
	if bestArea < 0 {
		return 0, 0, 0, 0, errors.New("no usable icon entry")
	}
	return off, size, w, h, nil
}

func icoConfig(data []byte) (int, int, error) {
	_, _, w, h, err := icoBest(data)
	return w, h, err
}

func icoDecode(data []byte) (image.Image, error) {
	off, size, _, _, err := icoBest(data)
	if err != nil {
		return nil, err
	}
	payload := data[off : off+size]
	// Vista-era icons embed a whole PNG per entry.
	if has(payload, 0, "\x89PNG\r\n\x1a\n") {
		return png.Decode(bytes.NewReader(payload))
	}
	return dibDecode(payload)
}

// dibDecode reads the headerless BMP that classic icon entries contain. Two
// things make it unlike an ordinary BMP: there is no file header (so x/image's
// decoder can't be handed the bytes directly), and the stored height is DOUBLE
// the real one because a 1-bit AND mask follows the colour data.
func dibDecode(b []byte) (image.Image, error) {
	if len(b) < 40 {
		return nil, errors.New("icon bitmap header is truncated")
	}
	hdr := int(le32(b))
	w := int(int32(le32(b[4:])))
	hh := int(int32(le32(b[8:])))
	bpp := int(le16(b[14:]))
	nColors := int(le32(b[32:]))
	h := hh / 2
	// The DIB header stores dimensions as signed 32-bit, so this needs the
	// shared bound and not just a positivity check.
	if err := checkDims(w, h); err != nil {
		return nil, fmt.Errorf("icon bitmap is unusable: %w", err)
	}
	if hdr < 40 || hdr > len(b) {
		return nil, errors.New("icon bitmap header size is bogus")
	}
	p := hdr
	var pal []color.RGBA
	if bpp <= 8 {
		if nColors == 0 {
			nColors = 1 << uint(bpp)
		}
		if p+nColors*4 > len(b) {
			return nil, errTruncated
		}
		pal = make([]color.RGBA, nColors)
		for i := range pal {
			// Palette entries are BGRA with the last byte unused.
			pal[i] = color.RGBA{b[p+i*4+2], b[p+i*4+1], b[p+i*4], 255}
		}
		p += nColors * 4
	}
	stride := (w*bpp + 31) / 32 * 4
	if p+stride*h > len(b) {
		return nil, errTruncated
	}
	xor := b[p : p+stride*h]
	maskStride := (w + 31) / 32 * 4
	var mask []byte
	if p+stride*h+maskStride*h <= len(b) {
		mask = b[p+stride*h:]
	}

	img := image.NewNRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		sy := h - 1 - y // bottom-up, like every BMP
		row := xor[sy*stride:]
		for x := 0; x < w; x++ {
			var c color.NRGBA
			switch bpp {
			case 1, 2, 4, 8:
				var idx int
				switch bpp {
				case 8:
					idx = int(row[x])
				case 4:
					idx = int(row[x/2] >> (4 * (1 - uint(x%2))) & 0x0f)
				case 2:
					idx = int(row[x/4] >> (2 * (3 - uint(x%4))) & 0x03)
				case 1:
					idx = int(row[x/8] >> (7 - uint(x%8)) & 1)
				}
				if idx < len(pal) {
					q := pal[idx]
					c = color.NRGBA{q.R, q.G, q.B, 255}
				}
			case 24:
				c = color.NRGBA{row[x*3+2], row[x*3+1], row[x*3], 255}
			case 32:
				c = color.NRGBA{row[x*4+2], row[x*4+1], row[x*4], row[x*4+3]}
			default:
				return nil, fmt.Errorf("icon colour depth %d not supported", bpp)
			}
			// The AND mask makes pixels transparent. 32-bit icons carry real
			// alpha and usually leave the mask zeroed, so it is only applied
			// where the entry has no alpha channel of its own.
			if mask != nil && bpp != 32 {
				if mask[sy*maskStride+x/8]>>(7-uint(x%8))&1 == 1 {
					c.A = 0
				}
			}
			img.SetNRGBA(x, y, c)
		}
	}
	return img, nil
}
