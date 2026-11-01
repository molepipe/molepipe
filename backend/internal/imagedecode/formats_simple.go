package imagedecode

// Decoders for formats with no Go implementation worth depending on: the Netpbm
// family, farbfeld, QOI, XBM, WBMP and XPM. Each is small enough that a
// dependency would cost more than the code.
//
// Every one of these parses untrusted bytes, so the shared rules are: read the
// dimensions from the header and let the caller's pixel budget pass judgement
// BEFORE allocating; never trust a length field against the actual buffer; and
// return an error rather than a partially-filled image, so a truncated file
// can't look like a successful decode of a mostly-black picture.

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"image"
	"image/color"
	"strconv"
	"strings"
)

var errTruncated = errors.New("file ends in the middle of the image data")

// ---- Netpbm: PBM / PGM / PPM / PAM (P1 - P7) ----

type pnmHeader struct {
	magic   byte // '1'..'7'
	w, h    int
	maxval  int
	depth   int // PAM only: channels
	hdrLen  int // bytes consumed by the header
	pamTupl string
}

// pnmReadHeader parses the textual header shared by the whole family. Netpbm
// allows comments (# to end of line) and arbitrary whitespace ANYWHERE between
// fields, including inside the dimensions block, which is why this is a token
// scanner rather than a Sscanf.
func pnmReadHeader(data []byte) (pnmHeader, error) {
	var h pnmHeader
	if len(data) < 3 || data[0] != 'P' {
		return h, errors.New("not a Netpbm file")
	}
	h.magic = data[1]
	p := 2
	next := func() (string, error) {
		for {
			for p < len(data) && (data[p] == ' ' || data[p] == '\t' || data[p] == '\n' || data[p] == '\r') {
				p++
			}
			if p < len(data) && data[p] == '#' {
				for p < len(data) && data[p] != '\n' {
					p++
				}
				continue
			}
			break
		}
		s := p
		for p < len(data) && !(data[p] == ' ' || data[p] == '\t' || data[p] == '\n' || data[p] == '\r') {
			p++
		}
		if s == p {
			return "", errTruncated
		}
		return string(data[s:p]), nil
	}
	num := func() (int, error) {
		t, err := next()
		if err != nil {
			return 0, err
		}
		v, err := strconv.Atoi(t)
		if err != nil || v < 0 {
			return 0, fmt.Errorf("bad header value %q", t)
		}
		return v, nil
	}

	if h.magic == '7' {
		// PAM: key/value lines, terminated by ENDHDR.
		h.maxval, h.depth = 255, 1
		for {
			k, err := next()
			if err != nil {
				return h, err
			}
			if k == "ENDHDR" {
				break
			}
			v, err := next()
			if err != nil {
				return h, err
			}
			n, _ := strconv.Atoi(v)
			switch k {
			case "WIDTH":
				h.w = n
			case "HEIGHT":
				h.h = n
			case "DEPTH":
				h.depth = n
			case "MAXVAL":
				h.maxval = n
			case "TUPLTYPE":
				h.pamTupl = v
			}
		}
		// A single byte of whitespace ends the header.
		if p < len(data) {
			p++
		}
		h.hdrLen = p
		if h.depth < 1 || h.depth > 4 {
			return h, fmt.Errorf("unsupported PAM depth %d", h.depth)
		}
		return h, nil
	}

	var err error
	if h.w, err = num(); err != nil {
		return h, err
	}
	if h.h, err = num(); err != nil {
		return h, err
	}
	switch h.magic {
	case '1', '4':
		h.maxval = 1
		h.depth = 1
	case '2', '5':
		if h.maxval, err = num(); err != nil {
			return h, err
		}
		h.depth = 1
	case '3', '6':
		if h.maxval, err = num(); err != nil {
			return h, err
		}
		h.depth = 3
	default:
		return h, fmt.Errorf("unknown Netpbm type P%c", h.magic)
	}
	if h.maxval < 1 || h.maxval > 65535 {
		return h, fmt.Errorf("bad Netpbm maxval %d", h.maxval)
	}
	// Exactly one whitespace byte separates a binary header from its raster.
	if p < len(data) {
		p++
	}
	h.hdrLen = p
	return h, nil
}

func pnmConfig(data []byte) (int, int, error) {
	h, err := pnmReadHeader(data)
	if err != nil {
		return 0, 0, err
	}
	return h.w, h.h, nil
}

func pnmDecode(data []byte) (image.Image, error) {
	h, err := pnmReadHeader(data)
	if err != nil {
		return nil, err
	}
	if err := checkDims(h.w, h.h); err != nil {
		return nil, err
	}
	switch h.magic {
	case '1', '2', '3':
		return pnmDecodeASCII(data[h.hdrLen:], h)
	default:
		return pnmDecodeBinary(data[h.hdrLen:], h)
	}
}

// pnmDecodeASCII handles P1/P2/P3, where samples are decimal numbers. P1 is the
// odd one out: its samples need no separator at all, so "0101" is four pixels.
func pnmDecodeASCII(body []byte, h pnmHeader) (image.Image, error) {
	img := image.NewRGBA(image.Rect(0, 0, h.w, h.h))
	sc := bufio.NewScanner(bytes.NewReader(body))
	sc.Split(bufio.ScanWords)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	var toks []string
	for sc.Scan() {
		t := sc.Text()
		if strings.HasPrefix(t, "#") {
			continue
		}
		toks = append(toks, t)
	}
	need := h.w * h.h * h.depth
	var vals []int
	if h.magic == '1' {
		for _, t := range toks {
			for _, c := range t {
				if c == '0' || c == '1' {
					vals = append(vals, int(c-'0'))
				}
			}
		}
	} else {
		for _, t := range toks {
			v, err := strconv.Atoi(t)
			if err != nil {
				continue
			}
			vals = append(vals, v)
		}
	}
	if len(vals) < need {
		return nil, errTruncated
	}
	scale := func(v int) uint8 {
		if v > h.maxval {
			v = h.maxval
		}
		if v < 0 {
			v = 0
		}
		return uint8(v * 255 / h.maxval)
	}
	i := 0
	for y := 0; y < h.h; y++ {
		for x := 0; x < h.w; x++ {
			var r, g, b uint8
			if h.depth == 1 {
				v := scale(vals[i])
				i++
				// In PBM, 1 means BLACK — the opposite of every other format
				// here, and a classic way to get an inverted image.
				if h.magic == '1' {
					v = 255 - v
				}
				r, g, b = v, v, v
			} else {
				r, g, b = scale(vals[i]), scale(vals[i+1]), scale(vals[i+2])
				i += 3
			}
			img.SetRGBA(x, y, color.RGBA{r, g, b, 255})
		}
	}
	return img, nil
}

// pnmDecodeBinary handles P4/P5/P6/P7. Samples are 1, 8 or 16 bits, big-endian,
// with P4 packing eight pixels per byte and padding each ROW to a byte boundary.
func pnmDecodeBinary(body []byte, h pnmHeader) (image.Image, error) {
	img := image.NewRGBA(image.Rect(0, 0, h.w, h.h))
	if h.magic == '4' {
		stride := (h.w + 7) / 8
		if len(body) < stride*h.h {
			return nil, errTruncated
		}
		for y := 0; y < h.h; y++ {
			row := body[y*stride:]
			for x := 0; x < h.w; x++ {
				bit := row[x/8] >> (7 - uint(x%8)) & 1
				v := uint8(255)
				if bit == 1 {
					v = 0 // 1 = black, as in P1
				}
				img.SetRGBA(x, y, color.RGBA{v, v, v, 255})
			}
		}
		return img, nil
	}
	bytesPer := 1
	if h.maxval > 255 {
		bytesPer = 2
	}
	ch := h.depth
	if len(body) < h.w*h.h*ch*bytesPer {
		return nil, errTruncated
	}
	get := func(i int) uint8 {
		var v int
		if bytesPer == 1 {
			v = int(body[i])
		} else {
			v = int(body[2*i])<<8 | int(body[2*i+1])
		}
		if v > h.maxval {
			v = h.maxval
		}
		return uint8(v * 255 / h.maxval)
	}
	i := 0
	for y := 0; y < h.h; y++ {
		for x := 0; x < h.w; x++ {
			var c color.RGBA
			switch ch {
			case 1:
				v := get(i)
				c = color.RGBA{v, v, v, 255}
			case 2: // PAM grayscale + alpha
				v := get(i)
				c = color.RGBA{v, v, v, get(i + 1)}
			case 3:
				c = color.RGBA{get(i), get(i + 1), get(i + 2), 255}
			case 4:
				c = color.RGBA{get(i), get(i + 1), get(i + 2), get(i + 3)}
			}
			i += ch
			img.SetRGBA(x, y, c)
		}
	}
	return img, nil
}

// ---- farbfeld: the simplest image format that exists ----
// "farbfeld" + width + height, both 32-bit big-endian, then 16-bit RGBA rows.

func farbfeldConfig(data []byte) (int, int, error) {
	if len(data) < 16 || !has(data, 0, "farbfeld") {
		return 0, 0, errors.New("not a farbfeld file")
	}
	return int(be32(data[8:])), int(be32(data[12:])), nil
}

func farbfeldDecode(data []byte) (image.Image, error) {
	w, h, err := farbfeldConfig(data)
	if err != nil {
		return nil, err
	}
	if err := checkDims(w, h); err != nil {
		return nil, err
	}
	body := data[16:]
	if len(body) < w*h*8 {
		return nil, errTruncated
	}
	img := image.NewNRGBA64(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			i := (y*w + x) * 8
			img.SetNRGBA64(x, y, color.NRGBA64{
				R: be16(body[i:]), G: be16(body[i+2:]), B: be16(body[i+4:]), A: be16(body[i+6:]),
			})
		}
	}
	return img, nil
}

// ---- QOI: the "Quite OK Image" format ----
// A modern lossless codec built for simplicity: six opcodes, a 64-entry hash
// table of recently seen colours, and no entropy coding at all.

func qoiConfig(data []byte) (int, int, error) {
	if len(data) < 14 || !has(data, 0, "qoif") {
		return 0, 0, errors.New("not a QOI file")
	}
	return int(be32(data[4:])), int(be32(data[8:])), nil
}

func qoiDecode(data []byte) (image.Image, error) {
	w, h, err := qoiConfig(data)
	if err != nil {
		return nil, err
	}
	if err := checkDims(w, h); err != nil {
		return nil, err
	}
	channels := data[12]
	if channels != 3 && channels != 4 {
		return nil, fmt.Errorf("QOI channel count %d is not 3 or 4", channels)
	}
	img := image.NewNRGBA(image.Rect(0, 0, w, h))
	var index [64]color.NRGBA
	px := color.NRGBA{0, 0, 0, 255}
	p := 14
	total := w * h
	for i := 0; i < total; i++ {
		if p >= len(data) {
			return nil, errTruncated
		}
		b := data[p]
		switch {
		case b == 0xfe: // QOI_OP_RGB
			if p+4 > len(data) {
				return nil, errTruncated
			}
			px.R, px.G, px.B = data[p+1], data[p+2], data[p+3]
			p += 4
		case b == 0xff: // QOI_OP_RGBA
			if p+5 > len(data) {
				return nil, errTruncated
			}
			px.R, px.G, px.B, px.A = data[p+1], data[p+2], data[p+3], data[p+4]
			p += 5
		case b>>6 == 0: // QOI_OP_INDEX
			px = index[b&0x3f]
			p++
		case b>>6 == 1: // QOI_OP_DIFF — 2-bit per-channel deltas, biased by 2
			px.R += (b >> 4 & 3) - 2
			px.G += (b >> 2 & 3) - 2
			px.B += (b & 3) - 2
			p++
		case b>>6 == 2: // QOI_OP_LUMA — 6-bit green delta, 4-bit r/b relative to it
			if p+2 > len(data) {
				return nil, errTruncated
			}
			dg := (b & 0x3f) - 32
			rg := data[p+1]
			px.R += dg - 8 + (rg >> 4 & 0xf)
			px.G += dg
			px.B += dg - 8 + (rg & 0xf)
			p += 2
		default: // QOI_OP_RUN — 6-bit length, biased by 1
			run := int(b&0x3f) + 1
			if i+run > total {
				run = total - i
			}
			for k := 0; k < run; k++ {
				idx := i + k
				img.SetNRGBA(idx%w, idx/w, px)
			}
			index[qoiHash(px)] = px
			i += run - 1
			p++
			continue
		}
		index[qoiHash(px)] = px
		img.SetNRGBA(i%w, i/w, px)
	}
	return img, nil
}

func qoiHash(c color.NRGBA) int {
	return (int(c.R)*3 + int(c.G)*5 + int(c.B)*7 + int(c.A)*11) % 64
}

// ---- XBM: X11 bitmap, which is a C source file ----

func xbmParse(data []byte) (w, h int, bits []byte, err error) {
	s := string(data)
	grab := func(suffix string) int {
		i := strings.Index(s, "_"+suffix)
		if i < 0 {
			return 0
		}
		rest := s[i+len(suffix)+1:]
		f := strings.Fields(rest)
		if len(f) == 0 {
			return 0
		}
		v, _ := strconv.Atoi(f[0])
		return v
	}
	w, h = grab("width"), grab("height")
	if w <= 0 || h <= 0 {
		return 0, 0, nil, errors.New("XBM has no usable _width/_height defines")
	}
	open := strings.Index(s, "{")
	if open < 0 {
		return 0, 0, nil, errors.New("XBM has no data block")
	}
	body := s[open+1:]
	if c := strings.Index(body, "}"); c >= 0 {
		body = body[:c]
	}
	for _, t := range strings.Split(body, ",") {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		v, e := strconv.ParseUint(strings.TrimPrefix(strings.TrimPrefix(t, "0x"), "0X"), 16, 16)
		if e != nil {
			continue
		}
		bits = append(bits, byte(v))
	}
	return w, h, bits, nil
}

func xbmConfig(data []byte) (int, int, error) {
	w, h, _, err := xbmParse(data)
	return w, h, err
}

func xbmDecode(data []byte) (image.Image, error) {
	w, h, bits, err := xbmParse(data)
	if err != nil {
		return nil, err
	}
	// The dimensions are decimal text in a #define, so "99999999" is one
	// keystroke away and must not reach an allocation.
	if err := checkDims(w, h); err != nil {
		return nil, err
	}
	stride := (w + 7) / 8
	if len(bits) < stride*h {
		return nil, errTruncated
	}
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			// XBM packs bits LSB-first within each byte, unlike almost
			// everything else.
			on := bits[y*stride+x/8]>>(uint(x%8))&1 == 1
			v := uint8(255)
			if on {
				v = 0
			}
			img.SetRGBA(x, y, color.RGBA{v, v, v, 255})
		}
	}
	return img, nil
}

// ---- WBMP: the WAP-era 1-bit mobile format ----

// wbmpUintvar reads WBMP's variable-length integer: seven bits per byte, high
// bit set on every byte but the last.
func wbmpUintvar(data []byte, p int) (int, int, error) {
	v := 0
	for i := 0; i < 5; i++ {
		if p+i >= len(data) {
			return 0, 0, errTruncated
		}
		b := data[p+i]
		v = v<<7 | int(b&0x7f)
		if b&0x80 == 0 {
			return v, p + i + 1, nil
		}
	}
	return 0, 0, errors.New("WBMP length field is malformed")
}

func wbmpHeader(data []byte) (w, h, off int, err error) {
	if len(data) < 4 || data[0] != 0 {
		return 0, 0, 0, errors.New("not a WBMP type-0 file")
	}
	p := 2 // type byte + fixed header byte
	if w, p, err = wbmpUintvar(data, p); err != nil {
		return 0, 0, 0, err
	}
	if h, p, err = wbmpUintvar(data, p); err != nil {
		return 0, 0, 0, err
	}
	return w, h, p, nil
}

func wbmpConfig(data []byte) (int, int, error) {
	w, h, _, err := wbmpHeader(data)
	return w, h, err
}

func wbmpDecode(data []byte) (image.Image, error) {
	w, h, off, err := wbmpHeader(data)
	if err != nil {
		return nil, err
	}
	if err := checkDims(w, h); err != nil {
		return nil, err
	}
	stride := (w + 7) / 8
	body := data[off:]
	if len(body) < stride*h {
		return nil, errTruncated
	}
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			on := body[y*stride+x/8]>>(7-uint(x%8))&1 == 1
			v := uint8(0)
			if on {
				v = 255 // in WBMP, 1 is white
			}
			img.SetRGBA(x, y, color.RGBA{v, v, v, 255})
		}
	}
	return img, nil
}

// ---- XPM: X11 pixmap, also a C source file ----

func xpmParse(data []byte) (int, int, []string, map[string]color.RGBA, error) {
	// Collect the double-quoted string literals, which is where every XPM keeps
	// all of its actual content.
	var lits []string
	s := data
	for i := 0; i < len(s); i++ {
		if s[i] != '"' {
			continue
		}
		j := i + 1
		for j < len(s) && s[j] != '"' {
			j++
		}
		if j >= len(s) {
			break
		}
		lits = append(lits, string(s[i+1:j]))
		i = j
	}
	if len(lits) == 0 {
		return 0, 0, nil, nil, errors.New("XPM has no string data")
	}
	f := strings.Fields(lits[0])
	if len(f) < 4 {
		return 0, 0, nil, nil, errors.New("XPM header line is malformed")
	}
	w, _ := strconv.Atoi(f[0])
	h, _ := strconv.Atoi(f[1])
	ncolors, _ := strconv.Atoi(f[2])
	cpp, _ := strconv.Atoi(f[3])
	if w <= 0 || h <= 0 || cpp <= 0 || cpp > 4 || ncolors < 0 || ncolors > 1<<16 {
		return 0, 0, nil, nil, fmt.Errorf("XPM header values out of range (%dx%d, %d colours, %d chars/pixel)", w, h, ncolors, cpp)
	}
	if len(lits) < 1+ncolors {
		return 0, 0, nil, nil, errTruncated
	}
	pal := make(map[string]color.RGBA, ncolors)
	for i := 0; i < ncolors; i++ {
		line := lits[1+i]
		if len(line) < cpp {
			continue
		}
		key := line[:cpp]
		pal[key] = xpmColor(line[cpp:])
	}
	return w, h, lits[1+ncolors:], pal, nil
}

// xpmColor reads the colour spec that follows a pixel key. Only the "c" (colour)
// visual is honoured; symbolic, mono and grayscale variants fall through to it.
// A handful of names cover what hand-written XPMs actually use.
func xpmColor(spec string) color.RGBA {
	f := strings.Fields(spec)
	val := ""
	for i := 0; i+1 < len(f); i++ {
		if f[i] == "c" || f[i] == "m" || f[i] == "g" || f[i] == "g4" {
			val = f[i+1]
			if f[i] == "c" {
				break
			}
		}
	}
	if val == "" {
		return color.RGBA{0, 0, 0, 255}
	}
	if strings.EqualFold(val, "none") {
		return color.RGBA{0, 0, 0, 0}
	}
	if strings.HasPrefix(val, "#") {
		hex := val[1:]
		// XPM allows 4, 8 or 12 hex digits per channel group as well as 6.
		per := len(hex) / 3
		if per >= 1 && per*3 == len(hex) {
			comp := func(i int) uint8 {
				v, err := strconv.ParseUint(hex[i*per:(i+1)*per], 16, 32)
				if err != nil {
					return 0
				}
				switch per {
				case 1:
					return uint8(v * 17)
				case 2:
					return uint8(v)
				default:
					return uint8(v >> uint(4*(per-2)))
				}
			}
			return color.RGBA{comp(0), comp(1), comp(2), 255}
		}
	}
	switch strings.ToLower(val) {
	case "black":
		return color.RGBA{0, 0, 0, 255}
	case "white":
		return color.RGBA{255, 255, 255, 255}
	case "red":
		return color.RGBA{255, 0, 0, 255}
	case "green":
		return color.RGBA{0, 128, 0, 255}
	case "blue":
		return color.RGBA{0, 0, 255, 255}
	case "yellow":
		return color.RGBA{255, 255, 0, 255}
	case "cyan":
		return color.RGBA{0, 255, 255, 255}
	case "magenta":
		return color.RGBA{255, 0, 255, 255}
	case "gray", "grey":
		return color.RGBA{190, 190, 190, 255}
	}
	return color.RGBA{0, 0, 0, 255}
}

func xpmConfig(data []byte) (int, int, error) {
	w, h, _, _, err := xpmParse(data)
	return w, h, err
}

func xpmDecode(data []byte) (image.Image, error) {
	w, h, rows, pal, err := xpmParse(data)
	if err != nil {
		return nil, err
	}
	if err := checkDims(w, h); err != nil {
		return nil, err
	}
	if len(rows) < h {
		return nil, errTruncated
	}
	cpp := 0
	for k := range pal {
		cpp = len(k)
		break
	}
	if cpp == 0 {
		cpp = 1
	}
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		row := rows[y]
		for x := 0; x < w; x++ {
			s, e := x*cpp, (x+1)*cpp
			if e > len(row) {
				break
			}
			img.SetRGBA(x, y, pal[row[s:e]])
		}
	}
	return img, nil
}

func be16(b []byte) uint16 { return uint16(b[0])<<8 | uint16(b[1]) }
func be32(b []byte) uint32 {
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}
