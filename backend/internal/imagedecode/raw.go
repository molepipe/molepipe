package imagedecode

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"image/jpeg"
	"sort"
)

// Camera RAW, and why this file is short.
//
// A RAW file is not a picture. It is undemosaiced sensor data — one colour per
// photosite, in a proprietary compression, needing a per-camera colour matrix
// and a debayer pass to become an image. Writing that from scratch means
// reimplementing dcraw/LibRaw: hundreds of camera-specific quirks, and no way
// to be CORRECT for a camera nobody here owns. In cgo-free Go, compiled for
// four platforms, it is not a weekend.
//
// It is also the wrong thing to do. Every RAW file a camera writes carries one
// or more embedded JPEG previews — that is how the camera shows you the shot on
// its own screen, and how every fast image browser renders RAW thumbnails. The
// preview is usually full-resolution or close to it, already demosaiced by the
// camera's own processor (so the colour is what the photographer saw), and a
// couple of megabytes rather than eighty.
//
// So: we extract the preview instead of developing the RAW. That single
// decision is what makes "support every RAW format" tractable, because the
// preview lives in one of a handful of places regardless of brand:
//
//   1. A TIFF/EXIF tag pointing at a JPEG — covers CR2, NEF, NRW, ARW, SR2,
//      DNG, ORF, RW2, PEF, SRW, ERF, 3FR, FFF, IIQ, RWL, DCR, KDC, MOS and
//      every other TIFF-container RAW, in ONE code path.
//   2. Failing that, anywhere in the file at all — found by scanning for
//      well-formed JPEG streams and keeping the largest. This catches the
//      non-TIFF containers (RAF, X3F, CRW, MRW, CR3) without a bespoke parser
//      for each, and rescues TIFF-container files whose tags we misread.
//
// The honest limitation, stated here and in the user-facing changelog: what
// gets sent is the camera's JPEG rendering, not a RAW development. Nobody is
// doing exposure recovery inside a chat app — and the alternative was refusing
// the file.

// maxPreviewScan bounds the brute-force scan. A RAW can be 150 MB; without a
// ceiling a malformed file could have us validating JPEG candidates all day.
const maxPreviewCandidates = 256

// maxIFDDepth bounds SubIFD recursion. Real files nest two or three deep; a
// malicious one can claim to nest forever.
const maxIFDDepth = 8

// maxIFDEntries bounds one directory. The largest real IFD is a few dozen tags.
const maxIFDEntries = 512

// TIFF tags we care about. Everything else in a 400-tag spec is irrelevant to
// finding a preview.
const (
	tagNewSubfileType    = 0x00fe
	tagImageWidth        = 0x0100
	tagImageLength       = 0x0101
	tagCompression       = 0x0103
	tagPhotometric       = 0x0106
	tagStripOffsets      = 0x0111
	tagStripByteCounts   = 0x0117
	tagJPEGIFOffset      = 0x0201
	tagJPEGIFByteCount   = 0x0202
	tagSubIFDs           = 0x014a
	tagExifIFD           = 0x8769
	tagDNGVersion        = 0xc612
	tagDNGPrivateData    = 0xc634
	photometricCFA       = 32803
	photometricLinearRaw = 34892
)

// rawCompressions are compression codes that mean "this strip is sensor data,
// not a picture". Their presence is strong evidence of a RAW. Note that 7
// (JPEG) is deliberately ABSENT: a JPEG-compressed TIFF is an ordinary TIFF,
// and treating it as RAW would send its thumbnail instead of the image.
var rawCompressions = map[uint32]bool{
	6:     true, // "old-style JPEG" — what Canon CR2 uses for the RAW strips
	34713: true, // Nikon NEF
	34892: true, // lossy DNG
	32767: true, // Sony ARW
	65000: true, // Kodak DCR
	65535: true, // Panasonic / Pentax variants
}

// rawLooksLikeRaw decides whether a TIFF-container file is a camera RAW rather
// than a scanned or exported TIFF. It only answers yes on STRONG evidence,
// because the two answers fail differently: calling a RAW a TIFF just means we
// try the TIFF decoder first and fall back (harmless), while calling a TIFF a
// RAW would send its small embedded thumbnail in place of the real image.
func rawLooksLikeRaw(data []byte, order binary.ByteOrder) bool {
	// Canon CR2 says so in its header: "CR" plus a version byte at offset 8.
	if has(data, 8, "CR") {
		return true
	}
	found := false
	walkIFDs(data, order, func(e ifdEntry, _ int) bool {
		switch e.tag {
		case tagDNGVersion, tagDNGPrivateData:
			found = true
		case tagPhotometric:
			if v, ok := e.uint(order, data); ok && (v == photometricCFA || v == photometricLinearRaw) {
				found = true
			}
		case tagCompression:
			if v, ok := e.uint(order, data); ok && rawCompressions[v] {
				found = true
			}
		}
		return !found // stop walking as soon as we know
	})
	return found
}

// ifdEntry is one TIFF directory entry, kept as raw field values so a caller
// can interpret it without a second parse.
type ifdEntry struct {
	tag    uint16
	typ    uint16
	count  uint32
	valOff uint32 // the 4 value bytes, read as an offset when the value doesn't fit inline
	inline [4]byte
}

// typeSize is the byte width of each TIFF field type (index = type code).
var typeSize = [...]uint32{0, 1, 1, 2, 4, 8, 1, 1, 2, 4, 8, 4, 8}

// uint reads a single numeric value from an entry, whatever integer width the
// file chose to store it in. Returns false for non-numeric or multi-valued
// entries, so callers never silently read a pointer as a number.
func (e ifdEntry) uint(order binary.ByteOrder, data []byte) (uint32, bool) {
	if e.count != 1 {
		return 0, false
	}
	switch e.typ {
	case 1: // BYTE
		return uint32(e.inline[0]), true
	case 3: // SHORT
		return uint32(order.Uint16(e.inline[:2])), true
	case 4: // LONG
		return order.Uint32(e.inline[:]), true
	}
	return 0, false
}

// uints reads every value of a numeric entry, following the offset when the
// values don't fit in the entry's four inline bytes. Bounded by maxIFDEntries
// so a count of four billion can't make us allocate.
func (e ifdEntry) uints(order binary.ByteOrder, data []byte) []uint32 {
	if int(e.typ) >= len(typeSize) || typeSize[e.typ] == 0 {
		return nil
	}
	w := typeSize[e.typ]
	if e.typ != 1 && e.typ != 3 && e.typ != 4 {
		return nil
	}
	n := e.count
	if n == 0 || n > maxIFDEntries {
		return nil
	}
	var src []byte
	if w*n <= 4 {
		src = e.inline[:]
	} else {
		off := order.Uint32(e.inline[:])
		if uint64(off)+uint64(w*n) > uint64(len(data)) {
			return nil
		}
		src = data[off : uint64(off)+uint64(w*n)]
	}
	out := make([]uint32, 0, n)
	for i := uint32(0); i < n; i++ {
		b := src[i*w:]
		switch e.typ {
		case 1:
			out = append(out, uint32(b[0]))
		case 3:
			out = append(out, uint32(order.Uint16(b)))
		case 4:
			out = append(out, order.Uint32(b))
		}
	}
	return out
}

// walkIFDs visits every entry of every directory reachable from the TIFF
// header: the IFD chain, the Exif IFD, and SubIFDs (where DNG and NEF keep
// their full-size previews), depth-first. fn returns false to stop the walk.
//
// Hardened deliberately, because this parses attacker-shaped input in the same
// process that holds the onion service: every offset is bounds-checked, every
// directory already visited is skipped (a self-referential IFD chain is a
// one-line infinite loop otherwise), recursion is depth-capped, and entry
// counts are capped.
func walkIFDs(data []byte, order binary.ByteOrder, fn func(ifdEntry, int) bool) {
	if len(data) < 8 {
		return
	}
	visited := map[uint32]bool{}
	var walk func(off uint32, depth int) bool
	walk = func(off uint32, depth int) bool {
		for off != 0 {
			if depth > maxIFDDepth || visited[off] || uint64(off)+2 > uint64(len(data)) {
				return true
			}
			visited[off] = true
			n := uint32(order.Uint16(data[off : off+2]))
			if n > maxIFDEntries {
				n = maxIFDEntries
			}
			base := uint64(off) + 2
			if base+uint64(n)*12+4 > uint64(len(data)) {
				// Truncated directory: read the entries that are fully present
				// rather than abandoning the file, since a RAW's preview often
				// sits in an earlier IFD than the damaged one.
				if base+12 > uint64(len(data)) {
					return true
				}
				n = uint32((uint64(len(data)) - base) / 12)
			}
			var subs []uint32
			for i := uint32(0); i < n; i++ {
				p := base + uint64(i)*12
				var e ifdEntry
				e.tag = order.Uint16(data[p : p+2])
				e.typ = order.Uint16(data[p+2 : p+4])
				e.count = order.Uint32(data[p+4 : p+8])
				copy(e.inline[:], data[p+8:p+12])
				e.valOff = order.Uint32(data[p+8 : p+12])
				if !fn(e, depth) {
					return false
				}
				switch e.tag {
				case tagSubIFDs, tagExifIFD:
					subs = append(subs, e.uints(order, data)...)
				}
			}
			for _, s := range subs {
				if !walk(s, depth+1) {
					return false
				}
			}
			nextAt := base + uint64(n)*12
			if nextAt+4 > uint64(len(data)) {
				return true
			}
			off = order.Uint32(data[nextAt : nextAt+4])
		}
		return true
	}
	walk(order.Uint32(data[4:8]), 0)
}

// jpegCandidate is one embedded JPEG found in a container, with the dimensions
// read from its own SOF header.
type jpegCandidate struct {
	off, size int
	w, h      int
}

// extractEmbeddedJPEG returns the best embedded JPEG preview in a RAW (or any
// container), largest by PIXEL AREA. Area, not byte count: a 6000×4000 preview
// saved at middling quality can be smaller on disk than a 160×120 thumbnail
// stored uncompressed-ish, and sending the thumbnail would be the single most
// annoying possible outcome of this feature.
//
// Tag-directed lookup runs first because it is exact; the whole-file scan runs
// when tags yield nothing, or yield something small.
func extractEmbeddedJPEG(data []byte) ([]byte, int, int, error) {
	var cands []jpegCandidate

	// Pass 1: follow the tags, when this is a TIFF-shaped file.
	if order, ok := tiffOrder(data); ok {
		var pairs []jpegCandidate
		walkIFDs(data, order, func(e ifdEntry, _ int) bool {
			if len(pairs) > maxPreviewCandidates {
				return false
			}
			switch e.tag {
			case tagJPEGIFOffset, tagStripOffsets:
				if offs := e.uints(order, data); len(offs) == 1 {
					pairs = append(pairs, jpegCandidate{off: int(offs[0])})
				}
			}
			return true
		})
		for _, p := range pairs {
			if c, ok := validateJPEGAt(data, p.off); ok {
				cands = append(cands, c)
			}
		}
	}

	// Pass 2: scan, always. The tags are a hint, not an inventory — a RAW's
	// IFD0 thumbnail is often the only tagged JPEG while the full-size preview
	// sits in a MakerNote we do not parse, and a camera that tags a half-size
	// preview can still have a better one further in. Scanning unconditionally
	// is what makes "the largest preview in the file" true rather than "the
	// largest one that happened to be described". What makes it safe on a file
	// whose sensor data is itself a JPEG stream is the decode check below —
	// validateJPEGAt's frame-type filter only gets the mosaic out of the way
	// earlier. Bounded by maxPreviewCandidates, and each accepted stream is
	// skipped whole, so the cost is one pass of SOI searching.
	for off := 0; off+3 < len(data) && len(cands) < maxPreviewCandidates; {
		i := indexSOI(data[off:])
		if i < 0 {
			break
		}
		at := off + i
		if c, ok := validateJPEGAt(data, at); ok {
			cands = append(cands, c)
			// Skip past this whole stream: the EXIF block of a large
			// preview contains its own small thumbnail, and we have no use
			// for candidates we already know are smaller.
			off = at + c.size
			continue
		}
		off = at + 2
	}

	// Largest first, and the first one that genuinely decodes wins. The header
	// walk above proves the stream is well-formed and of a readable frame type,
	// not that the decoder will accept its contents — a 12-bit preview, which
	// some cameras do write, parses cleanly here and is then refused by every
	// 8-bit JPEG decoder there is. Trying the next-largest instead of failing
	// means such a file still sends the next preview down.
	for _, c := range byAreaDesc(cands) {
		jpg := data[c.off : c.off+c.size]
		// No checkDims here, unlike every decoder that goes through decodeWith.
		// It would be unreachable: a JPEG carries its dimensions in two 16-bit
		// fields, so no stream can declare more than 65535 a side, which is
		// already inside MaxSide. Nothing is allocated per-pixel on this path
		// either — the bytes are handed over as they were found — so the
		// decode check below is the whole guarantee this path needs.
		cfg, err := jpeg.DecodeConfig(bytes.NewReader(jpg))
		if err == nil {
			// Returned byte-for-byte. It is already a JPEG and already the
			// four-type wire allowlist's first entry, so re-encoding would only
			// lose quality and burn phone battery. Dimensions come from the
			// decoder rather than our own walk so the numbers reported to the
			// page are the ones it will actually see.
			return jpg, cfg.Width, cfg.Height, nil
		}
	}
	return nil, 0, 0, errors.New("no embedded preview found")
}

// byAreaDesc orders candidates largest-pixel-area first, breaking ties on the
// bigger byte count (the same stream tagged twice differs only in trailing
// padding; the longer one is the complete copy).
func byAreaDesc(cands []jpegCandidate) []jpegCandidate {
	out := make([]jpegCandidate, len(cands))
	copy(out, cands)
	sort.SliceStable(out, func(i, j int) bool {
		ai, aj := out[i].w*out[i].h, out[j].w*out[j].h
		if ai != aj {
			return ai > aj
		}
		return out[i].size > out[j].size
	})
	return out
}

func tiffOrder(data []byte) (binary.ByteOrder, bool) {
	if len(data) < 8 {
		return nil, false
	}
	switch {
	case has(data, 0, "II"):
		return binary.LittleEndian, true
	case has(data, 0, "MM"):
		return binary.BigEndian, true
	}
	return nil, false
}

// indexSOI finds the next JPEG start-of-image. A JPEG begins FF D8 FF: the
// third byte is the first marker's 0xFF prefix, and requiring it rejects most
// of the FF D8 pairs that occur naturally in compressed sensor data.
func indexSOI(b []byte) int {
	for i := 0; i+2 < len(b); i++ {
		if b[i] == 0xff && b[i+1] == 0xd8 && b[i+2] == 0xff {
			return i
		}
	}
	return -1
}

// validateJPEGAt walks the JPEG segment structure from off to prove there is a
// real, complete stream there and to read its dimensions. Walking the segments
// is what separates this from a hopeful "search for FF D9": inside entropy-coded
// scan data a literal 0xFF is byte-stuffed as FF 00, so segment walking gives an
// exact end offset, and a candidate that doesn't parse is discarded instead of
// being sent as a corrupt image.
func validateJPEGAt(data []byte, off int) (jpegCandidate, bool) {
	if off < 0 || off+4 > len(data) || data[off] != 0xff || data[off+1] != 0xd8 {
		return jpegCandidate{}, false
	}
	var w, h int
	p := off + 2
	for p+1 < len(data) {
		if data[p] != 0xff {
			return jpegCandidate{}, false
		}
		// Padding: a run of FFs before a marker is legal.
		for p+1 < len(data) && data[p+1] == 0xff {
			p++
		}
		if p+1 >= len(data) {
			return jpegCandidate{}, false
		}
		m := data[p+1]
		p += 2
		switch {
		case m == 0xd9: // EOI — a complete stream
			if w == 0 || h == 0 {
				return jpegCandidate{}, false
			}
			return jpegCandidate{off: off, size: p - off, w: w, h: h}, true
		case m == 0x01 || (m >= 0xd0 && m <= 0xd7): // TEM, RSTn: no payload
			continue
		case m == 0xda: // SOS — skip the entropy-coded data to the next marker
			if p+2 > len(data) {
				return jpegCandidate{}, false
			}
			ln := int(binary.BigEndian.Uint16(data[p : p+2]))
			if ln < 2 || p+ln > len(data) {
				return jpegCandidate{}, false
			}
			p += ln
			for p+1 < len(data) {
				if data[p] == 0xff && data[p+1] != 0x00 && !(data[p+1] >= 0xd0 && data[p+1] <= 0xd7) {
					break
				}
				p++
			}
		default:
			if p+2 > len(data) {
				return jpegCandidate{}, false
			}
			ln := int(binary.BigEndian.Uint16(data[p : p+2]))
			if ln < 2 || p+ln > len(data) {
				return jpegCandidate{}, false
			}
			// A frame header carries the real dimensions — but only three of
			// the fifteen frame types are a JPEG anything downstream can read:
			// baseline, extended sequential and progressive. The others are
			// lossless, differential or arithmetic-coded, and that is exactly
			// how CR2, DNG and NEF store the undemosaiced sensor data. Such a
			// stream is full sensor resolution, so it outranks every real
			// preview on pixel count, and nothing — not Chromium, not Go's own
			// decoder — can open it. Rejecting the whole candidate here is the
			// cheap early-out that keeps the mosaic out of the running on a file
			// whose raw data is itself a JPEG stream; the decode check in
			// extractEmbeddedJPEG is what actually guarantees it never ships.
			// (0xc4 DHT, 0xc8 JPG and 0xcc DAC are not frame headers at all and
			// fall through to the plain skip.)
			switch m {
			case 0xc0, 0xc1, 0xc2: // SOF0, SOF1, SOF2
				if ln >= 7 && p+7 <= len(data) {
					h = int(binary.BigEndian.Uint16(data[p+3 : p+5]))
					w = int(binary.BigEndian.Uint16(data[p+5 : p+7]))
				}
			case 0xc3, 0xc5, 0xc6, 0xc7, 0xc9, 0xca, 0xcb, 0xcd, 0xce, 0xcf:
				return jpegCandidate{}, false
			}
			p += ln
		}
	}
	return jpegCandidate{}, false
}

// decodeRawPreview is the entry point for every RAW family. There is one
// implementation because the answer is the same for all of them: find the
// camera's own JPEG. The Format argument only shapes the error message.
func decodeRawPreview(data []byte, f Format) (Result, error) {
	jpg, w, h, err := extractEmbeddedJPEG(data)
	if err != nil {
		return Result{}, fmt.Errorf("%s: no embedded JPEG preview to extract — this RAW "+
			"would need full RAW development, which Molepipe does not do", rawFamilyName(f))
	}
	return Result{
		Data:   jpg,
		Mime:   "image/jpeg",
		Format: string(f),
		Width:  w,
		Height: h,
		Note:   "camera preview extracted from " + rawFamilyName(f),
	}, nil
}

func rawFamilyName(f Format) string {
	switch f {
	case RawTIFF:
		return "camera RAW"
	case RawISO:
		return "Canon CR3"
	case RawFuji:
		return "Fujifilm RAF"
	case RawSigma:
		return "Sigma X3F"
	case RawCRW:
		return "Canon CRW"
	case RawMRW:
		return "Minolta MRW"
	}
	return "camera RAW"
}
