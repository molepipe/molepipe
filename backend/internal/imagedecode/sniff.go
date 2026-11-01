// Package imagedecode widens the set of image files a user can PICK, without
// widening the set that can travel between peers.
//
// The split matters, so it is stated once here. Two very different things are
// called "supported image type" in this codebase:
//
//   - On the WIRE, exactly four types are legal (protocol.allowedImageMIME:
//     JPEG, PNG, WebP, GIF). That list is a security boundary — an attachment's
//     type is attacker-controlled, so anything a peer sends is restricted at the
//     door. NOTHING in this package may widen it, and nothing a peer sends ever
//     reaches this package: inbound attachments are checked against that
//     allowlist and stored, never decoded.
//
//   - At the PICKER, the user may now choose almost anything a camera or an
//     editor produces. This package turns those bytes into one of the four wire
//     types, so a RAW file off a DSLR becomes an ordinary JPEG before the
//     messaging code ever sees it.
//
// Why decode in Go at all, when the browser decodes JPEG/PNG/GIF/WebP/AVIF/BMP
// for free? Because the formats the browser CANNOT read are exactly the ones
// people have the most trouble sending: iPhone HEIC on desktop, scanner TIFFs,
// Photoshop PSDs, and every camera RAW. Doing it here means Android and desktop
// share one implementation.
//
// Everything is pure Go. There is no cgo here and there must never be: this
// package is compiled into the gomobile AAR, where a C dependency (libraw,
// libheif, ImageMagick) would have to be cross-compiled for every Android ABI.
// That constraint is what shapes the RAW strategy — see raw.go.
package imagedecode

import (
	"bytes"
	"encoding/binary"
)

// Format is a file format this package recognises. The zero value is Unknown.
type Format string

const (
	Unknown Format = ""

	// Formats a browser already decodes. We still recognise them so a pick can
	// be passed through untouched rather than needlessly re-encoded.
	JPEG Format = "jpeg"
	PNG  Format = "png"
	GIF  Format = "gif"
	WEBP Format = "webp"
	BMP  Format = "bmp"
	AVIF Format = "avif"

	// Formats we decode ourselves.
	TIFF     Format = "tiff"
	PSD      Format = "psd"
	ICO      Format = "ico"
	CUR      Format = "cur"
	DDS      Format = "dds"
	QOI      Format = "qoi"
	FARBFELD Format = "farbfeld"
	PNM      Format = "pnm"
	PCX      Format = "pcx"
	SGI      Format = "sgi"
	SUNRAS   Format = "sunras"
	XBM      Format = "xbm"
	XPM      Format = "xpm"
	HDR      Format = "hdr"
	WBMP     Format = "wbmp"
	HEIF     Format = "heif"

	// Camera RAW. One Format per container FAMILY, not per camera brand: what
	// matters for decoding is how the file is laid out, not whose logo is on
	// the camera. See raw.go.
	RawTIFF  Format = "raw-tiff"  // CR2, NEF, ARW, DNG, ORF, RW2, PEF, SRW, …
	RawISO   Format = "raw-iso"   // CR3 and friends (ISO base media container)
	RawFuji  Format = "raw-fuji"  // RAF
	RawSigma Format = "raw-sigma" // X3F
	RawCRW   Format = "raw-crw"   // pre-CR2 Canon (CIFF)
	RawMRW   Format = "raw-mrw"   // Minolta

	// Recognised but NOT decodable here, kept distinct so the user gets "this
	// app can't read JPEG 2000" instead of "unrecognised file".
	JP2 Format = "jp2"
	JXL Format = "jxl"
	EXR Format = "exr"
)

// browserNative lists the formats every supported browser engine decodes on its
// own. A pick in one of these never needs us — the page only calls the decode
// endpoint after its own createImageBitmap has already failed, but knowing the
// format lets us pass the bytes back untouched instead of re-encoding and
// losing quality for nothing.
var browserNative = map[Format]bool{
	JPEG: true, PNG: true, GIF: true, WEBP: true, BMP: true, AVIF: true,
}

// IsBrowserNative reports whether a browser can decode f unaided.
func IsBrowserNative(f Format) bool { return browserNative[f] }

// undecodable maps the formats we can recognise but not read to the reason, so
// the error the user sees names the format and says why. Being specific here is
// the whole point: "Molepipe can't read JPEG XL files" tells someone to export a
// JPEG, where "couldn't read that image" sends them to a bug report.
var undecodable = map[Format]string{
	JP2: "JPEG 2000",
	JXL: "JPEG XL",
	EXR: "OpenEXR",
}

// Sniff identifies data by its CONTENT, never by filename or declared type.
// Both of those are attacker- or accident-controlled: a RAW arrives from a
// share sheet as application/octet-stream, phones rename .heic to .jpg, and a
// peer can claim anything. The bytes are the only honest source.
func Sniff(data []byte) Format {
	if len(data) < 4 {
		return Unknown
	}
	switch {
	case has(data, 0, "\xff\xd8\xff"):
		return JPEG
	case has(data, 0, "\x89PNG\r\n\x1a\n"):
		return PNG
	case has(data, 0, "GIF87a"), has(data, 0, "GIF89a"):
		return GIF
	case has(data, 0, "RIFF") && has(data, 8, "WEBP"):
		return WEBP
	case has(data, 0, "8BPS"):
		return PSD
	case has(data, 0, "DDS "):
		return DDS
	case has(data, 0, "qoif"):
		return QOI
	case has(data, 0, "farbfeld"):
		return FARBFELD
	case has(data, 0, "\x00MRM"):
		return RawMRW
	case has(data, 0, "FUJIFILMCCD-RAW"):
		return RawFuji
	case has(data, 0, "FOVb"):
		return RawSigma
	case has(data, 6, "HEAPCCDR"):
		return RawCRW
	case has(data, 0, "\x01\xda"):
		return SGI
	case has(data, 0, "\x59\xa6\x6a\x95"):
		return SUNRAS
	case has(data, 0, "\x76\x2f\x31\x01"):
		return EXR
	case has(data, 0, "#?RADIANCE"), has(data, 0, "#?RGBE"):
		return HDR
	case has(data, 0, "\xff\x0a"), has(data, 0, "\x00\x00\x00\x0cJXL "):
		return JXL
	case has(data, 0, "\x00\x00\x00\x0cjP  "), has(data, 0, "\x00\x00\x00\x0cjP\x1a\x1a"):
		return JP2
	case has(data, 0, "/* XPM */"):
		return XPM
	case has(data, 0, "#define"):
		return XBM
	case has(data, 0, "BM"):
		return BMP
	}
	// ICO and CUR share a header that differs only in the type word, and both
	// start with two zero bytes — checked after the magic-string formats so a
	// file that merely happens to begin 00 00 cannot steal the match.
	if data[0] == 0 && data[1] == 0 && data[3] == 0 && (data[2] == 1 || data[2] == 2) {
		if data[2] == 1 {
			return ICO
		}
		return CUR
	}
	// Netpbm: "P" then a digit 1..7, then whitespace. The whitespace check
	// keeps "P3DFOO" (not Netpbm) from matching.
	if data[0] == 'P' && data[1] >= '1' && data[1] <= '7' && isPNMSpace(data[2]) {
		return PNM
	}
	// ISO base media (ftyp at offset 4): HEIF/HEIC photos, AVIF, and Canon CR3
	// all live in this container, told apart by the brand.
	if len(data) >= 12 && has(data, 4, "ftyp") {
		switch string(data[8:12]) {
		case "crx ":
			return RawISO
		case "avif", "avis":
			return AVIF
		case "heic", "heix", "hevc", "hevx", "heim", "heis", "mif1", "msf1":
			return HEIF
		}
	}
	// TIFF byte order + magic. This is the gateway to most of the RAW world, so
	// the RAW-vs-plain-TIFF decision is made by looking inside (rawLooksLikeRaw)
	// rather than by extension.
	if f := sniffTIFF(data); f != Unknown {
		return f
	}
	// PCX has no magic string, only a plausible header: manufacturer 0x0A, a
	// known version, and RLE-or-none encoding.
	if data[0] == 0x0a && data[1] <= 5 && data[2] <= 1 && len(data) > 128 {
		return PCX
	}
	// TGA is last and least certain: no signature at all. A v2 file ends with a
	// footer we can trust; otherwise fall back to a header plausibility check,
	// which is why this is the final candidate rather than an early one.
	if looksLikeTGA(data) {
		return TGA
	}
	return Unknown
}

// TGA is declared here rather than in the const block above because it is the
// one format identified by elimination rather than by signature.
const TGA Format = "tga"

// sniffTIFF separates "a TIFF someone scanned" from "a camera RAW that happens
// to use the TIFF container". Most RAW formats ARE TIFFs structurally — the
// difference is that a RAW's main image is undecodable sensor data with a JPEG
// preview alongside, where a plain TIFF's main image is the picture.
func sniffTIFF(data []byte) Format {
	if len(data) < 8 {
		return Unknown
	}
	var order binary.ByteOrder
	switch {
	case has(data, 0, "II"):
		order = binary.LittleEndian
	case has(data, 0, "MM"):
		order = binary.BigEndian
	default:
		return Unknown
	}
	magic := order.Uint16(data[2:4])
	switch magic {
	case 42, 43: // 42 = TIFF, 43 = BigTIFF
	case 0x4f52, 0x5352: // "OR"/"RS" — Olympus ORF
		return RawTIFF
	case 0x0055: // Panasonic RW2
		return RawTIFF
	default:
		return Unknown
	}
	if rawLooksLikeRaw(data, order) {
		return RawTIFF
	}
	return TIFF
}

func has(data []byte, off int, sig string) bool {
	if len(data) < off+len(sig) {
		return false
	}
	return string(data[off:off+len(sig)]) == sig
}

func isPNMSpace(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r' || b == '#'
}

// looksLikeTGA checks the v2 footer first (authoritative) and falls back to a
// header sanity check: a known image type, a colour depth from the real set,
// and non-zero dimensions. Deliberately conservative — a false positive here
// means a confusing decode error on some unrelated file.
func looksLikeTGA(data []byte) bool {
	if len(data) >= 18 && bytes.Equal(data[len(data)-18:len(data)-2], []byte("TRUEVISION-XFILE")) {
		return true
	}
	if len(data) < 18 {
		return false
	}
	switch data[2] { // image type
	case 1, 2, 3, 9, 10, 11:
	default:
		return false
	}
	switch data[16] { // bits per pixel
	case 8, 15, 16, 24, 32:
	default:
		return false
	}
	w := binary.LittleEndian.Uint16(data[12:14])
	h := binary.LittleEndian.Uint16(data[14:16])
	return w > 0 && h > 0
}
