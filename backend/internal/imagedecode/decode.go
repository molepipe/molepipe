package imagedecode

import (
	"bytes"
	"errors"
	"fmt"
	"image"
	"image/color"
	"image/draw"
	"image/jpeg"
	"image/png"

	_ "image/gif"  // registered so a GIF pick is recognised by the stdlib path too
	_ "image/jpeg" // ditto JPEG
	_ "image/png"  // ditto PNG

	xdraw "golang.org/x/image/draw"
)

// MaxInputBytes bounds what the decode endpoint will read. It is deliberately
// MUCH larger than protocol.MaxAttachmentBytes (3 MiB) and that is not an
// inconsistency: this is a LOCAL file the user picked on their own device, and a
// medium-format RAW is routinely 120 MB. The 3 MiB cap applies to what leaves
// the device, which is the re-encoded JPEG — so the wire bound is untouched by
// anything here.
const MaxInputBytes = 256 << 20 // 256 MiB

// MaxPixels is the decompression-bomb guard: 80 megapixels is beyond any
// consumer camera (a 100 MP medium-format back is ~11600×8700 = 101 MP, which
// this refuses — its embedded preview path is unaffected, since that is a
// straight byte copy with no decode).
//
// This guard matters more here than in an ordinary app. The decoder runs inside
// the same process as the Tor onion service, so an out-of-memory kill does not
// just lose the image: it drops the onion, and republishing it costs minutes of
// the user's time. A 20000×20000 PNG is 1.6 GB as RGBA. So the dimensions are
// checked from the header BEFORE any pixel buffer is allocated.
const MaxPixels = 80 << 20

// DefaultMaxDim is the longest side of what we hand back to the page. The page
// downscales to 1600 for sending anyway; going through an intermediate much
// larger than that just moves bytes around, and going smaller would throw away
// detail the avatar cropper wants.
const DefaultMaxDim = 4096

// MaxSide bounds a SINGLE dimension, and it exists to make the MaxPixels check
// above trustworthy rather than to limit anything a user would notice. Several
// of these formats store dimensions as 32-bit values, so a header claiming
// 4294967295x4294967295 makes w*h overflow to a NEGATIVE number — and a
// negative area sails straight past "is the area too large?", which is how a
// pixel-budget guard ends up guarding nothing. (Found by FuzzDecode, not by
// reading: a farbfeld header with huge dimensions panicked inside
// image.NewNRGBA64 having passed every check.)
//
// With both sides bounded here, every width*height*bytesPerPixel product in
// this package stays well inside int64, so the arithmetic downstream is safe
// without each decoder repeating the analysis.
const MaxSide = 1 << 16

// checkDims is the guard every decoder calls before it allocates anything.
func checkDims(w, h int) error {
	if w <= 0 || h <= 0 {
		return fmt.Errorf("image reports empty dimensions (%dx%d)", w, h)
	}
	if w > MaxSide || h > MaxSide {
		return fmt.Errorf("image dimensions are implausible (%dx%d; limit %d per side)", w, h, MaxSide)
	}
	return nil
}

// Result is a decoded image in a form a browser can render.
type Result struct {
	Data   []byte // JPEG, PNG, WebP or GIF bytes
	Mime   string // one of the four wire-legal image types
	Format string // the format we read it FROM, for the UI to mention
	Width  int
	Height int
	Note   string // human-readable detail, e.g. that a RAW preview was extracted
}

// Options tunes a decode. The zero value is the sane default.
type Options struct {
	MaxDim    int // longest side of the output; 0 = DefaultMaxDim
	MaxPixels int // 0 = MaxPixels
}

func (o Options) maxDim() int {
	if o.MaxDim > 0 {
		return o.MaxDim
	}
	return DefaultMaxDim
}

func (o Options) maxPixels() int {
	if o.MaxPixels > 0 {
		return o.MaxPixels
	}
	return MaxPixels
}

// ErrUnsupported is returned for input we cannot turn into an image. Its
// message always names the format when we recognised one, because "Molepipe
// can't read JPEG XL" is actionable where "couldn't read that image" is not.
var ErrUnsupported = errors.New("unsupported image format")

// decoder pairs a cheap header read with the full decode, so the pixel budget
// can be enforced before any large allocation happens.
type decoder struct {
	config func([]byte) (int, int, error)
	decode func([]byte) (image.Image, error)
}

// decoders are the formats this package reads itself. The browser-native four
// and the RAW families are handled separately in Decode.
var decoders = map[Format]decoder{
	TIFF:     {stdConfig, stdDecode},
	BMP:      {stdConfig, stdDecode},
	PNM:      {pnmConfig, pnmDecode},
	TGA:      {tgaConfig, tgaDecode},
	QOI:      {qoiConfig, qoiDecode},
	FARBFELD: {farbfeldConfig, farbfeldDecode},
	ICO:      {icoConfig, icoDecode},
	CUR:      {icoConfig, icoDecode},
	PCX:      {pcxConfig, pcxDecode},
	SGI:      {sgiConfig, sgiDecode},
	SUNRAS:   {sunrasConfig, sunrasDecode},
	PSD:      {psdConfig, psdDecode},
	DDS:      {ddsConfig, ddsDecode},
	HDR:      {hdrConfig, hdrDecode},
	XBM:      {xbmConfig, xbmDecode},
	WBMP:     {wbmpConfig, wbmpDecode},
	XPM:      {xpmConfig, xpmDecode},
}

// Decode turns arbitrary image bytes into something a browser can render.
//
// The three outcomes, in the order they are tried:
//
//  1. Already browser-readable (JPEG/PNG/GIF/WebP/AVIF) — returned untouched.
//     Re-encoding would lose quality to no purpose, and the caller only reached
//     us because its own decode failed for some OTHER reason (a .heic named
//     .jpg, say), so handing the bytes back lets it retry honestly.
//  2. Camera RAW — the camera's embedded JPEG preview, byte-for-byte. No
//     decode, no re-encode, no pixel budget needed. See raw.go.
//  3. Anything else we can read — decoded, downscaled to fit MaxDim, and
//     re-encoded as PNG when it has transparency or JPEG when it does not.
func Decode(data []byte, opt Options) (Result, error) {
	if len(data) == 0 {
		return Result{}, errors.New("empty file")
	}
	if len(data) > MaxInputBytes {
		return Result{}, fmt.Errorf("file is too large to read (%d MiB; limit %d MiB)",
			len(data)>>20, MaxInputBytes>>20)
	}
	f := Sniff(data)
	if f == Unknown {
		return Result{}, fmt.Errorf("%w: unrecognised file — it does not look like an image", ErrUnsupported)
	}
	if why, bad := undecodable[f]; bad {
		return Result{}, fmt.Errorf("%w: %s files can't be read on this device — "+
			"export the photo as JPEG, PNG or WebP and try again", ErrUnsupported, why)
	}

	if IsBrowserNative(f) {
		mime := mimeFor(f)
		w, h, _ := stdConfig(data) // best-effort; AVIF has no stdlib config
		return Result{Data: data, Mime: mime, Format: string(f), Width: w, Height: h,
			Note: "passed through unchanged"}, nil
	}

	switch f {
	case RawTIFF, RawISO, RawFuji, RawSigma, RawCRW, RawMRW:
		res, err := decodeRawPreview(data, f)
		if err == nil {
			return res, nil
		}
		// A file we classified as RAW but whose preview we could not find may
		// simply be a TIFF we misjudged, so give the real decoder a turn before
		// giving up. This is the safety net that makes the RAW-vs-TIFF guess in
		// sniffTIFF non-critical.
		if res2, err2 := decodeWith(decoders[TIFF], data, TIFF, opt); err2 == nil {
			return res2, nil
		}
		return Result{}, fmt.Errorf("%w: %s", ErrUnsupported, err)

	case HEIF:
		// HEIC/HEIF is HEVC-coded. There is no pure-Go HEVC intra decoder, and
		// adding libheif would mean cgo in the gomobile build — the one thing
		// this package may not do. On Android it never gets here: MainActivity
		// transcodes HEIC through the platform ImageDecoder before the page sees
		// it. On desktop, some HEICs carry a JPEG preview we can lift.
		if jpg, w, h, err := extractEmbeddedJPEG(data); err == nil {
			return Result{Data: jpg, Mime: "image/jpeg", Format: string(f), Width: w, Height: h,
				Note: "preview extracted from HEIF (the full-resolution image needs HEVC)"}, nil
		}
		return Result{}, fmt.Errorf("%w: HEIC/HEIF photos can't be read on the desktop app — "+
			"they work when sent from the Android app, or export as JPEG first", ErrUnsupported)
	}

	d, ok := decoders[f]
	if !ok {
		return Result{}, fmt.Errorf("%w: %s files are recognised but not supported", ErrUnsupported, f)
	}
	res, err := decodeWith(d, data, f, opt)
	if err == nil {
		return res, nil
	}
	// Last resort for container formats: a TIFF whose compression x/image does
	// not implement (old-style JPEG, some CCITT variants) very often still has
	// a usable JPEG inside it.
	if jpg, w, h, err2 := extractEmbeddedJPEG(data); err2 == nil {
		return Result{Data: jpg, Mime: "image/jpeg", Format: string(f), Width: w, Height: h,
			Note: "embedded preview used — the main image uses a compression this app can't read"}, nil
	}
	return Result{}, err
}

// decodeWith runs one decoder under the pixel budget and re-encodes the result.
func decodeWith(d decoder, data []byte, f Format, opt Options) (Result, error) {
	if d.config == nil {
		return Result{}, fmt.Errorf("%w: %s", ErrUnsupported, f)
	}
	w, h, err := d.config(data)
	if err != nil {
		return Result{}, fmt.Errorf("that %s file looks damaged: %w", f, err)
	}
	if err := checkDims(w, h); err != nil {
		return Result{}, fmt.Errorf("that %s file is unusable: %w", f, err)
	}
	// The guard, before any pixel buffer exists. int64 because the whole point
	// is to be immune to the overflow that checkDims has just ruled out — a
	// belt-and-braces pair, since this is the check that keeps an OOM from
	// taking the onion service down with it.
	if int64(w)*int64(h) > int64(opt.maxPixels()) {
		return Result{}, fmt.Errorf("that image is too big to open safely (%dx%d = %d megapixels; limit %d)",
			w, h, w*h/(1<<20), opt.maxPixels()/(1<<20))
	}
	img, err := d.decode(data)
	if err != nil {
		return Result{}, fmt.Errorf("couldn't read that %s file: %w", f, err)
	}
	// Only the TIFF container carries an Orientation tag that its decoder
	// ignores. Doing this unconditionally would be wrong: a JPEG never reaches
	// here, and running the IFD walk over a PSD or a DDS would at best waste
	// time and at worst find a number that means something else.
	if f == TIFF {
		img = applyOrientation(img, orientationOf(data))
	}
	return encode(img, string(f), opt)
}

// encode downscales to fit and picks the output format by whether the image
// actually uses transparency. PNG for transparent images (JPEG has no alpha and
// would fill it with black); JPEG for everything else, because a photographic
// PNG is many times larger for no visible gain.
func encode(img image.Image, format string, opt Options) (Result, error) {
	img = fit(img, opt.maxDim())
	b := img.Bounds()
	var buf bytes.Buffer
	mime := "image/jpeg"
	if hasAlpha(img) {
		mime = "image/png"
		if err := png.Encode(&buf, img); err != nil {
			return Result{}, err
		}
	} else if err := jpeg.Encode(&buf, img, &jpeg.Options{Quality: 92}); err != nil {
		return Result{}, err
	}
	return Result{Data: buf.Bytes(), Mime: mime, Format: format,
		Width: b.Dx(), Height: b.Dy(), Note: "converted to " + mime}, nil
}

// fit scales img down so its longest side is at most maxDim, using
// ApproxBiLinear — good enough for an intermediate the page will downscale
// again, and far cheaper than CatmullRom on a 50 MP scan.
func fit(img image.Image, maxDim int) image.Image {
	b := img.Bounds()
	long := b.Dx()
	if b.Dy() > long {
		long = b.Dy()
	}
	if long <= maxDim || long == 0 {
		return img
	}
	w := b.Dx() * maxDim / long
	h := b.Dy() * maxDim / long
	if w < 1 {
		w = 1
	}
	if h < 1 {
		h = 1
	}
	dst := image.NewRGBA(image.Rect(0, 0, w, h))
	xdraw.ApproxBiLinear.Scale(dst, dst.Bounds(), img, b, draw.Src, nil)
	return dst
}

// hasAlpha reports whether any pixel is actually non-opaque. The Opaque()
// fast path covers the common cases; the scan exists because an RGBA image is
// frequently fully opaque in practice (every PNG screenshot without
// transparency), and sending those as PNG would multiply their size.
func hasAlpha(img image.Image) bool {
	type opaquer interface{ Opaque() bool }
	if o, ok := img.(opaquer); ok {
		return !o.Opaque()
	}
	b := img.Bounds()
	for y := b.Min.Y; y < b.Max.Y; y++ {
		for x := b.Min.X; x < b.Max.X; x++ {
			if _, _, _, a := img.At(x, y).RGBA(); a != 0xffff {
				return true
			}
		}
	}
	return false
}

func mimeFor(f Format) string {
	switch f {
	case JPEG:
		return "image/jpeg"
	case PNG:
		return "image/png"
	case GIF:
		return "image/gif"
	case WEBP:
		return "image/webp"
	case BMP:
		return "image/bmp"
	case AVIF:
		return "image/avif"
	}
	return "application/octet-stream"
}

// stdConfig / stdDecode go through the image package's registry, which the
// imports at the top of this file and in formats_x.go populate (stdlib JPEG,
// PNG, GIF; x/image BMP, TIFF, WebP).
func stdConfig(data []byte) (int, int, error) {
	cfg, _, err := image.DecodeConfig(bytes.NewReader(data))
	if err != nil {
		return 0, 0, err
	}
	return cfg.Width, cfg.Height, nil
}

func stdDecode(data []byte) (image.Image, error) {
	img, _, err := image.Decode(bytes.NewReader(data))
	return img, err
}

// ---- EXIF orientation ----
//
// Browsers honour the EXIF Orientation tag when they decode a JPEG themselves
// (verified: createImageBitmap reports a 120x60 image with orientation 6 as
// 60x120, and "none" is no longer even a valid value for that option). So two
// of our three paths need nothing: a passed-through JPEG and an extracted RAW
// preview both keep their EXIF and get rotated by the browser.
//
// x/image/tiff does NOT do this. A scan or a phone photo saved as TIFF carries
// the same tag and would come back on its side, which matters precisely because
// the files people cannot open elsewhere are the ones they send here.

// orientationOf reads the EXIF/TIFF Orientation tag, returning 1 (no change)
// when it is absent or out of range. Only the first value found is used: a
// camera writes it once, and a file with several is not worth guessing about.
func orientationOf(data []byte) int {
	order, ok := tiffOrder(data)
	if !ok {
		return 1
	}
	o := 1
	walkIFDs(data, order, func(e ifdEntry, _ int) bool {
		if e.tag != tagOrientation {
			return true
		}
		if v, ok := e.uint(order, data); ok && v >= 1 && v <= 8 {
			o = int(v)
			return false
		}
		return true
	})
	return o
}

// applyOrientation rotates and flips img into its upright form. The eight cases
// are the EXIF spec's, and all eight are implemented because the mirrored ones
// (2, 4, 5, 7) show up in scans and in photos that have been through an editor,
// where getting them wrong produces a mirror image rather than an obvious
// sideways one — the harder error to notice.
func applyOrientation(img image.Image, o int) image.Image {
	if o <= 1 || o > 8 {
		return img
	}
	b := img.Bounds()
	w, h := b.Dx(), b.Dy()
	swap := o >= 5 // orientations 5-8 exchange the axes
	ow, oh := w, h
	if swap {
		ow, oh = h, w
	}
	dst := image.NewNRGBA(image.Rect(0, 0, ow, oh))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			var dx, dy int
			switch o {
			case 2: // mirrored horizontally
				dx, dy = w-1-x, y
			case 3: // rotated 180°
				dx, dy = w-1-x, h-1-y
			case 4: // mirrored vertically
				dx, dy = x, h-1-y
			case 5: // mirrored along the main diagonal
				dx, dy = y, x
			case 6: // rotated 90° clockwise
				dx, dy = h-1-y, x
			case 7: // mirrored along the anti-diagonal
				dx, dy = h-1-y, w-1-x
			case 8: // rotated 90° counter-clockwise
				dx, dy = y, w-1-x
			}
			r, g, bl, a := img.At(b.Min.X+x, b.Min.Y+y).RGBA()
			dst.SetNRGBA(dx, dy, color.NRGBA{uint8(r >> 8), uint8(g >> 8), uint8(bl >> 8), uint8(a >> 8)})
		}
	}
	return dst
}

const tagOrientation = 0x0112
