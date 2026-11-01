package imagedecode

// Pulling in the x/image decoders registers them with the image package, which
// is what makes stdConfig/stdDecode able to read TIFF, BMP and WebP. They are
// imported here rather than in decode.go so the reason is in one place: these
// are pure-Go decoders, which is the only kind this package may use — see the
// cgo note in the package comment.
//
// What this gets us for free, and would be a lot of work otherwise:
//   TIFF — LZW, Deflate, PackBits and CCITT Group 3/4 compression, which is
//          what fax archives and scanned documents use.
//   BMP  — the uncompressed Windows bitmap, in its many bit depths.
//   WebP — both lossy (VP8) and lossless (VP8L), for desktop builds whose
//          browser engine is older than the format.
import (
	_ "golang.org/x/image/bmp"
	_ "golang.org/x/image/tiff"
	_ "golang.org/x/image/webp"
)
