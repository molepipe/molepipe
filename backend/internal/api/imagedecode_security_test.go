package api

// The whole image-format feature rests on one boundary: the set of types a USER
// may pick is now enormous, while the set a PEER may send is still exactly four.
// These tests assert that boundary instead of trusting the comments that
// describe it.
//
// Written in the enumerate-the-surfaces style rather than the test-the-helper
// style: asserting that AllowedImageMIME returns false for "image/x-canon-cr2"
// proves nothing about whether some handler bypassed it.

import (
	"bytes"
	"go/parser"
	"go/token"
	"image"
	"image/color"
	"image/jpeg"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/molepipe/molepipe/backend/internal/imagedecode"
	"github.com/molepipe/molepipe/backend/internal/protocol"
)

// TestWireAllowlistIsStillExactlyFourTypes pins the list itself. Widening it is
// a security decision — an attachment's type is attacker-controlled, and any
// endpoint echoing a stored type as Content-Type would then be a vector — so
// this test exists to make such a change deliberate and reviewed, never a side
// effect of adding picker support for a new format.
func TestWireAllowlistIsStillExactlyFourTypes(t *testing.T) {
	allowed := []string{"image/jpeg", "image/png", "image/webp", "image/gif"}
	for _, m := range allowed {
		if !protocol.AllowedImageMIME(m) {
			t.Fatalf("%s is no longer wire-legal, but the send path depends on it", m)
		}
	}
	// Every format the picker gained must stay OUT of the wire allowlist: these
	// travel as the JPEG or PNG they were converted into, never as themselves.
	for _, m := range []string{
		"image/tiff", "image/x-tiff", "image/vnd.adobe.photoshop", "image/x-photoshop",
		"image/x-canon-cr2", "image/x-canon-cr3", "image/x-nikon-nef", "image/x-sony-arw",
		"image/x-adobe-dng", "image/x-panasonic-rw2", "image/x-olympus-orf",
		"image/x-fuji-raf", "image/x-sigma-x3f", "image/x-minolta-mrw",
		"image/heic", "image/heif", "image/avif", "image/jxl", "image/jp2",
		"image/x-targa", "image/x-tga", "image/x-portable-pixmap", "image/x-pcx",
		"image/x-dds", "image/vnd-ms.dds", "image/x-qoi", "image/vnd.radiance",
		"image/x-xbitmap", "image/x-xpixmap", "image/x-sgi", "image/x-cmu-raster",
		"image/vnd.wap.wbmp", "image/x-icon", "image/vnd.microsoft.icon",
		"image/bmp", "image/x-ms-bmp",
		// And the classics this allowlist exists to stop.
		"text/html", "image/svg+xml", "application/octet-stream", "",
	} {
		if protocol.AllowedImageMIME(m) {
			t.Fatalf("%q became wire-legal — the picker's format support must NOT widen "+
				"what a peer can send", m)
		}
	}
}

// TestDecoderOnlyEverProducesWireLegalTypes is the property that lets the send
// path stay unchanged: whatever goes into the decoder, what comes out is
// something a peer is already allowed to receive.
func TestDecoderOnlyEverProducesWireLegalTypes(t *testing.T) {
	for _, tc := range []struct {
		name string
		data []byte
	}{
		{"netpbm", pnmFixture()},
		{"farbfeld opaque", farbfeldFixture(255)},
		{"farbfeld transparent", farbfeldFixture(0)},
		{"jpeg passthrough", jpegFixture(t)},
		{"raw preview", rawFixture(t)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res, err := imagedecode.Decode(tc.data, imagedecode.Options{})
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			if !protocol.AllowedImageMIME(res.Mime) {
				t.Fatalf("decoder produced %q, which a peer may not receive", res.Mime)
			}
		})
	}
}

// TestOnlyTheDecodeEndpointImportsTheDecoder is the reachability assertion.
//
// A behavioural test cannot prove a negative here — there is no input that
// makes an inbound attachment "try" to decode — so this reads the source
// instead: the wire layer and the storage layer must not import imagedecode at
// all, and inside the api package only the decode endpoint may. If someone
// later calls imagedecode from attachment.go (to generate a thumbnail of a
// received image, say) this fails, and that is the point: it would put a
// hand-written parser in the path of attacker-controlled bytes, which is
// exactly what the four-type allowlist was built to avoid.
func TestOnlyTheDecodeEndpointImportsTheDecoder(t *testing.T) {
	const decoderPkg = "github.com/molepipe/molepipe/backend/internal/imagedecode"
	// Files in internal/api that are allowed to import it.
	allowedInAPI := map[string]bool{
		"imagedecode.go":               true,
		"imagedecode_security_test.go": true,
		"imagedecode_test.go":          true,
	}

	check := func(dir string, allow map[string]bool) {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("read %s: %v", dir, err)
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") {
				continue
			}
			path := filepath.Join(dir, e.Name())
			f, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
			if err != nil {
				t.Fatalf("parse %s: %v", path, err)
			}
			for _, imp := range f.Imports {
				if strings.Trim(imp.Path.Value, `"`) != decoderPkg {
					continue
				}
				if allow == nil {
					t.Errorf("%s imports the image decoder. The wire and storage layers "+
						"handle peer-controlled bytes and must never decode them — that is "+
						"what the four-type allowlist protects.", path)
				} else if !allow[e.Name()] {
					t.Errorf("%s imports the image decoder. Only the decode endpoint may: "+
						"it handles files the USER picked, never anything a peer sent.", path)
				}
			}
		}
	}
	check("../protocol", nil)
	check("../chatstore", nil)
	check(".", allowedInAPI)
}

// TestDecodeEndpointIsGuardedLikeEveryOtherControlEndpoint: unauthenticated or
// cross-origin requests must not reach the decoder at all. Without this, a page
// the user has open in another tab could feed files to a parser.
func TestDecodeEndpointIsGuardedLikeEveryOtherControlEndpoint(t *testing.T) {
	s, tok := unlocked(t)
	body := string(pnmFixture())

	t.Run("no auth", func(t *testing.T) {
		rr := s.do(t, "POST", "/api/image/decode", body, map[string]string{"Origin": s.origin()})
		if rr.Code == http.StatusOK {
			t.Fatal("decoded a file for an unauthenticated request")
		}
	})
	t.Run("wrong origin", func(t *testing.T) {
		h := authHdr(s, tok)
		h["Origin"] = "http://evil.example"
		rr := s.do(t, "POST", "/api/image/decode", body, h)
		if rr.Code == http.StatusOK {
			t.Fatal("decoded a file for a cross-origin request")
		}
	})
	t.Run("authenticated and same-origin", func(t *testing.T) {
		h := authHdr(s, tok)
		h["Origin"] = s.origin()
		rr := s.do(t, "POST", "/api/image/decode", body, h)
		if rr.Code != http.StatusOK {
			t.Fatalf("a legitimate request was refused: %d %s", rr.Code, rr.Body.String())
		}
		if ct := rr.Header().Get("Content-Type"); !protocol.AllowedImageMIME(ct) {
			t.Fatalf("Content-Type %q is not a wire-legal image type", ct)
		}
		if rr.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Fatal("the response is missing nosniff, so a browser could sniff its way to another type")
		}
	})
}

// TestDecodeEndpointReportsWhatItDid: the page shows the user whether their RAW
// became a camera preview, so the metadata headers have to be populated.
func TestDecodeEndpointReportsWhatItDid(t *testing.T) {
	s, tok := unlocked(t)
	h := authHdr(s, tok)
	h["Origin"] = s.origin()
	rr := s.do(t, "POST", "/api/image/decode", string(rawFixture(t)), h)
	if rr.Code != http.StatusOK {
		t.Fatalf("decode: %d %s", rr.Code, rr.Body.String())
	}
	if got := rr.Header().Get("X-Image-Format"); got != "raw-tiff" {
		t.Fatalf("X-Image-Format = %q, want raw-tiff", got)
	}
	if note := rr.Header().Get("X-Image-Note"); !strings.Contains(note, "preview") {
		t.Fatalf("X-Image-Note = %q, want it to mention the extracted preview", note)
	}
	if rr.Header().Get("X-Image-Width") == "" || rr.Header().Get("X-Image-Height") == "" {
		t.Fatal("the dimension headers are empty, so the page cannot size the result")
	}
	// The bytes themselves, not just the labels on them: the page feeds this
	// response straight to createImageBitmap, so a truncated or mis-typed body
	// would surface there as "Couldn't read that image" with the decoder
	// apparently having succeeded.
	cfg, format, err := image.DecodeConfig(bytes.NewReader(rr.Body.Bytes()))
	if err != nil {
		t.Fatalf("the response body does not decode as an image: %v", err)
	}
	if format != "jpeg" {
		t.Fatalf("body decoded as %q, but Content-Type said %q", format, rr.Header().Get("Content-Type"))
	}
	if got := strconv.Itoa(cfg.Width); got != rr.Header().Get("X-Image-Width") {
		t.Fatalf("X-Image-Width = %q but the image is %d wide", rr.Header().Get("X-Image-Width"), cfg.Width)
	}
	if got := strconv.Itoa(cfg.Height); got != rr.Header().Get("X-Image-Height") {
		t.Fatalf("X-Image-Height = %q but the image is %d high", rr.Header().Get("X-Image-Height"), cfg.Height)
	}
}

// TestDecodeEndpointRefusesEmptyAndUnreadableInput: the two cases the page can
// hit by accident, which must be clean 4xx answers rather than 500s.
func TestDecodeEndpointRefusesEmptyAndUnreadableInput(t *testing.T) {
	s, tok := unlocked(t)
	h := authHdr(s, tok)
	h["Origin"] = s.origin()

	if rr := s.do(t, "POST", "/api/image/decode", "", h); rr.Code != http.StatusBadRequest {
		t.Fatalf("empty body: %d, want 400", rr.Code)
	}
	rr := s.do(t, "POST", "/api/image/decode", "this is not an image at all, it is prose", h)
	if rr.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("garbage body: %d, want 415", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "image") {
		t.Fatalf("the error does not mention images: %s", rr.Body.String())
	}
}

// ---- fixtures ----

func pnmFixture() []byte {
	var buf bytes.Buffer
	buf.WriteString("P6\n2 2\n255\n")
	buf.Write([]byte{255, 0, 0, 0, 255, 0, 0, 0, 255, 255, 255, 255})
	return buf.Bytes()
}

func farbfeldFixture(alpha byte) []byte {
	var buf bytes.Buffer
	buf.WriteString("farbfeld")
	buf.Write([]byte{0, 0, 0, 2, 0, 0, 0, 1})
	buf.Write([]byte{0xff, 0xff, 0, 0, 0, 0, alpha, alpha})
	buf.Write([]byte{0, 0, 0xff, 0xff, 0, 0, 0xff, 0xff})
	return buf.Bytes()
}

func jpegFixture(t *testing.T) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, 8, 8))
	for i := 0; i < 8; i++ {
		img.SetRGBA(i, i, color.RGBA{255, 0, 0, 255})
	}
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, img, nil); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// rawFixture builds a minimal TIFF-container RAW: a CFA photometric tag marks
// it as sensor data, and a JPEG preview sits in the blob area where the scan
// will find it.
func rawFixture(t *testing.T) []byte {
	t.Helper()
	jpg := jpegFixture(t)
	hdr := make([]byte, 8+2+12+4)
	copy(hdr, "II")
	hdr[2], hdr[3] = 42, 0
	hdr[4] = 8
	hdr[8] = 1 // one entry
	// Tag 0x0106 (PhotometricInterpretation) = 32803 (CFA).
	hdr[10], hdr[11] = 0x06, 0x01
	hdr[12], hdr[13] = 3, 0 // SHORT
	hdr[14] = 1
	hdr[18], hdr[19] = 0x23, 0x80 // 32803, little-endian
	return append(hdr, jpg...)
}

// TestDecodeEndpointOutlivesTheDefaultReadTimeout: the control server reads
// with a 30s timeout, which is right for a JSON control call and wrong for a
// 200 MB file coming off a phone's SD card. Without the per-request extension
// the connection is dropped mid-upload and the page shows "couldn't read that
// image" for a file that was perfectly fine — the worst kind of failure to
// debug, because nothing is wrong with the image. Run against a real server
// with a deliberately tiny timeout and a body that arrives slowly, since this
// behaviour does not exist at all in a ResponseRecorder.
func TestDecodeEndpointOutlivesTheDefaultReadTimeout(t *testing.T) {
	s, _ := unlocked(t)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.handleDecodeImage(w, r, nil)
	}))
	// Two orders of magnitude tighter than production, so a body that trickles
	// for a second is the same shape of problem as a 200 MB upload against 30s.
	srv.Config.ReadTimeout = 250 * time.Millisecond
	srv.Config.WriteTimeout = 250 * time.Millisecond
	srv.Start()
	defer srv.Close()

	fixture := rawFixture(t)
	// Chunked, with a stall in the middle: the first bytes arrive at once, the
	// rest only after the server's own ReadTimeout would have fired.
	body, pw := io.Pipe()
	go func() {
		defer pw.Close()
		_, _ = pw.Write(fixture[:len(fixture)/2])
		time.Sleep(600 * time.Millisecond)
		_, _ = pw.Write(fixture[len(fixture)/2:])
	}()
	req, err := http.NewRequest("POST", srv.URL+"/api/image/decode", body)
	if err != nil {
		t.Fatal(err)
	}
	res, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("the slow upload was dropped instead of being allowed to finish: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("decode: %d", res.StatusCode)
	}
	got, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("reading the response: %v", err)
	}
	if _, _, err := image.DecodeConfig(bytes.NewReader(got)); err != nil {
		t.Fatalf("the response body does not decode as an image: %v", err)
	}
}
