package api

import (
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"github.com/molepipe/molepipe/backend/internal/identity"
	"github.com/molepipe/molepipe/backend/internal/imagedecode"
	"github.com/molepipe/molepipe/backend/internal/protocol"
)

// imageDecodeDeadline bounds one decode request end to end. Kept in step with
// IMAGE_DECODE_TIMEOUT_MS in public/app.js, which is the page's side of the
// same number.
const imageDecodeDeadline = 3 * time.Minute

// POST /api/image/decode — convert a file the browser cannot read into one it
// can, so the picker accepts far more formats than the wire does.
//
// Where this sits in the security model, because it is the one place the
// backend touches image PIXELS at all:
//
//   - It only ever sees a file the USER picked on their own device, handed
//     straight from the file input or the Android share sheet. Nothing a peer
//     sends can reach it: an inbound attachment is checked against
//     protocol.AllowedImageMIME and stored as opaque bytes, and no code path
//     leads from there to here. (api/imagedecode_security_test.go asserts
//     that, rather than trusting this comment.)
//   - It cannot widen the wire allowlist. The response type is chosen by
//     imagedecode from a fixed set, never echoed from the request, and the
//     send handlers re-check it independently afterwards.
//   - It is auth'd and origin-guarded like every other control endpoint, so a
//     web page the user happens to have open cannot post files into it.
//
// The body is the raw file, NOT base64 JSON: a 90 MB RAW would become ~120 MB
// of JSON string, and both sides would hold it in memory at once.
func (s *Server) handleDecodeImage(w http.ResponseWriter, r *http.Request, _ *identity.Identity) {
	// The server's own timeouts are sized for small control requests (30s to
	// read, 60s to write). This is the only endpoint whose body is a file —
	// MaxInputBytes allows a couple of hundred megabytes — streamed out of a
	// phone's storage through a content provider, and whose work then continues
	// for a while after the last byte arrives: a full decode and re-encode of a
	// large PSD is not instant. On the defaults a big file has its connection
	// dropped mid-upload, which reaches the page as the generic "couldn't read
	// that image" and makes MaxInputBytes a promise the read window cannot
	// keep. Extended per-request so every other endpoint keeps its tight
	// bounds, and matched to the page's own fetch timeout so neither side waits
	// on a connection the other has given up on. Best-effort by design: a
	// connection that cannot carry a deadline just keeps the server default.
	rc := http.NewResponseController(w)
	_ = rc.SetReadDeadline(time.Now().Add(imageDecodeDeadline))
	_ = rc.SetWriteDeadline(time.Now().Add(imageDecodeDeadline))

	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, imagedecode.MaxInputBytes))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "couldn't read that file — it may be larger than this app can open",
		})
		return
	}
	if len(data) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "no file was sent"})
		return
	}

	// maxDim is advisory and comes from the page, which knows what it needs the
	// result for (sending vs. cropping an avatar). Bounded here so a typo in
	// the query string can't ask for a 2-billion-pixel intermediate.
	opt := imagedecode.Options{}
	if v := r.URL.Query().Get("max_dim"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= imagedecode.DefaultMaxDim {
			opt.MaxDim = n
		}
	}

	res, err := imagedecode.Decode(data, opt)
	if err != nil {
		// The message is deliberately passed through: imagedecode writes these
		// for a human ("JPEG XL files can't be read on this device — export the
		// photo as JPEG"), and flattening them to "couldn't read that image"
		// would throw away the only actionable part.
		writeJSON(w, http.StatusUnsupportedMediaType, map[string]string{"error": err.Error()})
		return
	}
	// Belt and braces: the decoder is supposed to return only wire-legal types,
	// so if it ever did not, that is a bug to fail on rather than to serve.
	if !protocol.AllowedImageMIME(res.Mime) {
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": fmt.Sprintf("internal: decoder produced %q, which is not an allowed image type", res.Mime),
		})
		return
	}

	w.Header().Set("Content-Type", res.Mime)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")
	// Metadata for the UI: which format the file turned out to be, and whether
	// the bytes are a camera preview rather than a full decode, so the page can
	// tell the user what actually happened to their RAW.
	w.Header().Set("X-Image-Format", res.Format)
	w.Header().Set("X-Image-Note", res.Note)
	w.Header().Set("X-Image-Width", strconv.Itoa(res.Width))
	w.Header().Set("X-Image-Height", strconv.Itoa(res.Height))
	w.Header().Set("Content-Length", strconv.Itoa(len(res.Data)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(res.Data)
}
