package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	qrcode "github.com/skip2/go-qrcode"

	"github.com/molepipe/molepipe/backend/internal/chatstore"
	"github.com/molepipe/molepipe/backend/internal/device"
	"github.com/molepipe/molepipe/backend/internal/identity"
	"github.com/molepipe/molepipe/backend/internal/protocol"
)

const (
	syncStartDelay = 20 * time.Second
	syncInterval   = 60 * time.Second
	syncOpTimeout  = 90 * time.Second
)

// --- control API: pairing ---

// handlePairStart runs on the existing (primary) device: it mints a short-lived
// single-use secret and returns a pairing code + QR for the new device to scan.
func (s *Server) handlePairStart(w http.ResponseWriter, r *http.Request, id *identity.Identity) {
	d := s.currentDevice()
	if d == nil || !d.IsPrimary() {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "start linking from your primary device"})
		return
	}
	secret := s.pairSecrets.issue()
	code := id.AccountNumber() + ":" + base64.RawURLEncoding.EncodeToString(secret)
	png, err := qrcode.Encode("onionchat-pair:"+code, qrcode.Medium, 256)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"code": code, "qr": base64.StdEncoding.EncodeToString(png)})
}

// handlePairLink runs on the NEW device: it becomes a secondary (so it won't
// collide with the primary's onion), enrolls itself against the existing device
// using the scanned code, then pulls the history snapshot.
func (s *Server) handlePairLink(w http.ResponseWriter, r *http.Request, id *identity.Identity) {
	var req struct {
		Code       string `json:"code"`
		DeviceName string `json:"device_name"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<12)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	account, secret, err := parsePairCode(req.Code)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid pairing code"})
		return
	}
	if account != id.AccountNumber() {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "that code is for a different account"})
		return
	}
	if s.onion == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "Tor is disabled"})
		return
	}

	// Enrol and sync FIRST, while Tor is still up. Demoting used to happen here
	// and called stopOnion(), which kills Arti — and Arti is also the SOCKS
	// proxy this request needs to reach the primary, so pairing failed instantly
	// every time with "SOCKS proxy not available". Demotion happens after, once
	// there is nothing left to dial.
	ctx, cancel := context.WithTimeout(r.Context(), syncOpTimeout)
	defer cancel()
	d := s.currentDevice()
	if err := protocol.PairEnroll(ctx, s.onion.Dialer(), id, d.PublicKey(), clampDeviceName(req.DeviceName), secret); err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "could not reach your other device — is it online and showing the code? (" + err.Error() + ")"})
		return
	}
	if err := s.syncOnce(ctx, id); err != nil {
		// Enrollment succeeded; the background loop will retry the snapshot pull.
		log.Printf("initial sync after link: %v", err)
	}

	// Now stop publishing the account onion, and come back up as a client so
	// this device keeps a transport for sending and syncing.
	d.Role = device.RoleSecondary
	if err := device.Save(s.store.Dir, d); err != nil {
		log.Printf("save device role: %v", err)
	}
	// This device is now a secondary, so startOnion runs as a dial-out client and
	// ignores the key; derive it anyway (cheap, never fails for a live identity)
	// so the call site stays uniform with the primary paths.
	if onionKey, err := onionKeyFor(id); err != nil {
		log.Printf("derive onion key after link: %v", err)
	} else if err := s.startOnion(onionKey); err != nil {
		log.Printf("restart tor as client after link: %v", err)
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "linked"})
}

// handlePairLinkSetup is the combined recovery + pairing flow for a fresh
// install. It accepts the pairing code, recovery phrase, and a new password in
// one step: recovers the identity, saves it, links to the primary, and returns
// a session token — no separate create/recover/unlock steps needed.
func (s *Server) handlePairLinkSetup(w http.ResponseWriter, r *http.Request) {
	if s.store.Exists() {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "an identity already exists on this device — use Link from the settings screen instead"})
		return
	}
	var req struct {
		Code       string `json:"code"`
		Mnemonic   string `json:"mnemonic"`
		Password   string `json:"password"`
		DeviceName string `json:"device_name"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if err := validatePassword(req.Password); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	account, secret, err := parsePairCode(req.Code)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid pairing code"})
		return
	}
	id, err := identity.FromMnemonic(strings.TrimSpace(req.Mnemonic), "")
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid recovery phrase"})
		return
	}
	if account != id.AccountNumber() {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "that pairing code is for a different account"})
		return
	}
	if err := s.store.Save(id, []byte(req.Password)); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	// Set up as secondary — a linking device never publishes the onion.
	if d := s.currentDevice(); d != nil {
		d.Role = device.RoleSecondary
		if err := device.Save(s.store.Dir, d); err != nil {
			log.Printf("save device role after link-setup: %v", err)
		}
	}
	// Start session so the pairing dial can use Tor.
	token, err := s.vault.unlock(id)
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	s.startSession(id)
	onionKey, _ := onionKeyFor(id)
	s.ready.Add(1)
	go func() {
		defer s.ready.Done()
		s.startOnion(onionKey)
	}()
	// Wait briefly for Tor to become dialable, then link.
	if err := s.awaitDialable(30 * time.Second); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "Tor did not start in time — please try again"})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), syncOpTimeout)
	defer cancel()
	d := s.currentDevice()
	if err := protocol.PairEnroll(ctx, s.onion.Dialer(), id, d.PublicKey(), clampDeviceName(req.DeviceName), secret); err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "could not reach your other device — is it online and showing the code? (" + err.Error() + ")"})
		return
	}
	if err := s.syncOnce(ctx, id); err != nil {
		log.Printf("initial sync after link-setup: %v", err)
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"account_number": id.AccountNumber(),
		"session_token":  token,
	})
}

// awaitDialable polls until the onion service is dialable or the timeout expires.

func (s *Server) handlePairChallenge(w http.ResponseWriter, r *http.Request) {
	if s.currentPeer() == nil {
		http.Error(w, "locked", http.StatusServiceUnavailable)
		return
	}
	writeJSON(w, http.StatusOK, map[string][]byte{"nonce": s.syncNonces.issue()})
}

func (s *Server) handlePairEnroll(w http.ResponseWriter, r *http.Request) {
	if s.currentPeer() == nil {
		http.Error(w, "locked", http.StatusServiceUnavailable)
		return
	}
	var req struct {
		DevicePub  []byte `json:"device_pub"`
		DeviceName string `json:"device_name"`
		Secret     []byte `json:"secret"`
		Nonce      []byte `json:"nonce"`
		IDSig      []byte `json:"id_sig"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<12)).Decode(&req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	// nonce (replay) → identity key → pairing secret. The pairing secret is
	// consumed LAST so a failed identity check doesn't burn a legitimate secret.
	if !s.syncNonces.consume(req.Nonce) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	s.sessMu.Lock()
	account := s.myAccount
	s.sessMu.Unlock()
	if err := protocol.PairVerify(account, req.Nonce, req.DevicePub, req.IDSig); err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if !s.pairSecrets.consume(req.Secret) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	s.sessMu.Lock()
	enrolled := false
	for _, d := range s.devices {
		if bytes.Equal(d.PubKey, req.DevicePub) {
			enrolled = true
			break
		}
	}
	if !enrolled {
		s.devices = append(s.devices, chatstore.Device{PubKey: req.DevicePub, Name: clampDeviceName(req.DeviceName), AddedAt: time.Now()})
		s.persistLocked()
	}
	s.sessMu.Unlock()
	writeJSON(w, http.StatusOK, map[string]string{"status": "enrolled"})
}

// --- control API: device management ---

func (s *Server) handleListDevices(w http.ResponseWriter, r *http.Request, _ *identity.Identity) {
	self := []byte(nil)
	role := string(device.RolePrimary)
	if d := s.currentDevice(); d != nil {
		self = d.PublicKey()
		role = string(d.Role)
	}
	s.sessMu.Lock()
	out := make([]map[string]any, 0, len(s.devices))
	for _, d := range s.devices {
		out = append(out, map[string]any{
			"name":     d.Name,
			"added_at": d.AddedAt,
			"is_self":  bytes.Equal(d.PubKey, self),
		})
	}
	s.sessMu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"devices": out, "role": role})
}

// handleMakePrimary promotes this device to primary (it starts publishing the
// account onion). The user is responsible for demoting any other primary first;
// two primaries would collide.
func (s *Server) handleMakePrimary(w http.ResponseWriter, r *http.Request, id *identity.Identity) {
	d := s.currentDevice()
	if d == nil {
		http.Error(w, "no device config", http.StatusInternalServerError)
		return
	}
	d.Role = device.RolePrimary
	if err := device.Save(s.store.Dir, d); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	if onionKey, err := onionKeyFor(id); err != nil {
		log.Printf("derive onion key after promote: %v", err)
	} else if err := s.startOnion(onionKey); err != nil {
		log.Printf("start onion after promote: %v", err)
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "primary"})
}

// awaitDialable polls until the onion service is dialable or the timeout expires.
func (s *Server) awaitDialable(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if s.onion != nil && s.onion.Dialable() {
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("timed out waiting for Tor")
}

// --- sync loop (runs on secondaries) ---

// syncLoop periodically syncs from the primary. It only acts while this device is
// a secondary — the primary is the passive hub that secondaries dial.
func (s *Server) syncLoop(ctx context.Context, id *identity.Identity) {
	t := time.NewTimer(syncStartDelay)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if d := s.currentDevice(); d != nil && !d.IsPrimary() {
				if err := s.syncOnce(ctx, id); err != nil {
					log.Printf("sync: %v", err)
				}
				// After the metadata merge, backfill any image blobs this device
				// is missing (and push ones the primary asked for). Separate round
				// trip: image bytes are far too large to ride the state exchange.
				if err := s.attachmentSyncOnce(ctx, id); err != nil {
					log.Printf("attachment sync: %v", err)
				}
			}
			t.Reset(syncInterval)
		}
	}
}

// syncOnce does one sync round trip with the primary and adopts the merged state.
func (s *Server) syncOnce(ctx context.Context, id *identity.Identity) error {
	d := s.currentDevice()
	if s.onion == nil || d == nil {
		return nil
	}
	cctx, cancel := context.WithTimeout(ctx, syncOpTimeout)
	defer cancel()

	s.sessMu.Lock()
	state, err := json.Marshal(s.snapshotLocked())
	s.sessMu.Unlock()
	if err != nil {
		return err
	}
	mergedJSON, err := protocol.SyncExchange(cctx, s.onion.Dialer(), id, d.PublicKey(), d.Sign, state)
	if err != nil {
		return err
	}
	var remote chatstore.Data
	if err := json.Unmarshal(mergedJSON, &remote); err != nil {
		return err
	}
	s.sessMu.Lock()
	final := chatstore.Merge(s.snapshotLocked(), &remote) // re-merge in case local changed mid-flight
	s.adoptDataLocked(final)
	s.sweepOrphanAttachmentsLocked() // reclaim blobs orphaned by a tombstone this merge adopted
	s.sweepOrphanAvatarsLocked()     // reclaim avatars orphaned by a profile picture change this merge adopted
	s.persistLocked()
	s.sessMu.Unlock()
	return nil
}

// --- helpers ---

func parsePairCode(code string) (account string, secret []byte, err error) {
	code = strings.TrimSpace(strings.TrimPrefix(code, "onionchat-pair:"))
	i := strings.IndexByte(code, ':')
	if i <= 0 || i == len(code)-1 {
		return "", nil, fmt.Errorf("malformed pairing code")
	}
	account = code[:i]
	if _, err := identity.AccountNumberFromString(account); err != nil {
		return "", nil, fmt.Errorf("bad account in code: %w", err)
	}
	secret, err = base64.RawURLEncoding.DecodeString(code[i+1:])
	if err != nil || len(secret) == 0 {
		return "", nil, fmt.Errorf("bad secret in code")
	}
	return account, secret, nil
}

func clampDeviceName(s string) string {
	s = strings.TrimSpace(s)
	if r := []rune(s); len(r) > 40 {
		s = string(r[:40])
	}
	if s == "" {
		s = "linked device"
	}
	return s
}
