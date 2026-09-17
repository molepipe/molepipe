package protocol

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/molepipe/molepipe/backend/internal/identity"
	"github.com/molepipe/molepipe/backend/internal/tor"
)

// MailboxUsage mirrors the server's usage reply so a client can show how full a
// mailbox is. Field names match internal/mailbox's JSON (no custom tags there).
type MailboxUsage struct {
	Messages    int   `json:"messages"`
	Bytes       int64 `json:"bytes"`
	BackupBytes int64 `json:"backup_bytes"`
	Caps        struct {
		MaxMessages    int   `json:"MaxMessages"`
		MaxBytes       int64 `json:"MaxBytes"`
		MaxBackupBytes int64 `json:"MaxBackupBytes"`
	} `json:"caps"`
}

// MailboxDeleteBinding is the deterministic byte-encoding of the delete id list
// that both the client signs and the server verifies. Kept here so the two sides
// can never disagree on it.
func MailboxDeleteBinding(ids []string) []byte {
	var b bytes.Buffer
	for _, id := range ids {
		b.WriteString(id)
		b.WriteByte('\n')
	}
	return b.Bytes()
}

// mailboxOnionClient builds an HTTP client that dials a mailbox onion over Tor.
// Onion-only for now (clearnet-via-exit is a later increment).
func mailboxOnionClient(dialer tor.Dialer, mailbox string) (*http.Client, string) {
	dialTarget := mailbox
	if !strings.Contains(mailbox, ":") {
		dialTarget = mailbox + ":80"
	}
	client := &http.Client{
		// Backstop only — see clientBackstopTimeout. At 90s this exactly equalled
		// the caller's own drop-off budget, so whichever fired first was a race.
		Timeout: clientBackstopTimeout,
		Transport: &http.Transport{
			DialContext:       func(ctx context.Context, _, _ string) (net.Conn, error) { return dialer.DialOnion(ctx, dialTarget) },
			DisableKeepAlives: true,
		},
	}
	return client, "http://" + mailbox
}

func mailboxChallenge(ctx context.Context, client *http.Client, base string) ([]byte, error) {
	var r struct {
		Nonce []byte `json:"nonce"`
	}
	if err := getJSON(ctx, client, base+"/mailbox/challenge", &r); err != nil {
		return nil, fmt.Errorf("mailbox challenge: %w", err)
	}
	if len(r.Nonce) == 0 {
		return nil, fmt.Errorf("mailbox returned empty challenge")
	}
	return r.Nonce, nil
}

// MailboxCheckIn proves ownership of our account to the mailbox so it will accept
// drop-offs for us, and returns current usage.
func MailboxCheckIn(ctx context.Context, dialer tor.Dialer, id *identity.Identity, mailbox string) (MailboxUsage, error) {
	client, base := mailboxOnionClient(dialer, mailbox)
	nonce, err := mailboxChallenge(ctx, client, base)
	if err != nil {
		return MailboxUsage{}, err
	}
	sig := ed25519.Sign(id.Keys.Signing.Private, MailboxAuthBlob(MailboxOpCheckin, nonce, id.AccountNumber()))
	body := map[string]any{"account": id.AccountNumber(), "nonce": nonce, "sig": sig}
	var resp struct {
		Usage MailboxUsage `json:"usage"`
	}
	if err := postJSONInto(ctx, client, base+"/mailbox/checkin", body, &resp); err != nil {
		return MailboxUsage{}, fmt.Errorf("mailbox check-in: %w", err)
	}
	return resp.Usage, nil
}

// MailboxDropOff leaves a sealed envelope at the recipient's mailbox.
func MailboxDropOff(ctx context.Context, dialer tor.Dialer, env MailEnvelope, mailbox string) error {
	client, base := mailboxOnionClient(dialer, mailbox)
	if err := postJSONInto(ctx, client, base+"/mailbox/dropoff", map[string]any{"envelope": env}, nil); err != nil {
		return fmt.Errorf("mailbox drop-off: %w", err)
	}
	return nil
}

// MailboxPickup fetches everything waiting for us at our mailbox.
func MailboxPickup(ctx context.Context, dialer tor.Dialer, id *identity.Identity, mailbox string) ([]MailEnvelope, error) {
	client, base := mailboxOnionClient(dialer, mailbox)
	nonce, err := mailboxChallenge(ctx, client, base)
	if err != nil {
		return nil, err
	}
	sig := ed25519.Sign(id.Keys.Signing.Private, MailboxAuthBlob(MailboxOpPickup, nonce, id.AccountNumber()))
	body := map[string]any{"account": id.AccountNumber(), "nonce": nonce, "sig": sig}
	var resp struct {
		Items []struct {
			ID       string       `json:"id"`
			Envelope MailEnvelope `json:"envelope"`
		} `json:"items"`
	}
	if err := postJSONInto(ctx, client, base+"/mailbox/pickup", body, &resp); err != nil {
		return nil, fmt.Errorf("mailbox pickup: %w", err)
	}
	out := make([]MailEnvelope, 0, len(resp.Items))
	for _, it := range resp.Items {
		out = append(out, it.Envelope)
	}
	return out, nil
}

// MailboxDelete removes blobs from our mailbox after a confirmed local pickup.
func MailboxDelete(ctx context.Context, dialer tor.Dialer, id *identity.Identity, mailbox string, ids []string) error {
	if len(ids) == 0 {
		return nil
	}
	client, base := mailboxOnionClient(dialer, mailbox)
	nonce, err := mailboxChallenge(ctx, client, base)
	if err != nil {
		return err
	}
	sig := ed25519.Sign(id.Keys.Signing.Private, MailboxAuthBlob(MailboxOpDelete, nonce, id.AccountNumber(), MailboxDeleteBinding(ids)))
	body := map[string]any{"account": id.AccountNumber(), "nonce": nonce, "sig": sig, "ids": ids}
	if err := postJSONInto(ctx, client, base+"/mailbox/delete", body, nil); err != nil {
		return fmt.Errorf("mailbox delete: %w", err)
	}
	return nil
}

// MailboxBackupDropOff stores a durable self-sealed group-image backup in our OWN
// mailbox under the stable id we chose, requesting the given byte budget. Both the
// id and budget are bound into the auth signature so a captured request cannot be
// re-aimed. env.Recipient == env.Sender == our account (the server re-checks).
func MailboxBackupDropOff(ctx context.Context, dialer tor.Dialer, id *identity.Identity, mailbox, blobID string, budget int64, env MailEnvelope) error {
	client, base := mailboxOnionClient(dialer, mailbox)
	nonce, err := mailboxChallenge(ctx, client, base)
	if err != nil {
		return err
	}
	extra := MailboxBackupBinding(blobID, budget)
	sig := ed25519.Sign(id.Keys.Signing.Private, MailboxAuthBlob(MailboxOpBackupDropoff, nonce, id.AccountNumber(), extra...))
	body := map[string]any{"account": id.AccountNumber(), "nonce": nonce, "sig": sig, "id": blobID, "budget": budget, "envelope": env}
	if err := postJSONInto(ctx, client, base+"/mailbox/backup/dropoff", body, nil); err != nil {
		return fmt.Errorf("mailbox backup drop-off: %w", err)
	}
	return nil
}

// MailboxBackupPickup fetches all durable backup blobs from our own mailbox. Unlike
// MailboxPickup this is non-destructive server-side: the backups stay in place so
// another fresh device can also restore from them.
func MailboxBackupPickup(ctx context.Context, dialer tor.Dialer, id *identity.Identity, mailbox string) ([]MailEnvelope, error) {
	client, base := mailboxOnionClient(dialer, mailbox)
	nonce, err := mailboxChallenge(ctx, client, base)
	if err != nil {
		return nil, err
	}
	sig := ed25519.Sign(id.Keys.Signing.Private, MailboxAuthBlob(MailboxOpBackupPickup, nonce, id.AccountNumber()))
	body := map[string]any{"account": id.AccountNumber(), "nonce": nonce, "sig": sig}
	var resp struct {
		Items []struct {
			ID       string       `json:"id"`
			Envelope MailEnvelope `json:"envelope"`
		} `json:"items"`
	}
	if err := postJSONInto(ctx, client, base+"/mailbox/backup/pickup", body, &resp); err != nil {
		return nil, fmt.Errorf("mailbox backup pickup: %w", err)
	}
	out := make([]MailEnvelope, 0, len(resp.Items))
	for _, it := range resp.Items {
		out = append(out, it.Envelope)
	}
	return out, nil
}

// BackupMeta is one durable backup's id and byte size, as returned by
// MailboxBackupList. A restoring device uses the ids to fetch only what it lacks.
type BackupMeta struct {
	ID   string `json:"id"`
	Size int64  `json:"size"`
}

// MailboxBackupList returns the ids and sizes of our durable backups without any
// blob bytes. The whole-set MailboxBackupPickup is bounded by a single response
// size cap; listing then fetching by id lets a fresh device restore a budget far
// larger than one response, pulling only the ids whose bytes it is missing.
func MailboxBackupList(ctx context.Context, dialer tor.Dialer, id *identity.Identity, mailbox string) ([]BackupMeta, error) {
	client, base := mailboxOnionClient(dialer, mailbox)
	nonce, err := mailboxChallenge(ctx, client, base)
	if err != nil {
		return nil, err
	}
	sig := ed25519.Sign(id.Keys.Signing.Private, MailboxAuthBlob(MailboxOpBackupList, nonce, id.AccountNumber()))
	body := map[string]any{"account": id.AccountNumber(), "nonce": nonce, "sig": sig}
	var resp struct {
		Items []BackupMeta `json:"items"`
	}
	if err := postJSONInto(ctx, client, base+"/mailbox/backup/list", body, &resp); err != nil {
		return nil, fmt.Errorf("mailbox backup list: %w", err)
	}
	return resp.Items, nil
}

// MailboxBackupFetch fetches exactly one durable backup blob by id, so a restoring
// device pulls one blob per response instead of the whole set at once. The id is
// bound into the auth signature.
func MailboxBackupFetch(ctx context.Context, dialer tor.Dialer, id *identity.Identity, mailbox, blobID string) (MailEnvelope, error) {
	client, base := mailboxOnionClient(dialer, mailbox)
	nonce, err := mailboxChallenge(ctx, client, base)
	if err != nil {
		return MailEnvelope{}, err
	}
	extra := MailboxBackupFetchBinding(blobID)
	sig := ed25519.Sign(id.Keys.Signing.Private, MailboxAuthBlob(MailboxOpBackupFetch, nonce, id.AccountNumber(), extra...))
	body := map[string]any{"account": id.AccountNumber(), "nonce": nonce, "sig": sig, "id": blobID}
	var resp struct {
		ID       string       `json:"id"`
		Envelope MailEnvelope `json:"envelope"`
	}
	if err := postJSONInto(ctx, client, base+"/mailbox/backup/fetch", body, &resp); err != nil {
		return MailEnvelope{}, fmt.Errorf("mailbox backup fetch: %w", err)
	}
	return resp.Envelope, nil
}

// MailboxBackupPurge removes all durable backup blobs from our own mailbox (leaving
// messages and tenancy intact). Used when the owner turns backups off.
func MailboxBackupPurge(ctx context.Context, dialer tor.Dialer, id *identity.Identity, mailbox string) error {
	client, base := mailboxOnionClient(dialer, mailbox)
	nonce, err := mailboxChallenge(ctx, client, base)
	if err != nil {
		return err
	}
	sig := ed25519.Sign(id.Keys.Signing.Private, MailboxAuthBlob(MailboxOpBackupPurge, nonce, id.AccountNumber()))
	body := map[string]any{"account": id.AccountNumber(), "nonce": nonce, "sig": sig}
	if err := postJSONInto(ctx, client, base+"/mailbox/backup/purge", body, nil); err != nil {
		return fmt.Errorf("mailbox backup purge: %w", err)
	}
	return nil
}

// postJSONInto POSTs body and optionally decodes a JSON response. The response
// limit is generous because a pickup can carry a full mailbox of messages.
func postJSONInto(ctx context.Context, c *http.Client, url string, body, out any) error {
	buf, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(buf))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("status %d: %s", resp.StatusCode, bytes.TrimSpace(msg))
	}
	if out != nil {
		return json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(out)
	}
	return nil
}
