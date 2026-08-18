package providers

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/mori-box/moribox-shared/observability"
)

// Errors returned by the callback verifier.
var (
	ErrSignatureInvalid = errors.New("callback signature is invalid")
	ErrTimestampSkew    = errors.New("callback timestamp is outside the replay window")
	ErrPayloadMismatch  = errors.New("callback signature does not cover this payload")
)

// ReplayWindow is the maximum accepted age of a signed callback.
const ReplayWindow = 5 * time.Minute

// CallbackVerifier authenticates inbound provider callbacks.
//
// Two mechanisms are supported. The preferred one is a detached JWS whose
// payload digest must match the received body; the fallback is an HMAC shared
// secret for providers that cannot publish a JWKS. Both bind the signature to a
// timestamp so that a captured callback cannot be replayed later.
type CallbackVerifier struct {
	name         string
	jwks         *oidc.RemoteKeySet
	sharedSecret []byte
	audience     string
}

// NewCallbackVerifier builds a verifier for one provider.
func NewCallbackVerifier(ctx context.Context, name, jwksURL, sharedSecret, audience string) *CallbackVerifier {
	v := &CallbackVerifier{name: name, audience: audience}
	if jwksURL != "" {
		v.jwks = oidc.NewRemoteKeySet(ctx, jwksURL)
	}
	if sharedSecret != "" {
		v.sharedSecret = []byte(sharedSecret)
	}
	return v
}

// Configured reports whether any verification mechanism is available. A
// callback endpoint refuses every request when this is false, rather than
// accepting unauthenticated provider events.
func (v *CallbackVerifier) Configured() bool {
	return v.jwks != nil || len(v.sharedSecret) > 0
}

// Verify authenticates a callback body.
func (v *CallbackVerifier) Verify(ctx context.Context, signature, timestamp string, body []byte) error {
	if !v.Configured() {
		return fmt.Errorf("%w: no verification material configured for %s", ErrSignatureInvalid, v.name)
	}
	if err := v.checkTimestamp(timestamp); err != nil {
		return err
	}
	if v.jwks != nil {
		if err := v.verifyDetachedJWS(ctx, signature, body); err == nil {
			return nil
		} else if len(v.sharedSecret) == 0 {
			return err
		}
	}
	return v.verifyHMAC(signature, timestamp, body)
}

func (v *CallbackVerifier) checkTimestamp(raw string) error {
	if raw == "" {
		return fmt.Errorf("%w: missing timestamp", ErrTimestampSkew)
	}
	when, err := time.Parse(time.RFC3339, raw)
	if err != nil {
		return fmt.Errorf("%w: unparseable timestamp", ErrTimestampSkew)
	}
	drift := time.Since(when)
	if drift < 0 {
		drift = -drift
	}
	if drift > ReplayWindow {
		observability.SecurityAlertsTotal.WithLabelValues("callback_replay_window", "high").Inc()
		return fmt.Errorf("%w: %s is %s away from now", ErrTimestampSkew, raw, drift)
	}
	return nil
}

// verifyDetachedJWS validates a compact JWS whose payload segment is empty and
// whose signed claims carry the digest of the received body.
func (v *CallbackVerifier) verifyDetachedJWS(ctx context.Context, signature string, body []byte) error {
	parts := strings.Split(signature, ".")
	if len(parts) != 3 {
		return fmt.Errorf("%w: detached JWS must have three segments", ErrSignatureInvalid)
	}
	digest := sha256.Sum256(body)
	encodedDigest := base64.RawURLEncoding.EncodeToString(digest[:])

	// Reattach the payload so that the standard verifier can check the
	// signature over header.payload.
	claims := map[string]any{
		"payload_sha256": encodedDigest,
		"aud":            v.audience,
	}
	encodedClaims, err := json.Marshal(claims)
	if err != nil {
		return err
	}
	reattached := parts[0] + "." + base64.RawURLEncoding.EncodeToString(encodedClaims) + "." + parts[2]

	verified, err := v.jwks.VerifySignature(ctx, reattached)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrSignatureInvalid, err)
	}
	var payload struct {
		Digest   string `json:"payload_sha256"`
		Audience string `json:"aud"`
	}
	if err := json.Unmarshal(verified, &payload); err != nil {
		return fmt.Errorf("%w: %w", ErrSignatureInvalid, err)
	}
	if !hmac.Equal([]byte(payload.Digest), []byte(encodedDigest)) {
		return ErrPayloadMismatch
	}
	if v.audience != "" && payload.Audience != v.audience {
		return fmt.Errorf("%w: audience mismatch", ErrSignatureInvalid)
	}
	return nil
}

// verifyHMAC validates "sha256=<hex>" over timestamp and body.
func (v *CallbackVerifier) verifyHMAC(signature, timestamp string, body []byte) error {
	provided := strings.TrimPrefix(signature, "sha256=")
	mac := hmac.New(sha256.New, v.sharedSecret)
	mac.Write([]byte(timestamp))
	mac.Write([]byte{'.'})
	mac.Write(body)
	expected := fmt.Sprintf("%x", mac.Sum(nil))
	if !hmac.Equal([]byte(strings.ToLower(provided)), []byte(expected)) {
		observability.SecurityAlertsTotal.WithLabelValues("callback_signature_invalid", "high").Inc()
		return ErrSignatureInvalid
	}
	return nil
}

// SignHMAC produces the signature a sandbox provider sends. It exists so that
// the contract tests exercise the same code path both sides use.
func SignHMAC(secret, timestamp string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(timestamp))
	mac.Write([]byte{'.'})
	mac.Write(body)
	return "sha256=" + fmt.Sprintf("%x", mac.Sum(nil))
}
