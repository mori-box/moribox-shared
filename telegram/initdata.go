// Package telegram verifies the launch parameters a Telegram Mini App receives.
//
// Telegram opens the application with a signed string describing who opened it.
// Verifying that signature is the whole of the authentication: there is no
// redirect, no token endpoint and nothing to call back. The bot token is the
// shared secret, so it exists only here and only in memory.
package telegram

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Errors returned when launch parameters are not acceptable.
var (
	ErrMissingHash   = errors.New("the launch parameters carry no hash")
	ErrBadSignature  = errors.New("the launch parameters are not signed by this bot")
	ErrExpired       = errors.New("the launch parameters are too old to exchange")
	ErrFromTheFuture = errors.New("the launch parameters are dated in the future")
	ErrNoUser        = errors.New("the launch parameters name no user")
	ErrNotConfigured = errors.New("no telegram bot token is configured")
)

// User is the person who opened the application.
type User struct {
	ID           int64  `json:"id"`
	FirstName    string `json:"first_name"`
	LastName     string `json:"last_name"`
	Username     string `json:"username"`
	LanguageCode string `json:"language_code"`
	IsPremium    bool   `json:"is_premium"`
	PhotoURL     string `json:"photo_url"`
}

// DisplayName is what the platform shows for this person.
func (u User) DisplayName() string {
	full := strings.TrimSpace(strings.Join([]string{u.FirstName, u.LastName}, " "))
	if full != "" {
		return full
	}
	if u.Username != "" {
		return u.Username
	}
	return "telegram:" + strconv.FormatInt(u.ID, 10)
}

// Subject is the stable external identity for this person.
//
// It is prefixed rather than being the bare numeric id, so that a Telegram
// identity can never collide with a subject minted by another provider. The
// platform holds a unique index on this column and would otherwise be one
// integer away from joining two unrelated accounts.
func (u User) Subject() string {
	return "telegram:" + strconv.FormatInt(u.ID, 10)
}

// LaunchData is the verified content of the launch parameters.
type LaunchData struct {
	User       User
	AuthDate   time.Time
	QueryID    string
	StartParam string
	ChatType   string
	ChatID     int64
}

// Verifier checks launch parameters against one bot token.
type Verifier struct {
	// secret is HMAC-SHA256("WebAppData", botToken), derived once. The token
	// itself is not retained: nothing here needs it again, and not holding it
	// means it cannot be read out of this struct.
	secret []byte
	// tokenLen and tokenFingerprint are TEMPORARY diagnostic fields — never
	// the token itself, just its length and a one-way SHA256 fingerprint, so
	// two verifiers can be compared for using the identical token without
	// either ever printing anything secret. Remove once the real mismatch is
	// root-caused.
	tokenLen         int
	tokenFingerprint string
	maxAge           time.Duration
	// clockSkew tolerates a client whose clock runs slightly ahead. Telegram
	// stamps auth_date on its own servers, so the tolerance covers the gap
	// between their clock and ours, not a user's.
	clockSkew time.Duration
	now       func() time.Time
}

// NewVerifier derives the signing key from the bot token.
func NewVerifier(botToken string, maxAge time.Duration) (*Verifier, error) {
	// A token sourced from an environment variable or a mounted secrets file
	// can pick up a stray trailing newline or space along the way (a shell
	// export, a docker-compose env interpolation quirk, an editor that always
	// appends a final newline). getMe and other REST calls tolerate that kind
	// of noise because HTTP libraries trim it; HMAC does not — one extra byte
	// produces a completely different key and every real signature fails
	// with what looks like a wrong-bot error. Trimming here is cheap and
	// removes an entire class of "correct token, wrong signature" bugs.
	botToken = strings.TrimSpace(botToken)
	if botToken == "" {
		return nil, ErrNotConfigured
	}
	if maxAge <= 0 {
		// Telegram itself suggests treating launch parameters as short lived.
		// A day is generous for an exchange that happens the moment the
		// application opens, and it bounds how long a copied string is useful
		// to somebody who obtained one.
		maxAge = 24 * time.Hour
	}

	mac := hmac.New(sha256.New, []byte("WebAppData"))
	mac.Write([]byte(botToken))

	fp := sha256.Sum256([]byte(botToken))

	return &Verifier{
		secret:           mac.Sum(nil),
		tokenLen:         len(botToken),
		tokenFingerprint: hex.EncodeToString(fp[:8]),
		maxAge:           maxAge,
		clockSkew:        30 * time.Second,
		now:              time.Now,
	}, nil
}

// Verify checks the signature and the age, then returns what the parameters say.
//
// initData is the string exactly as Telegram produced it. It must not be
// re-encoded or reordered on the way here: the signature covers a particular
// sequence of bytes, and normalising it on the client would invalidate a login
// that was perfectly good.
func (v *Verifier) Verify(initData string) (*LaunchData, error) {
	values, err := url.ParseQuery(initData)
	if err != nil {
		return nil, fmt.Errorf("launch parameters are not a query string: %w", err)
	}

	provided := values.Get("hash")
	if provided == "" {
		return nil, ErrMissingHash
	}

	expected := v.sign(values)
	// A byte-by-byte comparison would leak, through its timing, how much of a
	// forged hash was correct — which is enough to construct the rest.
	if !hmac.Equal([]byte(expected), []byte(provided)) {
		// TEMPORARY diagnostic (2026-08-21, round 2): the TrimSpace fix did
		// not resolve the real failures, so logging again — this time also
		// the token length/fingerprint the secret was actually derived from,
		// to confirm which token is in play. Never the token or any field
		// value. Remove once root-caused.
		rawAlt := v.signRaw(initData)
		fmt.Printf("[telegram-verify-debug-2] initData_len=%d token_len=%d token_fp=%s expected_hash=%s received_hash=%s raw_alt_hash=%s raw_alt_matches=%v\n",
			len(initData), v.tokenLen, v.tokenFingerprint, expected, provided, rawAlt, hmac.Equal([]byte(rawAlt), []byte(provided)))
		return nil, ErrBadSignature
	}

	authDateRaw := values.Get("auth_date")
	seconds, err := strconv.ParseInt(authDateRaw, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("auth_date %q is not a unix timestamp: %w", authDateRaw, err)
	}
	authDate := time.Unix(seconds, 0).UTC()
	now := v.now().UTC()

	if authDate.After(now.Add(v.clockSkew)) {
		return nil, fmt.Errorf("%w: dated %s, now %s", ErrFromTheFuture, authDate, now)
	}
	if now.Sub(authDate) > v.maxAge {
		return nil, fmt.Errorf("%w: dated %s, limit %s", ErrExpired, authDate, v.maxAge)
	}

	userRaw := values.Get("user")
	if userRaw == "" {
		// A Mini App opened from an inline result carries no user. The platform
		// has nothing to key an account on, so this is refused rather than
		// creating an account nobody can sign back into.
		return nil, ErrNoUser
	}
	var user User
	if err := json.Unmarshal([]byte(userRaw), &user); err != nil {
		return nil, fmt.Errorf("user payload is not valid json: %w", err)
	}
	if user.ID == 0 {
		return nil, ErrNoUser
	}

	data := &LaunchData{
		User:       user,
		AuthDate:   authDate,
		QueryID:    values.Get("query_id"),
		StartParam: values.Get("start_param"),
		ChatType:   values.Get("chat_type"),
	}
	if raw := values.Get("chat_instance"); raw != "" {
		data.ChatID, _ = strconv.ParseInt(raw, 10, 64)
	}
	return data, nil
}

// signRaw is a TEMPORARY diagnostic twin of sign that skips url.ParseQuery
// decoding, splitting the raw initData string by hand and signing the still
// percent-encoded values. Remove once the real mismatch is root-caused.
func (v *Verifier) signRaw(initData string) string {
	pairs := strings.Split(initData, "&")
	kv := make(map[string]string, len(pairs))
	keys := make([]string, 0, len(pairs))
	for _, p := range pairs {
		parts := strings.SplitN(p, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := parts[0]
		if key == "hash" || key == "signature" {
			continue
		}
		if _, exists := kv[key]; !exists {
			keys = append(keys, key)
		}
		kv[key] = parts[1]
	}
	sort.Strings(keys)

	var check strings.Builder
	for i, key := range keys {
		if i > 0 {
			check.WriteByte('\n')
		}
		check.WriteString(key)
		check.WriteByte('=')
		check.WriteString(kv[key])
	}

	mac := hmac.New(sha256.New, v.secret)
	mac.Write([]byte(check.String()))
	return hex.EncodeToString(mac.Sum(nil))
}

// sign computes the hash Telegram would have produced for these values.
//
// The check string is every field except the hash, sorted by key, rendered as
// key=value and joined by newlines. `signature` is excluded as well: it belongs
// to Telegram's separate Ed25519 scheme for third parties and is not part of
// the HMAC input, so including it would make every signed request fail on the
// clients that send it.
func (v *Verifier) sign(values url.Values) string {
	keys := make([]string, 0, len(values))
	for key := range values {
		if key == "hash" || key == "signature" {
			continue
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)

	var check strings.Builder
	for i, key := range keys {
		if i > 0 {
			check.WriteByte('\n')
		}
		check.WriteString(key)
		check.WriteByte('=')
		check.WriteString(values.Get(key))
	}

	mac := hmac.New(sha256.New, v.secret)
	mac.Write([]byte(check.String()))
	return hex.EncodeToString(mac.Sum(nil))
}
