package telegram_test

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/mori-box/moribox-shared/telegram"
	"github.com/stretchr/testify/require"
)

const botToken = "8899816630:AAtest-token-for-unit-tests-only-not-real"

// sign builds launch parameters the way Telegram does, so the test exercises the
// real check rather than the implementation's own idea of a signature.
func sign(t *testing.T, token string, fields map[string]string) string {
	t.Helper()

	keys := make([]string, 0, len(fields))
	for k := range fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var check strings.Builder
	for i, k := range keys {
		if i > 0 {
			check.WriteByte('\n')
		}
		check.WriteString(k)
		check.WriteByte('=')
		check.WriteString(fields[k])
	}

	secretMac := hmac.New(sha256.New, []byte("WebAppData"))
	secretMac.Write([]byte(token))
	mac := hmac.New(sha256.New, secretMac.Sum(nil))
	mac.Write([]byte(check.String()))

	values := url.Values{}
	for k, v := range fields {
		values.Set(k, v)
	}
	values.Set("hash", hex.EncodeToString(mac.Sum(nil)))
	return values.Encode()
}

func freshFields(now time.Time) map[string]string {
	return map[string]string{
		"auth_date": strconv.FormatInt(now.Unix(), 10),
		"query_id":  "AAHdF6IQAAAAAN0XohDhrOrc",
		"user":      `{"id":42,"first_name":"Тест","last_name":"Игрок","username":"tester","language_code":"ru"}`,
	}
}

func TestVerifyAcceptsParametersSignedByThisBot(t *testing.T) {
	v, err := telegram.NewVerifier(botToken, time.Hour)
	require.NoError(t, err)

	data, err := v.Verify(sign(t, botToken, freshFields(time.Now())))
	require.NoError(t, err)

	require.EqualValues(t, 42, data.User.ID)
	require.Equal(t, "Тест Игрок", data.User.DisplayName())
	require.Equal(t, "telegram:42", data.User.Subject())
}

// TestVerifyRejectsAnotherBotsSignature is the property the whole scheme rests
// on: only the holder of this bot's token can produce parameters it accepts.
func TestVerifyRejectsAnotherBotsSignature(t *testing.T) {
	v, err := telegram.NewVerifier(botToken, time.Hour)
	require.NoError(t, err)

	_, err = v.Verify(sign(t, "1111111111:AAdifferent-bot-entirely", freshFields(time.Now())))
	require.ErrorIs(t, err, telegram.ErrBadSignature)
}

// TestVerifyRejectsATamperedUser is the attack the signature exists to stop:
// keeping a genuine hash and changing who the parameters claim to be.
func TestVerifyRejectsATamperedUser(t *testing.T) {
	v, err := telegram.NewVerifier(botToken, time.Hour)
	require.NoError(t, err)

	signed := sign(t, botToken, freshFields(time.Now()))
	values, err := url.ParseQuery(signed)
	require.NoError(t, err)
	values.Set("user", `{"id":999,"first_name":"Somebody","username":"else"}`)

	_, err = v.Verify(values.Encode())
	require.ErrorIs(t, err, telegram.ErrBadSignature)
}

func TestVerifyRejectsMissingHash(t *testing.T) {
	v, err := telegram.NewVerifier(botToken, time.Hour)
	require.NoError(t, err)

	_, err = v.Verify("auth_date=1700000000&user=%7B%22id%22%3A42%7D")
	require.ErrorIs(t, err, telegram.ErrMissingHash)
}

// TestVerifyRejectsStaleParameters bounds how long a copied launch string stays
// useful to whoever obtained one.
func TestVerifyRejectsStaleParameters(t *testing.T) {
	v, err := telegram.NewVerifier(botToken, time.Minute)
	require.NoError(t, err)

	_, err = v.Verify(sign(t, botToken, freshFields(time.Now().Add(-2*time.Minute))))
	require.ErrorIs(t, err, telegram.ErrExpired)
}

// TestVerifyRejectsAFutureAuthDate stops the age check being defeated by simply
// claiming a later time.
func TestVerifyRejectsAFutureAuthDate(t *testing.T) {
	v, err := telegram.NewVerifier(botToken, time.Minute)
	require.NoError(t, err)

	_, err = v.Verify(sign(t, botToken, freshFields(time.Now().Add(10*time.Minute))))
	require.ErrorIs(t, err, telegram.ErrFromTheFuture)
}

// TestVerifyToleratesSmallClockSkew keeps a few seconds of disagreement between
// Telegram's clock and ours from refusing a legitimate login.
func TestVerifyToleratesSmallClockSkew(t *testing.T) {
	v, err := telegram.NewVerifier(botToken, time.Minute)
	require.NoError(t, err)

	_, err = v.Verify(sign(t, botToken, freshFields(time.Now().Add(5*time.Second))))
	require.NoError(t, err)
}

// TestVerifyRefusesParametersWithNoUser covers the inline-result launch, which
// names nobody. Creating an account there would produce one nobody could ever
// sign back into.
func TestVerifyRefusesParametersWithNoUser(t *testing.T) {
	v, err := telegram.NewVerifier(botToken, time.Hour)
	require.NoError(t, err)

	fields := freshFields(time.Now())
	delete(fields, "user")

	_, err = v.Verify(sign(t, botToken, fields))
	require.ErrorIs(t, err, telegram.ErrNoUser)
}

// TestSignatureFieldIsNotPartOfTheHMAC guards a real interoperability trap:
// newer clients add an Ed25519 `signature` field, which is not part of the HMAC
// input. Including it would refuse every login from those clients.
func TestSignatureFieldIsNotPartOfTheHMAC(t *testing.T) {
	v, err := telegram.NewVerifier(botToken, time.Hour)
	require.NoError(t, err)

	signed := sign(t, botToken, freshFields(time.Now()))
	values, err := url.ParseQuery(signed)
	require.NoError(t, err)
	values.Set("signature", "3A0dyvfsRAkBQqbAcCkQ0mSGtDrsyfPa_i6xJlnCPpM")

	data, err := v.Verify(values.Encode())
	require.NoError(t, err, "an Ed25519 signature field must not break the HMAC check")
	require.EqualValues(t, 42, data.User.ID)
}

// TestStartParamSurvivesVerification carries the invite from a deep link, which
// is how attribution reaches the platform.
func TestStartParamSurvivesVerification(t *testing.T) {
	v, err := telegram.NewVerifier(botToken, time.Hour)
	require.NoError(t, err)

	fields := freshFields(time.Now())
	fields["start_param"] = "ALICE001"

	data, err := v.Verify(sign(t, botToken, fields))
	require.NoError(t, err)
	require.Equal(t, "ALICE001", data.StartParam)
}

func TestNewVerifierRefusesAnEmptyToken(t *testing.T) {
	_, err := telegram.NewVerifier("   ", time.Hour)
	require.ErrorIs(t, err, telegram.ErrNotConfigured)
}

func TestDisplayNameFallsBackThroughUsernameToIdentifier(t *testing.T) {
	require.Equal(t, "tester", telegram.User{ID: 7, Username: "tester"}.DisplayName())
	require.Equal(t, "telegram:7", telegram.User{ID: 7}.DisplayName())
}
