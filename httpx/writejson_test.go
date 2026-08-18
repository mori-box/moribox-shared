package httpx

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestNilCollectionsSerialiseAsEmpty is the guard for a failure the console hit
// twice: a healthy platform with nothing to report sent null where the contract
// promised an array, and the page that read .length on it went blank.
func TestNilCollectionsSerialiseAsEmpty(t *testing.T) {
	type item struct {
		ID string `json:"id"`
	}
	var (
		nilSlice []item
		nilMap   map[string]int64
	)

	rec := httptest.NewRecorder()
	WriteJSON(rec, http.StatusOK, map[string]any{
		"items":   nilSlice,
		"counts":  nilMap,
		"cursor":  "",
		"missing": nil,
	})

	var decoded map[string]json.RawMessage
	if err := json.Unmarshal(rec.Body.Bytes(), &decoded); err != nil {
		t.Fatalf("response is not valid JSON: %v", err)
	}
	if got := string(decoded["items"]); got != "[]" {
		t.Errorf("items = %s, want []", got)
	}
	if got := string(decoded["counts"]); got != "{}" {
		t.Errorf("counts = %s, want {}", got)
	}
	// A key whose value is genuinely absent keeps its meaning: null is the right
	// answer for "there is no such thing", and only collections are rewritten.
	if got := string(decoded["missing"]); got != "null" {
		t.Errorf("missing = %s, want null", got)
	}
}

func TestPopulatedCollectionsAreUntouched(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteJSON(rec, http.StatusOK, map[string]any{
		"items":  []string{"a", "b"},
		"counts": map[string]int{"x": 1},
	})

	var decoded struct {
		Items  []string       `json:"items"`
		Counts map[string]int `json:"counts"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &decoded); err != nil {
		t.Fatalf("response is not valid JSON: %v", err)
	}
	if len(decoded.Items) != 2 || decoded.Items[0] != "a" {
		t.Errorf("items were altered: %v", decoded.Items)
	}
	if decoded.Counts["x"] != 1 {
		t.Errorf("counts were altered: %v", decoded.Counts)
	}
}

// TestNonEnvelopeBodiesArePassedThrough keeps the rewrite narrow: a handler that
// returns a struct owns its own shape, and silently editing it here would hide
// the problem rather than fix it at the source.
func TestNonEnvelopeBodiesArePassedThrough(t *testing.T) {
	type response struct {
		Items []string `json:"items"`
	}
	rec := httptest.NewRecorder()
	WriteJSON(rec, http.StatusOK, response{})

	var decoded map[string]json.RawMessage
	if err := json.Unmarshal(rec.Body.Bytes(), &decoded); err != nil {
		t.Fatalf("response is not valid JSON: %v", err)
	}
	if got := string(decoded["items"]); got != "null" {
		t.Errorf("a struct field must be left alone, got %s", got)
	}
}

// TestCORSAllowsTheHeadersAHandlerActuallyReads guards a failure a browser
// reports as a generic network error: a header the preflight does not list is
// dropped silently, and the request arrives without it. It covers both the
// platform baseline this package always allows and a caller-supplied header
// passed through extraHeaders, which is how a deployment's own headers (an
// invite token, for example) join the preflight without this package having
// to know their names.
func TestCORSAllowsTheHeadersAHandlerActuallyReads(t *testing.T) {
	handler := CORS([]string{"https://play.example.com"}, false, "X-Invite-Token")(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

	req := httptest.NewRequest(http.MethodOptions, "/v1/widgets", nil)
	req.Header.Set("Origin", "https://play.example.com")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	allowed := rec.Header().Get("Access-Control-Allow-Headers")
	for _, header := range []string{
		"Authorization", "Content-Type",
		HeaderIdempotency, HeaderDeviceID, "X-Invite-Token",
	} {
		if !strings.Contains(allowed, header) {
			t.Errorf("%s is read by a handler but not permitted by the preflight", header)
		}
	}

	if rec.Header().Get("Access-Control-Allow-Credentials") != "" {
		t.Error("the player plane uses a bearer token; credentials must not be allowed")
	}
}

func TestCORSRefusesAnUnknownOrigin(t *testing.T) {
	handler := CORS([]string{"https://play.moribox.info"}, false)(
		http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

	req := httptest.NewRequest(http.MethodOptions, "/v1/box-openings", nil)
	req.Header.Set("Origin", "https://not-us.example.com")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Error("an origin that is not on the list must not be told it is welcome")
	}
}
