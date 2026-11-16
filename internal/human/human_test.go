package human

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

var (
	key   = []byte("0123456789abcdef0123456789abcdef")
	alice = Identity{Issuer: "https://dex-acme.demo.pathops.io", Subject: "alice-sub", Email: "alice@e2e.pathops.test"}
	t0    = time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
)

func auth(t *testing.T, k []byte, now *time.Time) *Auth {
	t.Helper()
	a, err := New(Config{Issuer: "https://dex-acme.demo.pathops.io", ClientID: "pathops-events-web", ClientSecret: "s",
		PublicURL: "https://events-acme.demo.pathops.io", SessionKey: k, Now: func() time.Time { return *now }})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func request(value string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/api/v1/events", nil)
	r.AddCookie(&http.Cookie{Name: SessionCookie, Value: value})
	return r
}

func TestSessionOutlivesARestart(t *testing.T) {
	now := t0
	v := auth(t, key, &now).seal(alice, now.Add(SessionLifetime))
	// Another process (a restart) with the same key opens it.
	if id, ok := auth(t, key, &now).Session(request(v)); !ok || id != alice {
		t.Fatal(id, ok)
	}
	// The cookie reveals nothing of the identity.
	if strings.Contains(v, "alice") {
		t.Fatal("readable cookie")
	}
}

func TestSessionRefused(t *testing.T) {
	now := t0
	a := auth(t, key, &now)
	v := a.seal(alice, now.Add(SessionLifetime))
	other := auth(t, []byte("fedcba9876543210fedcba9876543210"), &now)
	if _, ok := other.Session(request(v)); ok {
		t.Error("another key opened it")
	}
	flipped := []byte(v)
	flipped[len(flipped)/2] ^= 1
	for name, value := range map[string]string{"tampered": string(flipped), "truncated": v[:20], "empty": "", "not base64": "!!!",
		"random": "c2Vzc2lvbg", "huge": strings.Repeat("A", 5000)} {
		if _, ok := a.Session(request(value)); ok {
			t.Errorf("%s accepted", name)
		}
	}
	// Expired.
	now = t0.Add(SessionLifetime + time.Second)
	if _, ok := a.Session(request(v)); ok {
		t.Error("expired session accepted")
	}
}

func TestLogoutRevokes(t *testing.T) {
	now := t0
	a := auth(t, key, &now)
	v := a.seal(alice, now.Add(SessionLifetime))
	w := httptest.NewRecorder()
	a.Logout(w, request(v))
	if _, ok := a.Session(request(v)); ok {
		t.Fatal("a signed-out cookie still works here")
	}
	if c := w.Result().Cookies(); len(c) != 1 || c[0].MaxAge != -1 || !c[0].Secure || !c[0].HttpOnly {
		t.Fatalf("%+v", c)
	}
}

func TestSessionKeyRequired(t *testing.T) {
	now := t0
	for _, k := range [][]byte{nil, []byte("short")} {
		if _, err := New(Config{Issuer: "https://dex", ClientID: "c", ClientSecret: "s", PublicURL: "https://events.example",
			SessionKey: k, Now: func() time.Time { return now }}); err == nil {
			t.Errorf("key %q accepted", k)
		}
	}
}
