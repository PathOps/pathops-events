package server

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"

	"github.com/PathOps/pathops-events/internal/hub"
	"github.com/PathOps/pathops-events/internal/human"
	"github.com/PathOps/pathops-events/internal/workload"
)

const (
	clientID = "pathops-events-web"
	secret   = "client-secret"
	uiOrigin = "https://control-plane-acme.demo.pathops.io"
	appA     = "11111111-1111-4111-8111-111111111111"
	appB     = "22222222-2222-4222-8222-222222222222"
	buildA   = "33333333-3333-4333-8333-333333333333"
	buildA2  = "44444444-4444-4444-8444-444444444444"
	tcpToken = "tcp-token"
)

var sessionKey = []byte("0123456789abcdef0123456789abcdef")

// dex is a fake Dex: discovery, JWKS, and an authorization code flow whose
// codes the test mints (code -> the ID token claims it redeems to).
type dex struct {
	srv   *httptest.Server
	key   *rsa.PrivateKey
	kid   string
	mu    sync.Mutex
	codes map[string]dexCode
}

type dexCode struct {
	challenge string
	claims    map[string]any
	signer    *rsa.PrivateKey
}

func newDex(t *testing.T) *dex {
	d := &dex{kid: "oidc-1", codes: map[string]dexCode{}}
	d.key, _ = rsa.GenerateKey(rand.Reader, 2048)
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"issuer": d.srv.URL, "authorization_endpoint": d.srv.URL + "/auth",
			"token_endpoint": d.srv.URL + "/token", "jwks_uri": d.srv.URL + "/keys"})
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &d.key.PublicKey, KeyID: d.kid, Algorithm: "RS256", Use: "sig"}}})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		id, sec, ok := r.BasicAuth()
		_ = r.ParseForm()
		d.mu.Lock()
		c, found := d.codes[r.Form.Get("code")]
		delete(d.codes, r.Form.Get("code"))
		d.mu.Unlock()
		sum := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
		if !ok || id != clientID || sec != secret || !found || base64.RawURLEncoding.EncodeToString(sum[:]) != c.challenge ||
			r.Form.Get("grant_type") != "authorization_code" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"id_token": d.sign(c.signer, c.claims), "token_type": "bearer"})
	})
	d.srv = httptest.NewTLSServer(mux)
	t.Cleanup(d.srv.Close)
	return d
}

func (d *dex) sign(k *rsa.PrivateKey, claims map[string]any) string {
	s, _ := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: k}, (&jose.SignerOptions{}).WithHeader("kid", d.kid))
	b, _ := json.Marshal(claims)
	o, _ := s.Sign(b)
	out, _ := o.CompactSerialize()
	return out
}

// publishers accepts exactly tcpToken, and is unavailable for "down".
type publishers struct{}

func (publishers) Verify(_ context.Context, token string) (string, error) {
	switch token {
	case tcpToken:
		return "system:serviceaccount:pathops-system:tenant-control-plane", nil
	case "down":
		return "", workload.ErrUnavailable
	}
	return "", workload.ErrUnauthenticated
}

type env struct {
	t        *testing.T
	s        *Server
	pub, int *httptest.Server
	dex      *dex
}

func newEnv(t *testing.T) *env {
	d := newDex(t)
	e := &env{t: t, dex: d}
	e.s = &Server{Hub: &hub.Hub{}, Publishers: publishers{}, AllowedOrigin: uiOrigin, Issuer: d.srv.URL,
		Heartbeat: 50 * time.Millisecond, Retry: 5 * time.Second, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
	e.pub = httptest.NewUnstartedServer(nil)
	e.pub.Config.Handler = e.s.Public()
	e.pub.StartTLS()
	t.Cleanup(e.pub.Close)
	e.int = httptest.NewTLSServer(e.s.Internal())
	t.Cleanup(e.int.Close)
	e.s.PublicURL = e.pub.URL
	people, err := human.New(human.Config{Issuer: d.srv.URL, ClientID: clientID, ClientSecret: secret, PublicURL: e.pub.URL,
		SessionKey: sessionKey, HTTP: d.srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	e.s.People = people
	return e
}

// browser keeps cookies and does not follow redirects.
type browser struct {
	e      *env
	client *http.Client
}

func (e *env) browser() *browser {
	jar, _ := cookiejar.New(nil)
	c := *e.pub.Client() // a copy: each browser has its own cookies
	c.Jar = jar
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &browser{e: e, client: &c}
}

func (b *browser) get(path string, hdr ...string) (*http.Response, string) {
	b.e.t.Helper()
	req, _ := http.NewRequest(http.MethodGet, b.e.pub.URL+path, nil)
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	resp, err := b.client.Do(req)
	if err != nil {
		b.e.t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp, string(body)
}

// signIn starts at /login?return=<the UI>, "signs in" at Dex as subject
// with claims over the defaults and follows the callback; it returns the
// callback's answer.
func (b *browser) signIn(subject string, over map[string]any) *http.Response {
	t := b.e.t
	t.Helper()
	resp, _ := b.get("/login?return=" + url.QueryEscape(uiOrigin+"/applications/"+appA+"/builds"))
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("login: %d", resp.StatusCode)
	}
	loc, _ := url.Parse(resp.Header.Get("Location"))
	q := loc.Query()
	if !strings.HasPrefix(loc.String(), b.e.dex.srv.URL+"/auth?") || q.Get("client_id") != clientID || q.Get("code_challenge_method") != "S256" ||
		q.Get("redirect_uri") != b.e.pub.URL+"/oauth2/callback" || q.Get("state") == "" || q.Get("nonce") == "" || q.Get("code_challenge") == "" {
		t.Fatalf("authorization request: %s", loc)
	}
	claims := map[string]any{"iss": b.e.dex.srv.URL, "aud": clientID, "sub": subject, "email": subject + "@e2e.pathops.test",
		"exp": time.Now().Unix() + 600, "nonce": q.Get("nonce")}
	signer := b.e.dex.key
	for k, v := range over {
		if k == "signer" {
			signer = v.(*rsa.PrivateKey)
			continue
		}
		claims[k] = v
	}
	code := "code-" + subject + q.Get("state")[:8]
	b.e.dex.mu.Lock()
	b.e.dex.codes[code] = dexCode{challenge: q.Get("code_challenge"), claims: claims, signer: signer}
	b.e.dex.mu.Unlock()
	resp, _ = b.get("/oauth2/callback?code=" + code + "&state=" + url.QueryEscape(q.Get("state")))
	return resp
}

func (b *browser) mustSignIn(subject string) {
	b.e.t.Helper()
	resp := b.signIn(subject, nil)
	if resp.StatusCode != http.StatusFound || resp.Header.Get("Location") != uiOrigin+"/applications/"+appA+"/builds" {
		b.e.t.Fatalf("callback: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	for _, c := range resp.Cookies() {
		if c.Name == human.SessionCookie && (!c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteLaxMode || c.Path != "/" || c.Domain != "") {
			b.e.t.Fatalf("session cookie %+v", c)
		}
	}
}

// stream is an open SSE connection: its lines, read in the background.
type stream struct {
	resp  *http.Response
	lines chan string
}

func (b *browser) stream(origin string) *stream {
	b.e.t.Helper()
	req, _ := http.NewRequest(http.MethodGet, b.e.pub.URL+"/api/v1/events", nil)
	req.Header.Set("Accept", "text/event-stream")
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	resp, err := b.client.Do(req)
	if err != nil {
		b.e.t.Fatal(err)
	}
	s := &stream{resp: resp, lines: make(chan string, 256)}
	go func() {
		defer close(s.lines)
		sc := bufio.NewScanner(resp.Body)
		for sc.Scan() {
			s.lines <- sc.Text()
		}
	}()
	b.e.t.Cleanup(func() { resp.Body.Close() })
	return s
}

// next returns the next line that starts with prefix ("" on timeout or end).
func (s *stream) next(t *testing.T, prefix string, within time.Duration) string {
	t.Helper()
	deadline := time.After(within)
	for {
		select {
		case l, ok := <-s.lines:
			if !ok {
				return ""
			}
			if strings.HasPrefix(l, prefix) {
				return l
			}
		case <-deadline:
			return ""
		}
	}
}

func (e *env) publish(token string, body any) (int, map[string]any) {
	e.t.Helper()
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, e.int.URL+"/internal/v1/events", strings.NewReader(string(b)))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := e.int.Client().Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func (e *env) event(typ, app, resource, subject string) map[string]any {
	return map[string]any{"type": typ, "applicationId": app, "resourceId": resource, "occurredAt": time.Now().UTC().Format(time.RFC3339Nano),
		"recipient": map[string]string{"issuer": e.dex.srv.URL, "subject": subject}}
}

func waitSubscribers(t *testing.T, h *hub.Hub, n int) {
	t.Helper()
	for i := 0; i < 200 && h.Len() != n; i++ {
		time.Sleep(10 * time.Millisecond)
	}
	if h.Len() != n {
		t.Fatalf("%d subscribers, want %d", h.Len(), n)
	}
}

// ------------------------------------------------------------------ human

func TestNoSession(t *testing.T) {
	e := newEnv(t)
	b := e.browser()
	// An EventSource gets 401 (it cannot follow a sign-in); a page is sent
	// to Dex.
	resp, body := b.get("/api/v1/events", "Accept", "text/event-stream", "Origin", uiOrigin)
	if resp.StatusCode != http.StatusUnauthorized || !strings.Contains(body, `"login":"`+e.pub.URL+`/login"`) ||
		resp.Header.Get("Access-Control-Allow-Origin") != uiOrigin || resp.Header.Get("Access-Control-Allow-Credentials") != "true" {
		t.Fatal(resp.StatusCode, body, resp.Header)
	}
	resp, _ = b.get("/api/v1/events")
	if resp.StatusCode != http.StatusFound || !strings.HasPrefix(resp.Header.Get("Location"), e.dex.srv.URL+"/auth?") {
		t.Fatal(resp.StatusCode, resp.Header.Get("Location"))
	}
	if resp, _ := b.get("/api/v1/session", "Origin", uiOrigin); resp.StatusCode != http.StatusUnauthorized {
		t.Fatal(resp.StatusCode)
	}
}

func TestSignInThenStream(t *testing.T) {
	e := newEnv(t)
	b := e.browser()
	b.mustSignIn("alice")
	if resp, body := b.get("/api/v1/session", "Origin", uiOrigin); resp.StatusCode != http.StatusOK || !strings.Contains(body, "alice@e2e.pathops.test") {
		t.Fatal(resp.StatusCode, body)
	}
	s := b.stream(uiOrigin)
	if s.resp.StatusCode != http.StatusOK || s.resp.Header.Get("Content-Type") != "text/event-stream" ||
		s.resp.Header.Get("X-Accel-Buffering") != "no" || s.resp.Header.Get("Cache-Control") != "no-store" ||
		s.resp.Header.Get("Access-Control-Allow-Origin") != uiOrigin {
		t.Fatal(s.resp.StatusCode, s.resp.Header)
	}
	if l := s.next(t, "retry:", time.Second); l != "retry: 5000" {
		t.Fatalf("retry line %q", l)
	}
	// Heartbeats are comments; several arrive and the stream stays open.
	for i := 0; i < 3; i++ {
		if l := s.next(t, ":", time.Second); l != ": heartbeat" && l != ": connected" {
			t.Fatalf("heartbeat %d: %q", i, l)
		}
	}
}

func TestSignInRefused(t *testing.T) {
	e := newEnv(t)
	otherKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	for name, over := range map[string]map[string]any{
		"wrong issuer":   {"iss": "https://dex.other-cell.example"},
		"wrong audience": {"aud": "pathops-ui"},
		"wrong nonce":    {"nonce": "replayed"},
		"expired":        {"exp": time.Now().Unix() - 10},
		"another key":    {"signer": otherKey},
	} {
		b := e.browser()
		if resp := b.signIn("alice", over); resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s: %d", name, resp.StatusCode)
		}
		if resp, _ := b.get("/api/v1/session"); resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("%s: a session was created", name)
		}
	}
	// A callback with an unknown state, or from another browser than the
	// one that started the sign-in, is refused.
	b := e.browser()
	if resp, _ := b.get("/oauth2/callback?code=x&state=unknown"); resp.StatusCode != http.StatusUnauthorized {
		t.Fatal(resp.StatusCode)
	}
	resp, _ := b.get("/login")
	loc, _ := url.Parse(resp.Header.Get("Location"))
	if resp, _ := e.browser().get("/oauth2/callback?code=x&state=" + url.QueryEscape(loc.Query().Get("state"))); resp.StatusCode != http.StatusUnauthorized {
		t.Fatal("callback from another browser:", resp.StatusCode)
	}
}

func TestCookieTamperingAndLogout(t *testing.T) {
	e := newEnv(t)
	b := e.browser()
	b.mustSignIn("alice")
	u, _ := url.Parse(e.pub.URL)
	var real string
	for _, c := range b.client.Jar.Cookies(u) {
		if c.Name == human.SessionCookie {
			real = c.Value
		}
	}
	for _, forged := range []string{"forged", real + "x", strings.ToUpper(real)} {
		f := e.browser()
		f.client.Jar.SetCookies(u, []*http.Cookie{{Name: human.SessionCookie, Value: forged}})
		if resp, _ := f.get("/api/v1/events", "Accept", "text/event-stream"); resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("forged session %q: %d", forged, resp.StatusCode)
		}
	}
	// Sign-out: only from the PathOps UI or this host.
	req, _ := http.NewRequest(http.MethodPost, e.pub.URL+"/logout", nil)
	req.Header.Set("Origin", "https://evil.example")
	if resp, _ := b.client.Do(req); resp.StatusCode != http.StatusForbidden {
		t.Fatal("logout from another origin:", resp.StatusCode)
	}
	req, _ = http.NewRequest(http.MethodPost, e.pub.URL+"/logout", nil)
	req.Header.Set("Origin", uiOrigin)
	if resp, err := b.client.Do(req); err != nil || resp.StatusCode != http.StatusNoContent {
		t.Fatal("logout:", resp, err)
	}
	if resp, _ := b.get("/api/v1/session"); resp.StatusCode != http.StatusUnauthorized {
		t.Fatal("still signed in after logout")
	}
}

func TestOriginsAndReturns(t *testing.T) {
	e := newEnv(t)
	b := e.browser()
	b.mustSignIn("alice")
	if resp, _ := b.get("/api/v1/events", "Accept", "text/event-stream", "Origin", "https://evil.example"); resp.StatusCode != http.StatusForbidden ||
		resp.Header.Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("another origin:", resp.StatusCode)
	}
	for _, ret := range []string{"https://evil.example/", "http://control-plane-acme.demo.pathops.io/", "//evil.example", "javascript:alert(1)",
		"https://user@control-plane-acme.demo.pathops.io/"} {
		if resp, _ := b.get("/login?return=" + url.QueryEscape(ret)); resp.StatusCode != http.StatusBadRequest {
			t.Errorf("return %q: %d", ret, resp.StatusCode)
		}
	}
}

// -------------------------------------------------------------------- SSE

func TestFanOutFilteredByPerson(t *testing.T) {
	e := newEnv(t)
	a1, a2, bob := e.browser(), e.browser(), e.browser()
	a1.mustSignIn("alice")
	a2.mustSignIn("alice")
	bob.mustSignIn("bob")
	s1, s2, sb := a1.stream(uiOrigin), a2.stream(""), bob.stream(uiOrigin)
	waitSubscribers(t, e.s.Hub, 3)

	code, out := e.publish(tcpToken, e.event(hub.BuildChanged, appA, buildA, "alice"))
	if code != http.StatusAccepted || out["delivered"] != float64(2) {
		t.Fatal(code, out)
	}
	for _, s := range []*stream{s1, s2} {
		l := s.next(t, "data: ", time.Second)
		var got map[string]any
		if err := json.Unmarshal([]byte(strings.TrimPrefix(l, "data: ")), &got); err != nil {
			t.Fatalf("not JSON: %q", l)
		}
		// The invalidation only: no recipient, no domain state.
		if len(got) != 4 || got["type"] != hub.BuildChanged || got["applicationId"] != appA || got["resourceId"] != buildA || got["occurredAt"] == nil {
			t.Fatalf("event %v", got)
		}
	}
	// Bob receives nothing of alice's: only heartbeats.
	if l := sb.next(t, "data: ", 200*time.Millisecond); l != "" {
		t.Fatalf("bob received %q", l)
	}
	// Bob's own Application.
	if code, out := e.publish(tcpToken, e.event(hub.InboxChanged, appB, "", "bob")); code != http.StatusAccepted || out["delivered"] != float64(1) {
		t.Fatal(code, out)
	}
	if l := sb.next(t, "data: ", time.Second); !strings.Contains(l, `"type":"INBOX_CHANGED"`) || strings.Contains(l, "resourceId") {
		t.Fatalf("bob's event %q", l)
	}
	// An Application's own change names no resource.
	if code, out := e.publish(tcpToken, e.event(hub.ApplicationChanged, appB, "", "bob")); code != http.StatusAccepted || out["delivered"] != float64(1) {
		t.Fatal(code, out)
	}
	if l := sb.next(t, "data: ", time.Second); !strings.Contains(l, `"type":"APPLICATION_CHANGED"`) || !strings.Contains(l, appB) || strings.Contains(l, "resourceId") {
		t.Fatalf("bob's event %q", l)
	}
}

func TestDisconnectCleansUp(t *testing.T) {
	e := newEnv(t)
	b := e.browser()
	b.mustSignIn("alice")
	s := b.stream(uiOrigin)
	waitSubscribers(t, e.s.Hub, 1)
	s.resp.Body.Close()
	waitSubscribers(t, e.s.Hub, 0)
	if code, out := e.publish(tcpToken, e.event(hub.DeliveryChanged, appA, buildA2, "alice")); code != http.StatusAccepted || out["delivered"] != float64(0) {
		t.Fatal(code, out)
	}
}

func TestStreamEndsWithTheSession(t *testing.T) {
	e := newEnv(t)
	b := e.browser()
	b.mustSignIn("alice")
	s := b.stream(uiOrigin)
	waitSubscribers(t, e.s.Hub, 1)
	req, _ := http.NewRequest(http.MethodPost, e.pub.URL+"/logout", nil)
	req.Header.Set("Origin", uiOrigin)
	if _, err := b.client.Do(req); err != nil {
		t.Fatal(err)
	}
	// The next heartbeat finds no session and ends the stream.
	waitSubscribers(t, e.s.Hub, 0)
	for range s.lines {
	}
}

// ---------------------------------------------------------------- publish

func TestPublishAuthentication(t *testing.T) {
	e := newEnv(t)
	ev := e.event(hub.BuildChanged, appA, buildA, "alice")
	for name, token := range map[string]string{"no token": "", "unknown token": "someone-else", "a person's session value": "alice"} {
		if code, _ := e.publish(token, ev); code != http.StatusUnauthorized {
			t.Errorf("%s: %d", name, code)
		}
	}
	if code, _ := e.publish("down", ev); code != http.StatusServiceUnavailable {
		t.Errorf("review unavailable: %d", code)
	}
	// The publish path is not on the public listener, nor SSE on the
	// internal one.
	req, _ := http.NewRequest(http.MethodPost, e.pub.URL+"/internal/v1/events", strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer "+tcpToken)
	if resp, err := e.pub.Client().Do(req); err != nil || resp.StatusCode != http.StatusNotFound && resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatal("publish on the public listener:", resp.StatusCode, err)
	}
	if resp, err := e.int.Client().Get(e.int.URL + "/api/v1/events"); err != nil || resp.StatusCode != http.StatusNotFound {
		t.Fatal("SSE on the internal listener:", resp.StatusCode, err)
	}
}

func TestPublishValidation(t *testing.T) {
	e := newEnv(t)
	bad := map[string]func(map[string]any){
		"unknown type":              func(m map[string]any) { m["type"] = "APPLICATION_DELETED" },
		"app not a UUID":            func(m map[string]any) { m["applicationId"] = "hello" },
		"resource not a UUID":       func(m map[string]any) { m["resourceId"] = "../x" },
		"build without resource":    func(m map[string]any) { delete(m, "resourceId") },
		"application with resource": func(m map[string]any) { m["type"] = hub.ApplicationChanged },
		"future":                    func(m map[string]any) { m["occurredAt"] = time.Now().Add(time.Hour).Format(time.RFC3339) },
		"no time":                   func(m map[string]any) { delete(m, "occurredAt") },
		"recipient of another IdP": func(m map[string]any) {
			m["recipient"] = map[string]string{"issuer": "https://evil", "subject": "alice"}
		},
		"no recipient":       func(m map[string]any) { delete(m, "recipient") },
		"full domain object": func(m map[string]any) { m["build"] = map[string]any{"status": "FAILED", "logs": "..."} },
	}
	for name, mutate := range bad {
		ev := e.event(hub.BuildChanged, appA, buildA, "alice")
		mutate(ev)
		if code, _ := e.publish(tcpToken, ev); code != http.StatusUnprocessableEntity && code != http.StatusBadRequest {
			t.Errorf("%s: %d", name, code)
		}
	}
	big := e.event(hub.BuildChanged, appA, buildA, strings.Repeat("a", MaxEventBytes))
	if code, _ := e.publish(tcpToken, big); code != http.StatusBadRequest && code != http.StatusUnprocessableEntity {
		t.Errorf("oversized: %d", code)
	}
}
