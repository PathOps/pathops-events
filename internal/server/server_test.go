package server

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"

	"github.com/PathOps/pathops-events/internal/hub"
	"github.com/PathOps/pathops-events/internal/oidctest"
	"github.com/PathOps/pathops-events/internal/token"
	"github.com/PathOps/pathops-events/internal/workload"
)

const (
	uiAudience = "pathops-ui"
	uiOrigin   = "https://control-plane-acme.demo.pathops.io"
	appA       = "11111111-1111-4111-8111-111111111111"
	appB       = "22222222-2222-4222-8222-222222222222"
	buildA     = "33333333-3333-4333-8333-333333333333"
	buildA2    = "44444444-4444-4444-8444-444444444444"
	tcpToken   = "tcp-token"
)

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

// logBuf is a log a test reads.
type logBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *logBuf) Write(p []byte) (int, error) { l.mu.Lock(); defer l.mu.Unlock(); return l.b.Write(p) }
func (l *logBuf) String() string              { l.mu.Lock(); defer l.mu.Unlock(); return l.b.String() }

type env struct {
	t        *testing.T
	s        *Server
	pub, int *httptest.Server
	dex      *oidctest.Issuer
	logs     *logBuf
	tokens   []string
}

// newEnv: pathops-events with the Cell's Dex (oidctest) as the issuer of
// PathOps tokens, for the PathOps UI's audience.
func newEnv(t *testing.T) *env {
	d := oidctest.New(t)
	e := &env{t: t, dex: d, logs: &logBuf{}}
	e.s = &Server{Hub: &hub.Hub{}, People: token.NewVerifier(d.URL, uiAudience, d.Roots()), Publishers: publishers{},
		AllowedOrigin: uiOrigin, Issuer: d.URL, PingInterval: 100 * time.Millisecond, PingTimeout: 300 * time.Millisecond,
		Log: slog.New(slog.NewJSONHandler(e.logs, nil))}
	e.pub = httptest.NewTLSServer(e.s.Public())
	t.Cleanup(e.pub.Close)
	e.int = httptest.NewTLSServer(e.s.Internal())
	t.Cleanup(e.int.Close)
	t.Cleanup(func() {
		for _, tok := range e.tokens {
			if strings.Contains(e.logs.String(), tok) || strings.Contains(e.logs.String(), strings.Split(tok, ".")[2]) {
				t.Error("a token reached the log")
			}
		}
	})
	return e
}

// tok mints a PathOps token of the Cell's Dex for subject (edit changes its
// claims first).
func (e *env) tok(subject string, edit func(*oidctest.Claims)) string {
	c := e.dex.Claims(time.Now(), uiAudience, subject)
	if edit != nil {
		edit(&c)
	}
	t := oidctest.Mint(e.t, e.dex.Key(), c)
	e.tokens = append(e.tokens, t)
	return t
}

// sio is a raw Socket.IO v5 client over Engine.IO v4 WebSocket frames: the
// wire protocol socket.io-client speaks. It answers the server's pings.
type sio struct {
	t      *testing.T
	ws     *websocket.Conn
	in     chan string
	closed chan struct{}
	mu     sync.Mutex
	pong   bool
}

func (e *env) dial(origin string) (*sio, *http.Response, error) {
	d := websocket.Dialer{TLSClientConfig: e.pub.Client().Transport.(*http.Transport).TLSClientConfig.Clone(), HandshakeTimeout: 5 * time.Second}
	h := http.Header{}
	if origin != "" {
		h.Set("Origin", origin)
	}
	ws, resp, err := d.Dial("wss"+strings.TrimPrefix(e.pub.URL, "https")+"/socket.io/?EIO=4&transport=websocket", h)
	if err != nil {
		return nil, resp, err
	}
	c := &sio{t: e.t, ws: ws, in: make(chan string, 64), closed: make(chan struct{}), pong: true}
	go func() {
		defer close(c.closed)
		for {
			_, b, err := ws.ReadMessage()
			if err != nil {
				return
			}
			m := string(b)
			if m == "2" {
				c.mu.Lock()
				answer := c.pong
				c.mu.Unlock()
				if answer {
					c.send("3")
				}
				continue
			}
			c.in <- m
		}
	}()
	e.t.Cleanup(func() { _ = ws.Close() })
	return c, resp, nil
}

func (c *sio) send(m string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	_ = c.ws.WriteMessage(websocket.TextMessage, []byte(m))
}

// next is the next message, "" if none within d (or the connection closed).
func (c *sio) next(d time.Duration) string {
	select {
	case m := <-c.in:
		return m
	case <-c.closed:
		return ""
	case <-time.After(d):
		return ""
	}
}

// gone reports whether the server closed the connection within d (the
// transport, so socket.io-client reconnects by itself with its current token).
func (c *sio) gone(d time.Duration) bool {
	deadline := time.After(d)
	for {
		select {
		case <-c.closed:
			return true
		case <-c.in:
		case <-deadline:
			return false
		}
	}
}

// connect opens a connection and sends the CONNECT packet with auth (nil:
// none); it returns the connection and the server's answer to the CONNECT.
func (e *env) connect(auth map[string]any) (*sio, string) {
	e.t.Helper()
	c, _, err := e.dial(uiOrigin)
	if err != nil {
		e.t.Fatal(err)
	}
	if open := c.next(2 * time.Second); !strings.HasPrefix(open, "0{") {
		e.t.Fatalf("open packet %q", open)
	}
	if auth == nil {
		c.send("40")
	} else {
		b, _ := json.Marshal(auth)
		c.send("40" + string(b))
	}
	return c, c.next(2 * time.Second)
}

// refused is the CONNECT_ERROR message of an answer ("" when it is not one).
func refused(ans string) string {
	var v struct {
		Message string `json:"message"`
	}
	if !strings.HasPrefix(ans, "44") || json.Unmarshal([]byte(ans[2:]), &v) != nil {
		return ""
	}
	return v.Message
}

// person connects with a valid PathOps token of subject.
func (e *env) person(subject string) *sio {
	e.t.Helper()
	c, ans := e.connect(map[string]any{"token": e.tok(subject, nil)})
	if !strings.HasPrefix(ans, `40{"sid":"`) {
		e.t.Fatalf("connect: %q", ans)
	}
	return c
}

// invalidation is the next "invalidate" event's payload ("" if none).
func (c *sio) invalidation(d time.Duration) map[string]any {
	for {
		m := c.next(d)
		if m == "" {
			return nil
		}
		var ev []json.RawMessage
		if !strings.HasPrefix(m, "42") || json.Unmarshal([]byte(m[2:]), &ev) != nil || len(ev) != 2 || string(ev[0]) != `"`+EventInvalidate+`"` {
			continue
		}
		var out map[string]any
		_ = json.Unmarshal(ev[1], &out)
		return out
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
		"recipient": map[string]string{"issuer": e.dex.URL, "subject": subject}}
}

func waitSubscribers(t *testing.T, h *hub.Hub, n int) {
	t.Helper()
	for i := 0; i < 300 && h.Len() != n; i++ {
		time.Sleep(10 * time.Millisecond)
	}
	if h.Len() != n {
		t.Fatalf("%d subscribers, want %d", h.Len(), n)
	}
}

// ------------------------------------------------------------------ people

// The PathOps token in the handshake's auth payload connects; the person's
// invalidations arrive as "invalidate" events with exactly the four fields.
func TestConnectWithThePathOpsToken(t *testing.T) {
	e := newEnv(t)
	c := e.person("alice")
	waitSubscribers(t, e.s.Hub, 1)
	if code, out := e.publish(tcpToken, e.event(hub.BuildChanged, appA, buildA, "alice")); code != http.StatusAccepted || out["delivered"] != float64(1) {
		t.Fatal(code, out)
	}
	ev := c.invalidation(time.Second)
	if len(ev) != 4 || ev["type"] != hub.BuildChanged || ev["applicationId"] != appA || ev["resourceId"] != buildA || ev["occurredAt"] == nil {
		t.Fatalf("%v", ev)
	}
}

// Anything but a valid PathOps token is refused at the CONNECT, and no
// subscription is left behind.
func TestConnectRefused(t *testing.T) {
	e := newEnv(t)
	other := oidctest.New(t)
	foreign := oidctest.Mint(t, other.Key(), other.Claims(time.Now(), uiAudience, "alice"))
	good := e.tok("alice", nil)
	parts := strings.Split(good, ".")
	tampered := parts[0] + "." + strings.Split(e.tok("mallory", nil), ".")[1] + "." + parts[2]
	now := time.Now()
	oat := oidctest.MintTyped(t, e.dex.Key(), token.OperationAuthorizationType, map[string]any{"iss": e.dex.URL, "sub": "alice",
		"aud": uiAudience, "iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix()})
	e.tokens = append(e.tokens, foreign, tampered, oat)
	for name, auth := range map[string]map[string]any{
		"no auth":            nil,
		"no token":           {},
		"empty token":        {"token": ""},
		"not a string":       {"token": 42},
		"not a JWT":          {"token": "hello"},
		"expired":            {"token": e.tok("alice", func(c *oidctest.Claims) { c.IssuedAt, c.Expiry = now.Add(-10*time.Minute), now.Add(-time.Minute) })},
		"wrong issuer":       {"token": e.tok("alice", func(c *oidctest.Claims) { c.Issuer = "https://dex-globex.demo.pathops.io" })},
		"another Dex's key":  {"token": foreign},
		"the CLI's audience": {"token": e.tok("alice", func(c *oidctest.Claims) { c.Audience = []string{"pathops-cli"} })},
		"Events' audience":   {"token": e.tok("alice", func(c *oidctest.Claims) { c.Audience = []string{"pathops-events"} })},
		"no subject":         {"token": e.tok("", nil)},
		"not yet valid":      {"token": e.tok("alice", func(c *oidctest.Claims) { c.NotBefore = now.Add(time.Minute) })},
		"tampered":           {"token": tampered},
		"operation token":    {"token": oat},
		"in the bearer slot": {"Authorization": "Bearer " + good},
	} {
		t.Run(name, func(t *testing.T) {
			c, ans := e.connect(auth)
			if refused(ans) != "unauthorized" {
				t.Fatalf("answer %q", ans)
			}
			_ = c.ws.Close()
			waitSubscribers(t, e.s.Hub, 0)
		})
	}
	if !strings.Contains(e.logs.String(), `"reason":"expired"`) || !strings.Contains(e.logs.String(), `"reason":"audience_mismatch"`) {
		t.Fatalf("refusals are not logged by reason: %s", e.logs.String())
	}
}

// While Dex's keys cannot be read the token is not judged: "unavailable"
// (the browser tries again).
func TestConnectWhileDexIsDown(t *testing.T) {
	e := newEnv(t)
	tok := e.tok("alice", nil)
	e.dex.SetDown(true)
	if _, ans := e.connect(map[string]any{"token": tok}); refused(ans) != "unavailable" {
		t.Fatalf("answer %q", ans)
	}
}

// Only the PathOps UI's origin connects (the WebSocket upgrade included);
// long-polling is not served.
func TestOriginAndTransport(t *testing.T) {
	e := newEnv(t)
	for _, origin := range []string{"", "https://evil.example", "https://control-plane-acme.demo.pathops.io.evil.example", "http://control-plane-acme.demo.pathops.io"} {
		if _, resp, err := e.dial(origin); err == nil || resp == nil || resp.StatusCode < 400 {
			t.Errorf("origin %q connected", origin)
		}
	}
	req, _ := http.NewRequest(http.MethodGet, e.pub.URL+"/socket.io/?EIO=4&transport=polling", nil)
	req.Header.Set("Origin", uiOrigin)
	resp, err := e.pub.Client().Do(req)
	if err != nil || resp.StatusCode < 400 {
		t.Fatalf("polling: %v %v", resp.StatusCode, err)
	}
	if resp.Header.Get("Access-Control-Allow-Origin") == "*" {
		t.Fatal("wildcard CORS")
	}
}

// An invalidation reaches only the connections of the person it names,
// every one of them (several browsers).
func TestFanOutFilteredByPerson(t *testing.T) {
	e := newEnv(t)
	a1, a2, b := e.person("alice"), e.person("alice"), e.person("bob")
	waitSubscribers(t, e.s.Hub, 3)
	if code, out := e.publish(tcpToken, e.event(hub.DeliveryChanged, appA, buildA, "alice")); code != http.StatusAccepted || out["delivered"] != float64(2) {
		t.Fatal(code, out)
	}
	for i, c := range []*sio{a1, a2} {
		if ev := c.invalidation(time.Second); ev["type"] != hub.DeliveryChanged {
			t.Fatalf("alice %d: %v", i, ev)
		}
	}
	if ev := b.invalidation(300 * time.Millisecond); ev != nil {
		t.Fatalf("bob received alice's %v", ev)
	}
	if code, out := e.publish(tcpToken, e.event(hub.InboxChanged, appB, "", "bob")); code != http.StatusAccepted || out["delivered"] != float64(1) {
		t.Fatal(code, out)
	}
	if ev := b.invalidation(time.Second); ev["type"] != hub.InboxChanged || ev["resourceId"] != nil {
		t.Fatalf("bob: %v", ev)
	}
	if ev := a1.invalidation(300 * time.Millisecond); ev != nil {
		t.Fatalf("alice received bob's %v", ev)
	}
}

// A browser that leaves (or stops answering pings) is unsubscribed; one
// that comes back with its token is subscribed again.
func TestDisconnectAndReconnect(t *testing.T) {
	e := newEnv(t)
	c := e.person("alice")
	waitSubscribers(t, e.s.Hub, 1)
	c.send("41")
	waitSubscribers(t, e.s.Hub, 0)
	if _, out := e.publish(tcpToken, e.event(hub.BuildChanged, appA, buildA, "alice")); out["delivered"] != float64(0) {
		t.Fatal(out)
	}
	c = e.person("alice")
	waitSubscribers(t, e.s.Hub, 1)
	// Socket.IO's ping/pong: a peer that stops answering is dropped.
	c.mu.Lock()
	c.pong = false
	c.mu.Unlock()
	waitSubscribers(t, e.s.Hub, 0)
	c = e.person("alice")
	time.Sleep(time.Second) // answering pings: still there
	waitSubscribers(t, e.s.Hub, 1)
	if _, out := e.publish(tcpToken, e.event(hub.BuildChanged, appA, buildA2, "alice")); out["delivered"] != float64(1) {
		t.Fatal(out)
	}
	if ev := c.invalidation(time.Second); ev["resourceId"] != buildA2 {
		t.Fatal(ev)
	}
}

// A connection lasts while its token is valid; "reauth" with a newer token
// of the same person extends it, another person's does not.
func TestTokenExpiryAndReauth(t *testing.T) {
	e := newEnv(t)
	// exp has a resolution of seconds.
	short := func(c *oidctest.Claims) { c.Expiry = time.Now().Add(2 * time.Second) }
	c, ans := e.connect(map[string]any{"token": e.tok("alice", short)})
	if !strings.HasPrefix(ans, "40{") {
		t.Fatal(ans)
	}
	waitSubscribers(t, e.s.Hub, 1)
	// Expires: the server closes it.
	if !c.gone(4 * time.Second) {
		t.Fatal("still open after the token expired")
	}
	waitSubscribers(t, e.s.Hub, 0)

	c, _ = e.connect(map[string]any{"token": e.tok("alice", short)})
	b, _ := json.Marshal([]any{EventReauth, map[string]string{"token": e.tok("bob", nil)}})
	c.send("421" + string(b))
	if m := c.next(time.Second); m != `431[{"error":"unauthorized"}]` {
		t.Fatalf("another person's reauth: %q", m)
	}
	b, _ = json.Marshal([]any{EventReauth, map[string]string{"token": e.tok("alice", nil)}})
	c.send("422" + string(b))
	if m := c.next(time.Second); m != `432[{"ok":true}]` {
		t.Fatalf("reauth: %q", m)
	}
	time.Sleep(3 * time.Second) // past the first token's expiry
	if _, out := e.publish(tcpToken, e.event(hub.BuildChanged, appA, buildA, "alice")); out["delivered"] != float64(1) {
		t.Fatalf("not extended: %v", out)
	}
	if ev := c.invalidation(time.Second); ev["type"] != hub.BuildChanged {
		t.Fatal(ev)
	}
	b, _ = json.Marshal([]any{EventReauth, map[string]string{"token": "garbage"}})
	c.send("423" + string(b))
	if m := c.next(time.Second); m != `433[{"error":"unauthorized"}]` {
		t.Fatalf("bad reauth: %q", m)
	}
}

// The hub closing (shutdown) ends every connection.
func TestShutdownEndsConnections(t *testing.T) {
	e := newEnv(t)
	c := e.person("alice")
	waitSubscribers(t, e.s.Hub, 1)
	e.s.Hub.Close()
	if !c.gone(2 * time.Second) {
		t.Fatal("still open after the hub closed")
	}
	if _, ans := e.connect(map[string]any{"token": e.tok("alice", nil)}); refused(ans) != "unavailable" {
		t.Fatalf("after close %q", ans)
	}
}

func TestHomeAndHealth(t *testing.T) {
	e := newEnv(t)
	for _, p := range []string{"/", "/healthz"} {
		resp, err := e.pub.Client().Get(e.pub.URL + p)
		if err != nil || resp.StatusCode != http.StatusOK || resp.Header.Get("Set-Cookie") != "" {
			t.Fatalf("%s: %v %v", p, resp, err)
		}
	}
	for _, p := range []string{"/login", "/oauth2/callback", "/api/v1/events", "/api/v1/session"} {
		resp, err := e.pub.Client().Get(e.pub.URL + p)
		if err != nil || resp.StatusCode != http.StatusNotFound {
			t.Fatalf("%s still served: %v %v", p, resp.StatusCode, err)
		}
	}
}

// ------------------------------------------------------------------ the Tenant CP

func TestPublishAuthentication(t *testing.T) {
	e := newEnv(t)
	ev := e.event(hub.BuildChanged, appA, buildA, "alice")
	for name, token := range map[string]string{"no token": "", "unknown token": "someone-else", "a person's PathOps token": e.tok("alice", nil)} {
		if code, _ := e.publish(token, ev); code != http.StatusUnauthorized {
			t.Errorf("%s: %d", name, code)
		}
	}
	if code, _ := e.publish("down", ev); code != http.StatusServiceUnavailable {
		t.Errorf("review unavailable: %d", code)
	}
	// The publish path is not on the public listener, nor Socket.IO on
	// the internal one.
	req, _ := http.NewRequest(http.MethodPost, e.pub.URL+"/internal/v1/events", strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer "+tcpToken)
	if resp, err := e.pub.Client().Do(req); err != nil || resp.StatusCode != http.StatusNotFound && resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatal("publish on the public listener:", resp.StatusCode, err)
	}
	if resp, err := e.int.Client().Get(e.int.URL + "/socket.io/?EIO=4&transport=websocket"); err != nil || resp.StatusCode != http.StatusNotFound {
		t.Fatal("Socket.IO on the internal listener:", resp.StatusCode, err)
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
