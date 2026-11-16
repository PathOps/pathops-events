package server

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/zishang520/socket.io/servers/engine/v3"
	"github.com/zishang520/socket.io/servers/socket/v3"
	"github.com/zishang520/socket.io/v3/pkg/types"

	"github.com/PathOps/pathops-events/internal/hub"
	"github.com/PathOps/pathops-events/internal/token"
)

// The browsers' Socket.IO connection (Decision 0063), at /socket.io/ of the
// public listener:
//
//   - WebSocket only (no long-polling, no upgrade): one TLS connection
//     through Traefik's passthrough;
//   - Origin exactly the PathOps UI's (checked on the handshake request, so
//     the WebSocket upgrade is covered too, which CORS does not reach);
//   - the person's PathOps token in the handshake's auth payload
//     ({token: "<access token>"}), never in a URL, cookie or log; refused
//     with "unauthorized" (or "unavailable" while Dex's keys cannot be read);
//   - one invalidation per "invalidate" event: {type, applicationId,
//     resourceId?, occurredAt};
//   - the connection lasts while the token is valid: "reauth" with a newer
//     token of the same person (ack {ok: true} or {error}) extends it; at the
//     token's expiry the server disconnects and the browser connects again
//     with its current token;
//   - Socket.IO's own ping/pong keeps it alive and finds dead peers; there is
//     no other heartbeat.
const (
	EventInvalidate = "invalidate"
	EventReauth     = "reauth"
)

// The connect_error messages a browser can see.
const (
	refusedUnauthorized = "unauthorized"
	refusedUnavailable  = "unavailable"
	refusedTooMany      = "too_many_connections"
)

// verifyTimeout bounds one token verification (Dex's keys may be fetched).
const verifyTimeout = 10 * time.Second

var errOrigin = errors.New("origin not allowed")

// People verifies a person's PathOps token (internal/token).
type People interface {
	Verify(ctx context.Context, raw string) (token.Identity, error)
}

// conn is one browser connection: its person, its hub subscription and the
// token expiry it may live until.
type conn struct {
	person hub.Person
	sub    *hub.Subscriber
	renew  chan struct{} // the expiry changed

	mu     sync.Mutex
	expiry time.Time
}

func (c *conn) until() time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return time.Until(c.expiry)
}

// live returns the Socket.IO handler.
func (s *Server) live() http.Handler {
	opts := socket.DefaultServerOptions()
	opts.SetServeClient(false)
	opts.SetTransports(types.NewSet(engine.WebSocket))
	opts.SetAllowUpgrades(false)
	// The WebSocket upgrade checks Origin against this too.
	opts.SetCors(&types.Cors{Origin: s.AllowedOrigin, Methods: []string{http.MethodGet}})
	opts.SetAllowRequest(func(ctx *types.HttpContext) error {
		if ctx.Headers().Peek("Origin") != s.AllowedOrigin {
			return errOrigin
		}
		return nil
	})
	if s.PingInterval > 0 {
		opts.SetPingInterval(s.PingInterval)
	}
	if s.PingTimeout > 0 {
		opts.SetPingTimeout(s.PingTimeout)
	}
	// A handshake carries one token; nothing larger comes from a browser.
	opts.SetMaxHttpBufferSize(16 << 10)
	opts.SetConnectTimeout(10 * time.Second)

	io := socket.NewServer(nil, nil)
	io.Use(s.authenticate)
	_ = io.On("connection", func(args ...any) {
		if sk, ok := args[0].(*socket.Socket); ok {
			s.connected(sk)
		}
	})
	return io.ServeHandler(opts)
}

// auth reads the token of a handshake's auth payload.
func auth(sk *socket.Socket) string {
	t, _ := sk.Handshake().Auth["token"].(string)
	return t
}

// authenticate admits a handshake with a valid PathOps token and subscribes
// its person; the reason of a refusal is logged by label, the token never.
func (s *Server) authenticate(sk *socket.Socket, next func(*socket.ExtendedError)) {
	ctx, cancel := context.WithTimeout(context.Background(), verifyTimeout)
	defer cancel()
	id, err := s.People.Verify(ctx, auth(sk))
	if err != nil {
		if errors.Is(err, token.ErrUnavailable) {
			s.Log.Warn("person not verified", "reason", token.Reason(err))
			next(socket.NewExtendedError(refusedUnavailable, nil))
			return
		}
		s.Log.Info("person refused", "reason", token.Reason(err))
		next(socket.NewExtendedError(refusedUnauthorized, nil))
		return
	}
	p := hub.Person{Issuer: id.Issuer, Subject: id.Subject}
	sub, err := s.Hub.Subscribe(p)
	if errors.Is(err, hub.ErrClosed) {
		next(socket.NewExtendedError(refusedUnavailable, nil))
		return
	}
	if err != nil {
		next(socket.NewExtendedError(refusedTooMany, nil))
		return
	}
	sk.SetData(&conn{person: p, sub: sub, renew: make(chan struct{}, 1), expiry: id.Expiry})
	next(nil)
}

// connected pumps the person's invalidations to the browser until it leaves,
// lags, the hub closes or the token expires.
func (s *Server) connected(sk *socket.Socket) {
	c, ok := sk.Data().(*conn)
	if !ok {
		sk.Disconnect(true)
		return
	}
	_ = sk.On("disconnect", func(...any) { s.Hub.Unsubscribe(c.sub) })
	_ = sk.On(EventReauth, func(args ...any) { s.reauth(c, args) })
	go func() {
		expiry := time.NewTimer(c.until())
		defer expiry.Stop()
		for {
			select {
			case ev := <-c.sub.C:
				_ = sk.Emit(EventInvalidate, ev)
			case <-c.sub.Done():
				// Lagged, gone or shutting down: the browser connects again
				// and reads REST.
				sk.Disconnect(true)
				return
			case <-c.renew:
				expiry.Reset(c.until())
			case <-expiry.C:
				s.Log.Info("token expired, disconnected")
				sk.Disconnect(true)
				return
			}
		}
	}()
}

// reauth extends a connection with a newer token of the same person.
func (s *Server) reauth(c *conn, args []any) {
	var ack socket.Ack
	if n := len(args); n > 0 {
		ack, _ = args[n-1].(socket.Ack)
	}
	reply := func(v map[string]any) {
		if ack != nil {
			ack([]any{v}, nil)
		}
	}
	var raw string
	if len(args) > 0 {
		if m, ok := args[0].(map[string]any); ok {
			raw, _ = m["token"].(string)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), verifyTimeout)
	defer cancel()
	id, err := s.People.Verify(ctx, raw)
	switch {
	case err != nil:
		s.Log.Info("reauth refused", "reason", token.Reason(err))
		reply(map[string]any{"error": refusedUnauthorized})
		return
	case id.Issuer != c.person.Issuer || id.Subject != c.person.Subject:
		s.Log.Info("reauth refused", "reason", "another_person")
		reply(map[string]any{"error": refusedUnauthorized})
		return
	}
	c.mu.Lock()
	if id.Expiry.After(c.expiry) {
		c.expiry = id.Expiry
	}
	c.mu.Unlock()
	select {
	case c.renew <- struct{}{}:
	default: // one signal is pending already
	}
	reply(map[string]any{"ok": true})
}
