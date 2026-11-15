// Package server is pathops-events' HTTP API (Decision 0063): two HTTPS
// listeners, never one handler for both.
//
// Public (browsers, https://events-<cell>.<domain>, Dex sign-in):
//
//	GET  /api/v1/events    the signed-in person's invalidations as Server-Sent
//	                       Events; without a session 401 for an EventSource
//	                       (Accept: text/event-stream), otherwise 302 to Dex
//	GET  /api/v1/session   200 when signed in, 401 otherwise (the PathOps UI
//	                       checks before it starts a sign-in here)
//	GET  /login?return=U   sign in at Dex, then back to U (the PathOps UI or
//	                       this host only)
//	GET  /oauth2/callback  the end of a sign-in
//	POST /logout           end the session (from the PathOps UI or this host)
//	GET  /healthz          liveness
//
// The PathOps UI is another origin of the same site: these answers allow it
// (CORS with credentials) and no other origin; a request from another origin
// that carries an Origin header is refused.
//
// Internal (the Tenant Control Plane, on the Kubernetes Service only):
//
//	POST /internal/v1/events  one invalidation for one person (202), from
//	                          the expected ServiceAccount's short-lived token
//	GET  /healthz             liveness
//
// An invalidation says what changed, never its new state: REST stays the
// source of truth, and nothing here is persisted.
package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/PathOps/pathops-events/internal/hub"
	"github.com/PathOps/pathops-events/internal/human"
	"github.com/PathOps/pathops-events/internal/workload"
)

// People signs people in (internal/human).
type People interface {
	Session(r *http.Request) (human.Identity, bool)
	Login(ctx context.Context, w http.ResponseWriter, returnTo string) error
	Callback(ctx context.Context, w http.ResponseWriter, r *http.Request) (string, error)
	Logout(w http.ResponseWriter, r *http.Request)
}

// Publishers authenticates a publisher's bearer token (internal/workload).
type Publishers interface {
	Verify(ctx context.Context, token string) (string, error)
}

// Server serves both APIs.
type Server struct {
	Hub        *hub.Hub
	People     People
	Publishers Publishers
	// PublicURL is this host's (https://events-<cell>.<domain>);
	// AllowedOrigin the PathOps UI's; Issuer the Cell Dex's (an
	// invalidation names a person of this issuer).
	PublicURL, AllowedOrigin, Issuer string
	// Heartbeat is the interval of the SSE comment that keeps a stream
	// alive through proxies; Retry the reconnection delay EventSource is
	// told.
	Heartbeat, Retry time.Duration
	Log              *slog.Logger
	Now              func() time.Time
}

// MaxEventBytes bounds a published invalidation.
const MaxEventBytes = 4096

// writeTimeout bounds one write to a browser: a connection that cannot take
// a heartbeat in that time is dead.
const writeTimeout = 10 * time.Second

// Public is the browsers' API.
func (s *Server) Public() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", health)
	mux.HandleFunc("GET /api/v1/events", s.events)
	mux.HandleFunc("GET /api/v1/session", s.session)
	mux.HandleFunc("GET /login", s.login)
	mux.HandleFunc("GET "+human.CallbackPath, s.callback)
	mux.HandleFunc("POST /logout", s.logout)
	mux.HandleFunc("GET /{$}", s.home)
	return secure(mux)
}

// Internal is the publishers' API.
func (s *Server) Internal() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", health)
	mux.HandleFunc("POST /internal/v1/events", s.publish)
	return secure(mux)
}

func health(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = io.WriteString(w, "ok\n")
}

func secure(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")
		h.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// cors allows the PathOps UI (credentials included) and refuses another
// origin that announced itself (false: the request is answered).
func (s *Server) cors(w http.ResponseWriter, r *http.Request) bool {
	o := r.Header.Get("Origin")
	w.Header().Add("Vary", "Origin")
	switch o {
	case "", s.PublicURL:
		return true
	case s.AllowedOrigin:
		w.Header().Set("Access-Control-Allow-Origin", o)
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		return true
	}
	writeJSON(w, http.StatusForbidden, map[string]string{"error": "origin_not_allowed"})
	return false
}

func (s *Server) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Server) home(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if id, ok := s.People.Session(r); ok {
		fmt.Fprintf(w, "PathOps live updates: signed in as %s.\n", id.Email)
		return
	}
	_, _ = io.WriteString(w, "PathOps live updates: not signed in.\n")
}

func (s *Server) session(w http.ResponseWriter, r *http.Request) {
	if !s.cors(w, r) {
		return
	}
	id, ok := s.People.Session(r)
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthenticated", "login": s.PublicURL + "/login"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"email": id.Email})
}

// returnTo is where a sign-in may end: an https URL of the PathOps UI or of
// this host (default: this host's home).
func (s *Server) returnTo(v string) (string, bool) {
	if v == "" {
		return s.PublicURL + "/", true
	}
	u, err := url.Parse(v)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Opaque != "" {
		return "", false
	}
	if o := "https://" + u.Host; o != s.AllowedOrigin && o != s.PublicURL {
		return "", false
	}
	return u.String(), true
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	to, ok := s.returnTo(r.URL.Query().Get("return"))
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "return_not_allowed"})
		return
	}
	s.startLogin(w, r, to)
}

func (s *Server) startLogin(w http.ResponseWriter, r *http.Request, to string) {
	if err := s.People.Login(r.Context(), w, to); err != nil {
		s.Log.Warn("sign-in unavailable", "error", err.Error())
		http.Error(w, "the identity provider is unavailable", http.StatusServiceUnavailable)
	}
}

func (s *Server) callback(w http.ResponseWriter, r *http.Request) {
	to, err := s.People.Callback(r.Context(), w, r)
	switch {
	case errors.Is(err, human.ErrUnavailable):
		s.Log.Warn("sign-in unavailable", "error", err.Error())
		http.Error(w, "the identity provider is unavailable", http.StatusServiceUnavailable)
	case err != nil:
		s.Log.Info("sign-in refused", "error", err.Error())
		http.Error(w, "sign-in failed", http.StatusUnauthorized)
	default:
		if _, ok := s.returnTo(to); !ok {
			to = s.PublicURL + "/"
		}
		http.Redirect(w, r, to, http.StatusFound)
	}
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	// A cross-origin form or fetch always carries Origin: only the PathOps
	// UI and this host may end the session.
	if o := r.Header.Get("Origin"); o != s.AllowedOrigin && o != s.PublicURL {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "origin_not_allowed"})
		return
	}
	if !s.cors(w, r) {
		return
	}
	s.People.Logout(w, r)
	w.WriteHeader(http.StatusNoContent)
}

// events streams the signed-in person's invalidations.
func (s *Server) events(w http.ResponseWriter, r *http.Request) {
	if !s.cors(w, r) {
		return
	}
	id, ok := s.People.Session(r)
	if !ok {
		if strings.Contains(r.Header.Get("Accept"), "text/event-stream") {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthenticated", "login": s.PublicURL + "/login"})
			return
		}
		s.startLogin(w, r, s.PublicURL+"/api/v1/events")
		return
	}
	sub, err := s.Hub.Subscribe(hub.Person{Issuer: id.Issuer, Subject: id.Subject})
	if err != nil {
		w.Header().Set("Retry-After", "30")
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "too_many_connections"})
		return
	}
	defer s.Hub.Unsubscribe(sub)
	rc := http.NewResponseController(w)
	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	// Proxies pass each event on at once (nginx honours this header).
	h.Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	send := func(text string) bool {
		_ = rc.SetWriteDeadline(time.Now().Add(writeTimeout))
		if _, err := io.WriteString(w, text); err != nil {
			return false
		}
		return rc.Flush() == nil
	}
	if !send(fmt.Sprintf("retry: %d\n: connected\n\n", s.Retry.Milliseconds())) {
		return
	}
	tick := time.NewTicker(s.Heartbeat)
	defer tick.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-sub.Done():
			// Removed (it lagged) or shutting down: the browser reconnects.
			return
		case <-tick.C:
			// The session may have ended (sign-out, expiry): the browser
			// reconnects and is refused.
			if _, ok := s.People.Session(r); !ok {
				return
			}
			if !send(": heartbeat\n\n") {
				return
			}
		case ev := <-sub.C:
			b, _ := json.Marshal(ev)
			if !send("data: " + string(b) + "\n\n") {
				return
			}
		}
	}
}

// Published is an invalidation as the Tenant CP publishes it: the browser's
// event and the person who may receive it.
type Published struct {
	Type          string    `json:"type"`
	ApplicationID string    `json:"applicationId"`
	ResourceID    string    `json:"resourceId,omitempty"`
	OccurredAt    time.Time `json:"occurredAt"`
	Recipient     Recipient `json:"recipient"`
}

// Recipient is a person of the Cell's Dex.
type Recipient struct {
	Issuer  string `json:"issuer"`
	Subject string `json:"subject"`
}

var uuid = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

func (s *Server) valid(p Published) error {
	switch {
	case !slices.Contains(hub.Types, p.Type):
		return errors.New("unknown type")
	case !uuid.MatchString(p.ApplicationID):
		return errors.New("applicationId is not a UUID")
	case p.ResourceID != "" && !uuid.MatchString(p.ResourceID):
		return errors.New("resourceId is not a UUID")
	case p.ResourceID == "" && p.Type != hub.InboxChanged:
		return errors.New("resourceId is required")
	case p.OccurredAt.IsZero() || p.OccurredAt.After(s.now().Add(5*time.Minute)):
		return errors.New("occurredAt is missing or in the future")
	case p.Recipient.Issuer != s.Issuer:
		return errors.New("the recipient is not of the Cell's Dex")
	case p.Recipient.Subject == "" || len(p.Recipient.Subject) > 512:
		return errors.New("recipient.subject is missing or too long")
	}
	return nil
}

func (s *Server) publish(w http.ResponseWriter, r *http.Request) {
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthenticated"})
		return
	}
	if _, err := s.Publishers.Verify(r.Context(), strings.TrimSpace(token)); err != nil {
		if errors.Is(err, workload.ErrUnavailable) {
			s.Log.Warn("publisher not verified", "error", err.Error())
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "unavailable"})
			return
		}
		s.Log.Info("publisher refused")
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthenticated"})
		return
	}
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		writeJSON(w, http.StatusUnsupportedMediaType, map[string]string{"error": "json_required"})
		return
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, MaxEventBytes))
	dec.DisallowUnknownFields()
	var p Published
	if err := dec.Decode(&p); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "bad_request"})
		return
	}
	if err := s.valid(p); err != nil {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]string{"error": "invalid_event", "reason": err.Error()})
		return
	}
	n := s.Hub.Publish(hub.Person{Issuer: p.Recipient.Issuer, Subject: p.Recipient.Subject},
		hub.Event{Type: p.Type, ApplicationID: p.ApplicationID, ResourceID: p.ResourceID, OccurredAt: p.OccurredAt.UTC()})
	s.Log.Info("published", "type", p.Type, "applicationId", p.ApplicationID, "resourceId", p.ResourceID, "delivered", n)
	writeJSON(w, http.StatusAccepted, map[string]int{"delivered": n})
}
