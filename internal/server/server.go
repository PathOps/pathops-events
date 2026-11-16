// Package server is pathops-events' HTTP API (Decision 0063): two HTTPS
// listeners, never one handler for both.
//
// Public (browsers, https://events-<cell>.<domain>):
//
//	/socket.io/   the browsers' Socket.IO connection (live.go): WebSocket
//	              only, the PathOps UI's origin only, the person's PathOps
//	              token in the handshake's auth payload
//	GET /healthz  liveness
//
// There is no sign-in, session or cookie here: a person is authenticated by
// the PathOps token the UI already holds for the Tenant CP.
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
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/PathOps/pathops-events/internal/hub"
	"github.com/PathOps/pathops-events/internal/workload"
)

// Publishers authenticates a publisher's bearer token (internal/workload).
type Publishers interface {
	Verify(ctx context.Context, token string) (string, error)
}

// Server serves both APIs.
type Server struct {
	Hub        *hub.Hub
	People     People
	Publishers Publishers
	// AllowedOrigin is the PathOps UI's (https://<controlPlane host>), the
	// only origin a browser connection may come from; Issuer the Cell Dex's
	// (an invalidation names a person of this issuer).
	AllowedOrigin, Issuer string
	// PingInterval and PingTimeout are Socket.IO's (zero: its defaults,
	// 25s and 20s).
	PingInterval, PingTimeout time.Duration
	Log                       *slog.Logger
	Now                       func() time.Time
}

// MaxEventBytes bounds a published invalidation.
const MaxEventBytes = 4096

// Public is the browsers' API.
func (s *Server) Public() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", health)
	mux.Handle("/socket.io/", s.live())
	mux.HandleFunc("GET /{$}", home)
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

func home(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = io.WriteString(w, "PathOps live updates (Socket.IO at /socket.io/).\n")
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

func (s *Server) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
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
	case p.ResourceID != "" && p.Type == hub.ApplicationChanged:
		return errors.New("resourceId is not allowed")
	case p.ResourceID == "" && p.Type != hub.InboxChanged && p.Type != hub.ApplicationChanged:
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
