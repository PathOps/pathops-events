// Package hub fans invalidations out to the browsers connected in this
// process (Decision 0063, v1: one replica, in memory, no broker, no replay).
//
// A subscriber is one SSE connection of a signed-in person; an invalidation
// names the person who may read what changed (the Application's owner, as
// the Tenant CP decided) and reaches only that person's subscribers. Nothing
// is kept: an invalidation with no subscriber is gone, and a browser that
// reconnects reads the current state from REST again.
package hub

import (
	"errors"
	"sync"
	"time"
)

// Event types (Decision 0063): what changed, never its new state.
const (
	BuildChanged    = "BUILD_CHANGED"
	DeliveryChanged = "DELIVERY_CHANGED"
	InboxChanged    = "INBOX_CHANGED"
	// ApplicationChanged: the Application itself (created, its
	// provisioning); it names no resource.
	ApplicationChanged = "APPLICATION_CHANGED"
)

// Types are the event types the hub carries.
var Types = []string{BuildChanged, DeliveryChanged, InboxChanged, ApplicationChanged}

// Event is an invalidation as a browser receives it: its type, the
// Application and the resource (a Build's, DeliveryRun's or Inbox message's
// id; empty when the type has none) and when it happened.
type Event struct {
	Type          string    `json:"type"`
	ApplicationID string    `json:"applicationId"`
	ResourceID    string    `json:"resourceId,omitempty"`
	OccurredAt    time.Time `json:"occurredAt"`
}

// Person is a signed-in person: the Cell Dex's issuer and subject.
type Person struct {
	Issuer, Subject string
}

// Limits of the hub; a new subscriber past one is refused.
const (
	DefaultMaxSubscribers = 1024
	DefaultMaxPerPerson   = 16
	// Buffer is how many invalidations wait for a slow browser; one more
	// ends its stream (it reconnects and reads REST again).
	Buffer = 64
)

// ErrTooMany: the hub or the person has as many subscribers as allowed.
var ErrTooMany = errors.New("too many live connections")

// ErrClosed: the hub stopped (the process is shutting down).
var ErrClosed = errors.New("the hub is closed")

// Hub keeps the subscribers.
type Hub struct {
	MaxSubscribers, MaxPerPerson int

	mu     sync.Mutex
	subs   map[*Subscriber]struct{}
	per    map[Person]int
	closed bool
}

// Subscriber receives the invalidations of its person on C until Done is
// closed (it lagged, it was removed or the hub closed).
type Subscriber struct {
	Person Person
	C      chan Event
	done   chan struct{}
	once   sync.Once
}

// Done is closed when the subscriber stops receiving.
func (s *Subscriber) Done() <-chan struct{} { return s.done }

func (s *Subscriber) stop() { s.once.Do(func() { close(s.done) }) }

// Subscribe adds a subscriber for p.
func (h *Hub) Subscribe(p Person) (*Subscriber, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return nil, ErrClosed
	}
	if h.subs == nil {
		h.subs, h.per = map[*Subscriber]struct{}{}, map[Person]int{}
	}
	if len(h.subs) >= limit(h.MaxSubscribers, DefaultMaxSubscribers) || h.per[p] >= limit(h.MaxPerPerson, DefaultMaxPerPerson) {
		return nil, ErrTooMany
	}
	s := &Subscriber{Person: p, C: make(chan Event, Buffer), done: make(chan struct{})}
	h.subs[s] = struct{}{}
	h.per[p]++
	return s, nil
}

// Unsubscribe removes s (once; later calls do nothing).
func (h *Hub) Unsubscribe(s *Subscriber) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.remove(s)
}

func (h *Hub) remove(s *Subscriber) {
	if _, ok := h.subs[s]; !ok {
		return
	}
	delete(h.subs, s)
	if h.per[s.Person]--; h.per[s.Person] <= 0 {
		delete(h.per, s.Person)
	}
	s.stop()
}

// Publish sends e to every subscriber of p and returns how many received
// it. It never blocks: a subscriber whose buffer is full is removed.
func (h *Hub) Publish(p Person, e Event) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	n := 0
	for s := range h.subs {
		if s.Person != p {
			continue
		}
		select {
		case s.C <- e:
			n++
		default:
			h.remove(s)
		}
	}
	return n
}

// Len is the number of subscribers.
func (h *Hub) Len() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.subs)
}

// Close removes every subscriber and refuses new ones.
func (h *Hub) Close() {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.closed = true
	for s := range h.subs {
		h.remove(s)
	}
}

func limit(v, def int) int {
	if v <= 0 {
		return def
	}
	return v
}
