package hub

import (
	"errors"
	"testing"
	"time"
)

var (
	alice = Person{Issuer: "https://dex", Subject: "alice"}
	bob   = Person{Issuer: "https://dex", Subject: "bob"}
	ev    = Event{Type: BuildChanged, ApplicationID: "a", ResourceID: "b", OccurredAt: time.Unix(1, 0)}
)

func TestFanOutToThePersonOnly(t *testing.T) {
	var h Hub
	a1, _ := h.Subscribe(alice)
	a2, _ := h.Subscribe(alice)
	b1, _ := h.Subscribe(bob)
	if n := h.Publish(alice, ev); n != 2 {
		t.Fatalf("delivered to %d", n)
	}
	for _, s := range []*Subscriber{a1, a2} {
		if got := <-s.C; got != ev {
			t.Fatal(got)
		}
	}
	select {
	case got := <-b1.C:
		t.Fatalf("bob received alice's %v", got)
	default:
	}
	// Another issuer with the same subject is another person.
	if n := h.Publish(Person{Issuer: "https://other", Subject: "alice"}, ev); n != 0 {
		t.Fatalf("delivered to %d", n)
	}
}

func TestUnsubscribeCleansUp(t *testing.T) {
	h := Hub{MaxPerPerson: 1}
	s, _ := h.Subscribe(alice)
	if _, err := h.Subscribe(alice); !errors.Is(err, ErrTooMany) {
		t.Fatal(err)
	}
	h.Unsubscribe(s)
	h.Unsubscribe(s)
	select {
	case <-s.Done():
	default:
		t.Fatal("not done")
	}
	if h.Len() != 0 || h.Publish(alice, ev) != 0 {
		t.Fatal("still subscribed")
	}
	if _, err := h.Subscribe(alice); err != nil {
		t.Fatal("the person's count was not released:", err)
	}
}

func TestSlowSubscriberIsRemoved(t *testing.T) {
	var h Hub
	slow, _ := h.Subscribe(alice)
	for i := 0; i < Buffer; i++ {
		h.Publish(alice, ev)
	}
	if n := h.Publish(alice, ev); n != 0 {
		t.Fatalf("delivered to %d", n)
	}
	select {
	case <-slow.Done():
	default:
		t.Fatal("a full subscriber stays")
	}
	if h.Len() != 0 {
		t.Fatal(h.Len())
	}
}

func TestLimitsAndClose(t *testing.T) {
	h := Hub{MaxSubscribers: 2}
	h.Subscribe(alice)
	s, _ := h.Subscribe(bob)
	if _, err := h.Subscribe(bob); !errors.Is(err, ErrTooMany) {
		t.Fatal(err)
	}
	h.Close()
	<-s.Done()
	if _, err := h.Subscribe(alice); !errors.Is(err, ErrClosed) {
		t.Fatal(err)
	}
}
