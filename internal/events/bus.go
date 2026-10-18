// Package events is meshpanel's in-process event bus plus the poller that
// turns headscale snapshots into typed events. The WebSocket hub, the
// notifier, the audit feed and the dashboard all subscribe here.
package events

import (
	"log/slog"
	"sync"
	"time"
)

type Kind string

const (
	NodeOnline          Kind = "node_online"
	NodeOffline         Kind = "node_offline"
	NodeAdded           Kind = "node_added"
	NodeDeleted         Kind = "node_deleted"
	NodeRenamed         Kind = "node_renamed"
	NodeTagsChanged     Kind = "node_tags_changed"
	RouteAdvertised     Kind = "route_advertised"
	RouteApproved       Kind = "route_approved"
	KeyExpiring         Kind = "key_expiring"
	KeyExpired          Kind = "key_expired"
	NodeNotSeen         Kind = "node_not_seen"
	UserAdded           Kind = "user_added"
	UserDeleted         Kind = "user_deleted"
	RegistrationPending Kind = "registration_pending"
	RegistrationDecided Kind = "registration_decided"
	HeadscaleDown       Kind = "headscale_down"
	HeadscaleUp         Kind = "headscale_up"
	Security            Kind = "security"
	Changed             Kind = "changed" // something was edited via the panel; refresh views
)

// WatchableKinds are the events people can pick in a watch rule, in UI order.
var WatchableKinds = []struct {
	Kind  Kind
	Label string
}{
	{NodeOnline, "Comes online"},
	{NodeOffline, "Goes offline"},
	{NodeAdded, "New device registered"},
	{NodeDeleted, "Device deleted"},
	{KeyExpiring, "Key expiring soon"},
	{KeyExpired, "Key expired"},
	{RouteAdvertised, "Route advertised"},
	{RouteApproved, "Route approved"},
	{NodeNotSeen, "Not seen for a while"},
	{NodeTagsChanged, "Tags changed"},
	{NodeRenamed, "Renamed"},
}

type Event struct {
	Kind     Kind           `json:"kind"`
	At       time.Time      `json:"at"`
	NodeID   string         `json:"nodeId,omitempty"`
	NodeName string         `json:"nodeName,omitempty"`
	HSUser   string         `json:"hsUser,omitempty"`
	Tags     []string       `json:"tags,omitempty"`
	Actor    string         `json:"actor,omitempty"`
	Channel  string         `json:"channel,omitempty"`
	Text     string         `json:"text,omitempty"`
	Data     map[string]any `json:"data,omitempty"`
}

type Bus struct {
	mu   sync.RWMutex
	subs map[int]chan Event
	next int
}

func NewBus() *Bus { return &Bus{subs: map[int]chan Event{}} }

// Subscribe returns a buffered channel and an unsubscribe func.
func (b *Bus) Subscribe(buf int) (<-chan Event, func()) {
	ch := make(chan Event, buf)
	b.mu.Lock()
	id := b.next
	b.next++
	b.subs[id] = ch
	b.mu.Unlock()
	var once sync.Once
	return ch, func() {
		once.Do(func() {
			b.mu.Lock()
			delete(b.subs, id)
			b.mu.Unlock()
		})
	}
}

// Publish never blocks: a subscriber whose buffer is full misses the event.
func (b *Bus) Publish(e Event) {
	if e.At.IsZero() {
		e.At = time.Now()
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	for _, ch := range b.subs {
		select {
		case ch <- e:
		default:
			slog.Debug("event dropped for slow subscriber", "kind", e.Kind)
		}
	}
}
