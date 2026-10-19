package tailnet

import (
	"sync"
	"time"

	"github.com/meshpanel/meshpanel/internal/hs"
)

// releaseGrace keeps a finished session's key recognised long enough for the
// poller to see its node disappear without raising an alert.
const releaseGrace = 10 * time.Minute

// SessionKeys remembers the pre-auth keys meshpanel minted for browser SSH
// nodes, so those nodes can be told apart from real devices. A hostname is
// not enough: any device can pick one.
type SessionKeys struct {
	mu   sync.Mutex
	live map[string]bool
	done map[string]time.Time
	now  func() time.Time
}

func (k *SessionKeys) clock() time.Time {
	if k.now != nil {
		return k.now()
	}
	return time.Now()
}

func (k *SessionKeys) Add(id string) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.live == nil {
		k.live, k.done = map[string]bool{}, map[string]time.Time{}
	}
	k.live[id] = true
}

// Release marks a session finished; its key stays recognised for a while.
func (k *SessionKeys) Release(id string) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.live[id] {
		delete(k.live, id)
		k.done[id] = k.clock().Add(releaseGrace)
	}
}

// Owns reports whether the node registered with one of meshpanel's keys.
func (k *SessionKeys) Owns(n hs.Node) bool {
	if k == nil || n.PreAuthKey == nil || n.PreAuthKey.ID == "" {
		return false
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.live[n.PreAuthKey.ID] {
		return true
	}
	until, ok := k.done[n.PreAuthKey.ID]
	if ok && k.clock().After(until) {
		delete(k.done, n.PreAuthKey.ID)
		return false
	}
	return ok
}
