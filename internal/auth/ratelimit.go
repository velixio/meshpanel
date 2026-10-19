package auth

import (
	"sync"
	"time"
)

const (
	freeFailures = 5
	maxBackoff   = 15 * time.Minute
	forgetAfter  = time.Hour
)

// Limiter applies exponential backoff after repeated login failures, keyed
// by IP and by account. The first five failures are free; then each failure
// doubles the wait, starting at 2s and capped at 15 minutes.
type Limiter struct {
	mu   sync.Mutex
	m    map[string]*entry
	now  func() time.Time
	free int
	max  time.Duration
}

type entry struct {
	failures int
	inflight int
	until    time.Time
	last     time.Time
}

func NewLimiter() *Limiter { return NewLimiterWith(freeFailures, maxBackoff) }

// NewLimiterWith allows free failures before backoff starts, capped at max.
func NewLimiterWith(free int, max time.Duration) *Limiter {
	return &Limiter{m: map[string]*entry{}, now: time.Now, free: free, max: max}
}

func (l *Limiter) Allow(key string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	e := l.m[key]
	if e == nil {
		return true, 0
	}
	now := l.now()
	if now.Sub(e.last) > forgetAfter {
		delete(l.m, key)
		return true, 0
	}
	if now.Before(e.until) {
		return false, e.until.Sub(now)
	}
	return true, 0
}

// Acquire is Allow plus a reservation: an attempt still in flight counts as
// a failure until Release, so parallel requests can't all pass the check
// before any of them has failed. Past the free attempts, one at a time.
func (l *Limiter) Acquire(key string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	e := l.m[key]
	if e != nil && e.inflight == 0 && now.Sub(e.last) > forgetAfter {
		e = nil
	}
	if e == nil {
		e = &entry{last: now}
		l.m[key] = e
	}
	if now.Before(e.until) {
		return false, e.until.Sub(now)
	}
	if e.inflight > 0 && e.failures+e.inflight >= l.free {
		return false, time.Second
	}
	e.inflight++
	return true, 0
}

// Release ends an Acquire; a failed attempt is recorded as by Fail, which
// returns the failure count (0 when not failed).
func (l *Limiter) Release(key string, failed bool) int {
	l.mu.Lock()
	if e := l.m[key]; e != nil && e.inflight > 0 {
		e.inflight--
	}
	l.mu.Unlock()
	if failed {
		return l.Fail(key)
	}
	return 0
}

// Fail records a failure and returns the failure count.
func (l *Limiter) Fail(key string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	e := l.m[key]
	if e == nil {
		e = &entry{}
		l.m[key] = e
	}
	e.failures++
	e.last = now
	if e.failures > l.free {
		d := time.Second << min(e.failures-l.free, 30)
		if d > l.max || d <= 0 {
			d = l.max
		}
		e.until = now.Add(d)
	}
	if len(l.m) > 10000 {
		for k, v := range l.m {
			if v.inflight == 0 && now.Sub(v.last) > forgetAfter {
				delete(l.m, k)
			}
		}
	}
	return e.failures
}

func (l *Limiter) Reset(key string) {
	l.mu.Lock()
	delete(l.m, key)
	l.mu.Unlock()
}
