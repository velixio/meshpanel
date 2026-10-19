package tailnet

import (
	"sync"
	"time"
)

// HostInfo is what the agent learns about a machine from Tailscale.
type HostInfo struct {
	OS        string
	OSVersion string
	Device    string
	Tailscale string
	Hostname  string
	Endpoints []string
	HomeDERP  int
	Updated   time.Time
}

// AgentState is the agent's health for the Settings page.
type AgentState struct {
	Running  bool
	Error    string
	LastSync time.Time
	Peers    int
}

// HostCache holds the agent's latest host info, keyed by node key.
type HostCache struct {
	mu    sync.RWMutex
	info  map[string]HostInfo
	state AgentState
}

func (c *HostCache) Info(nodeKey string) (HostInfo, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	hi, ok := c.info[nodeKey]
	return hi, ok
}

func (c *HostCache) State() AgentState {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.state
}

// Store replaces the cache after a successful sync, or records err.
func (c *HostCache) Store(info map[string]HostInfo, at time.Time, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err != nil {
		c.state.Error = err.Error()
		return
	}
	c.info = info
	c.state = AgentState{Running: true, LastSync: at, Peers: len(info)}
}

// Fail marks the agent as stopped.
func (c *HostCache) Fail(err error) {
	c.mu.Lock()
	c.state.Running = false
	c.state.Error = err.Error()
	c.mu.Unlock()
}
