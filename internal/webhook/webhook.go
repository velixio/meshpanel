// Package webhook sends meshpanel events to HTTP endpoints: generic JSON
// (signed with HMAC-SHA256), Slack incoming webhooks, or Discord webhooks.
package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/meshpanel/meshpanel/internal/db"
	"github.com/meshpanel/meshpanel/internal/events"
	"github.com/meshpanel/meshpanel/internal/notify"
)

// Kinds are the events a webhook can subscribe to, in UI order.
var Kinds = func() []events.Kind {
	var k []events.Kind
	for _, w := range events.WatchableKinds {
		k = append(k, w.Kind)
	}
	return append(k, events.RegistrationPending, events.RegistrationDecided, events.Security, events.HeadscaleDown, events.HeadscaleUp)
}()

func deliverable(k events.Kind) bool {
	for _, x := range Kinds {
		if x == k {
			return true
		}
	}
	return false
}

type NodeRef struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name"`
}

// Payload is the generic JSON body.
type Payload struct {
	Event   string         `json:"event"`
	Text    string         `json:"text"`
	At      time.Time      `json:"at"`
	Node    *NodeRef       `json:"node,omitempty"`
	User    string         `json:"user,omitempty"`
	Tags    []string       `json:"tags,omitempty"`
	Actor   string         `json:"actor,omitempty"`
	Channel string         `json:"channel,omitempty"`
	Data    map[string]any `json:"data,omitempty"`
}

func payload(ev events.Event) Payload {
	p := Payload{Event: string(ev.Kind), Text: notify.Text(ev), At: ev.At, User: ev.HSUser, Tags: ev.Tags, Actor: ev.Actor, Channel: ev.Channel, Data: ev.Data}
	if p.At.IsZero() {
		p.At = time.Now()
	}
	if ev.NodeName != "" || ev.NodeID != "" {
		p.Node = &NodeRef{ID: ev.NodeID, Name: ev.NodeName}
	}
	return p
}

// Body renders the request body for a webhook's format.
func Body(format string, ev events.Event) ([]byte, error) {
	p := payload(ev)
	switch format {
	case "slack":
		return json.Marshal(map[string]string{"text": p.Text})
	case "discord":
		return json.Marshal(map[string]string{"content": p.Text})
	}
	return json.Marshal(p)
}

func Sign(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

type job struct {
	hook *db.Webhook
	ev   events.Event
}

// Dispatcher delivers events to configured webhooks with retries.
type Dispatcher struct {
	db      *db.DB
	client  *http.Client
	queue   chan job
	backoff []time.Duration
	once    sync.Once
}

func New(d *db.DB) *Dispatcher {
	return &Dispatcher{
		db: d, client: &http.Client{Timeout: 10 * time.Second}, queue: make(chan job, 256),
		backoff: []time.Duration{2 * time.Second, 10 * time.Second, 30 * time.Second},
	}
}

func (d *Dispatcher) startWorkers(ctx context.Context) {
	d.once.Do(func() { d.spawn(ctx) })
}

func (d *Dispatcher) spawn(ctx context.Context) {
	for i := 0; i < 4; i++ {
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case j := <-d.queue:
					d.deliver(ctx, j.hook, j.ev)
				}
			}
		}()
	}
}

// Handle queues an event for every webhook that wants it.
func (d *Dispatcher) Handle(ctx context.Context, ev events.Event) {
	if !deliverable(ev.Kind) {
		return
	}
	d.startWorkers(context.WithoutCancel(ctx))
	hooks, err := d.db.ListWebhooks(ctx)
	if err != nil {
		slog.Error("webhooks: listing", "err", err)
		return
	}
	for _, h := range hooks {
		if !h.Enabled || !h.Wants(string(ev.Kind)) {
			continue
		}
		select {
		case d.queue <- job{h, ev}:
		default:
			slog.Warn("webhooks: queue full, dropping event", "hook", h.Name, "kind", ev.Kind)
		}
	}
}

// Send delivers one event now (used by the "Send test" button).
func (d *Dispatcher) Send(ctx context.Context, h *db.Webhook, ev events.Event) error {
	return d.deliverOnce(ctx, h, ev)
}

func (d *Dispatcher) deliver(ctx context.Context, h *db.Webhook, ev events.Event) {
	var err error
	for attempt := 0; ; attempt++ {
		if err = d.deliverOnce(ctx, h, ev); err == nil || attempt >= len(d.backoff) {
			break
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(d.backoff[attempt]):
		}
	}
	if err != nil {
		slog.Warn("webhook delivery failed", "hook", h.Name, "err", err)
	}
}

type statusError struct{ code int }

func (e statusError) Error() string { return fmt.Sprintf("HTTP %d", e.code) }

func (d *Dispatcher) deliverOnce(ctx context.Context, h *db.Webhook, ev events.Event) error {
	body, err := Body(h.Format, ev)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "meshpanel-webhook")
	req.Header.Set("X-Meshpanel-Event", string(ev.Kind))
	req.Header.Set("X-Meshpanel-Signature", Sign(h.Secret, body))
	resp, err := d.client.Do(req)
	status := 0
	if err == nil {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		resp.Body.Close()
		status = resp.StatusCode
		if status >= 300 {
			err = statusError{status}
		}
	}
	errText := ""
	if err != nil {
		errText = err.Error()
	}
	_ = d.db.RecordWebhookResult(context.WithoutCancel(ctx), h.ID, status, errText)
	return err
}

// Run delivers bus events until ctx ends.
func (d *Dispatcher) Run(ctx context.Context, bus *events.Bus) {
	d.startWorkers(ctx)
	ch, cancel := bus.Subscribe(256)
	defer cancel()
	for {
		select {
		case <-ctx.Done():
			return
		case ev := <-ch:
			d.Handle(ctx, ev)
		}
	}
}
