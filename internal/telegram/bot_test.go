package telegram

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/meshpanel/meshpanel/internal/db"
	"github.com/meshpanel/meshpanel/internal/events"
	"github.com/meshpanel/meshpanel/internal/hs"
	"github.com/meshpanel/meshpanel/internal/perm"
	"github.com/meshpanel/meshpanel/internal/registration"
)

type call struct {
	Method string
	Params map[string]any
}

type fakeTG struct {
	mu    sync.Mutex
	calls []call
	next  int
}

func (f *fakeTG) handler(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(r.URL.Path, "/")
	method := parts[len(parts)-1]
	var p map[string]any
	json.NewDecoder(r.Body).Decode(&p)
	f.mu.Lock()
	f.calls = append(f.calls, call{method, p})
	f.next++
	id := f.next
	f.mu.Unlock()
	switch method {
	case "sendMessage":
		fmt.Fprintf(w, `{"ok":true,"result":{"message_id":%d,"chat":{"id":%v}}}`, id, p["chat_id"])
	case "getMe":
		fmt.Fprint(w, `{"ok":true,"result":{"id":1,"username":"acme_mesh_bot"}}`)
	default:
		fmt.Fprint(w, `{"ok":true,"result":true}`)
	}
}

func (f *fakeTG) byMethod(m string) []call {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []call
	for _, c := range f.calls {
		if c.Method == m {
			out = append(out, c)
		}
	}
	return out
}

type fakeHS struct{ calls int }

func (f *fakeHS) AuthRegister(context.Context, string, string) (hs.Node, error) {
	f.calls++
	return hs.Node{ID: "9", GivenName: "ravi-iphone"}, nil
}
func (f *fakeHS) RenameNode(_ context.Context, id, name string) (hs.Node, error) {
	return hs.Node{ID: id, GivenName: name}, nil
}
func (f *fakeHS) AuthApprove(context.Context, string) error { f.calls++; return nil }
func (f *fakeHS) AuthReject(context.Context, string) error  { return nil }

type env struct {
	bot        *Bot
	tg         *fakeTG
	hs         *fakeHS
	d          *db.DB
	reg        *registration.Service
	ravi, anna *db.Account
	bob        *db.Account
}

func setup(t *testing.T) *env {
	t.Helper()
	d, err := db.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	tg := &fakeTG{}
	srv := httptest.NewServer(http.HandlerFunc(tg.handler))
	t.Cleanup(srv.Close)
	ctx := context.Background()
	v := &env{tg: tg, d: d, hs: &fakeHS{}}
	v.ravi, _ = d.CreateAccount(ctx, db.Account{Username: "ravi", DisplayName: "Ravi <Kumar>", Role: "member", HSUser: "ravi"})
	v.anna, _ = d.CreateAccount(ctx, db.Account{Username: "anna", Role: "admin", HSUser: "anna"})
	v.bob, _ = d.CreateAccount(ctx, db.Account{Username: "bob", Role: "it_admin", HSUser: "bob"})
	d.LinkChat(ctx, v.anna.ID, 1001, "@anna")
	d.LinkChat(ctx, v.bob.ID, 1002, "@bob")
	v.reg = registration.New(d, v.hs, events.NewBus())
	v.bot = New(Options{
		API: NewAPI("TOKEN", srv.URL), DB: d, Reg: v.reg, PublicURL: "https://hs.example.com", BasePath: "/admin",
		Users: func() []hs.User { return []hs.User{{ID: "1", Name: "ravi"}, {ID: "2", Name: "office"}} },
	})
	v.bot.limit = nil
	return v
}

func (v *env) pending(t *testing.T) *db.Pending {
	t.Helper()
	p, err := v.reg.Create(context.Background(), registration.KindRegister, "hskey-authreq-0123456789abcdef01234567", v.ravi, "49.36.1.2", "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X)")
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func buttonData(t *testing.T, c call, label string) string {
	t.Helper()
	b, _ := json.Marshal(c.Params["reply_markup"])
	var kb Keyboard
	json.Unmarshal(b, &kb)
	for _, row := range kb.InlineKeyboard {
		for _, btn := range row {
			if strings.Contains(btn.Text, label) {
				return btn.CallbackData
			}
		}
	}
	t.Fatalf("no %q button in %s", label, b)
	return ""
}

func tap(v *env, from int64, data string) {
	v.bot.HandleUpdate(context.Background(), Update{CallbackQuery: &CallbackQuery{ID: "cb", From: User{ID: from}, Data: data, Message: &Message{Chat: Chat{ID: from}}}})
}

func TestCardsGoToApproversOnly(t *testing.T) {
	v := setup(t)
	v.d.LinkChat(context.Background(), v.ravi.ID, 1000, "@ravi")
	v.bot.NotifyPending(context.Background(), v.pending(t))
	sent := v.tg.byMethod("sendMessage")
	chats := map[float64]bool{}
	for _, c := range sent {
		chats[c.Params["chat_id"].(float64)] = true
	}
	if len(sent) != 2 || !chats[1001] || !chats[1002] || chats[1000] {
		t.Fatalf("cards sent to %v", chats)
	}
}

func TestDecisionEditsAllCards(t *testing.T) {
	v := setup(t)
	p := v.pending(t)
	v.bot.NotifyPending(context.Background(), p)
	sent := v.tg.byMethod("sendMessage")
	tap(v, 1001, buttonData(t, sent[0], "Approve"))
	if v.hs.calls != 1 {
		t.Fatalf("headscale calls %d", v.hs.calls)
	}
	edits := v.tg.byMethod("editMessageText")
	if len(edits) < 2 {
		t.Fatalf("edits %d", len(edits))
	}
	for _, e := range edits {
		if !strings.Contains(e.Params["text"].(string), "Approved by anna") {
			t.Fatalf("edit text %q", e.Params["text"])
		}
		if kb, _ := json.Marshal(e.Params["reply_markup"]); strings.Contains(string(kb), "callback_data") {
			t.Fatal("buttons not removed")
		}
	}
	// Bob taps his stale copy: no second registration.
	tap(v, 1002, buttonData(t, sent[1], "Approve"))
	if v.hs.calls != 1 {
		t.Fatal("stale button registered twice")
	}
}

func TestTelegramActionRechecksPermission(t *testing.T) {
	v := setup(t)
	p := v.pending(t)
	v.bot.NotifyPending(context.Background(), p)
	data := buttonData(t, v.tg.byMethod("sendMessage")[1], "Approve") // bob's card
	if err := v.d.SetRole(context.Background(), v.bob.ID, "viewer"); err != nil {
		t.Fatal(err)
	}
	tap(v, 1002, data)
	if v.hs.calls != 0 {
		t.Fatal("demoted approver's tap was honoured")
	}
	ans := v.tg.byMethod("answerCallbackQuery")
	if len(ans) == 0 || !strings.Contains(ans[len(ans)-1].Params["text"].(string), "permission") {
		t.Fatalf("answers %+v", ans)
	}
	got, _ := v.reg.Get(context.Background(), p.ID)
	if got.Status != db.StatusPending {
		t.Fatal("request consumed")
	}
}

func TestUnlinkedChatRefused(t *testing.T) {
	v := setup(t)
	v.bot.NotifyPending(context.Background(), v.pending(t))
	tap(v, 4242, buttonData(t, v.tg.byMethod("sendMessage")[0], "Approve"))
	if v.hs.calls != 0 {
		t.Fatal("stranger approved")
	}
}

func TestApproveAsAnotherUser(t *testing.T) {
	v := setup(t)
	p := v.pending(t)
	v.bot.NotifyPending(context.Background(), p)
	tap(v, 1001, buttonData(t, v.tg.byMethod("sendMessage")[0], "another user"))
	picker := v.tg.byMethod("sendMessage")
	last := picker[len(picker)-1]
	tap(v, 1001, buttonData(t, last, "office"))
	got, _ := v.reg.Get(context.Background(), p.ID)
	if got.Status != db.StatusApproved || v.hs.calls != 1 {
		t.Fatalf("%+v", got)
	}
}

func TestLinkTokenSingleUse(t *testing.T) {
	v := setup(t)
	ctx := context.Background()
	link, err := v.bot.LinkURL(ctx, v.ravi.ID)
	if err != nil || !strings.HasPrefix(link, "https://t.me/acme_mesh_bot?start=") {
		t.Fatalf("link %q %v", link, err)
	}
	tok := strings.TrimPrefix(link, "https://t.me/acme_mesh_bot?start=")
	start := func(chat int64) {
		v.bot.HandleUpdate(ctx, Update{Message: &Message{Chat: Chat{ID: chat, Type: "private"}, From: &User{ID: chat, Username: "r"}, Text: "/start " + tok}})
	}
	start(5000)
	if id, err := v.d.AccountForChat(ctx, 5000); err != nil || id != v.ravi.ID {
		t.Fatalf("not linked: %v", err)
	}
	start(6000)
	if _, err := v.d.AccountForChat(ctx, 6000); err == nil {
		t.Fatal("token reused")
	}
}

func TestCardEscapesHTML(t *testing.T) {
	v := setup(t)
	v.bot.NotifyPending(context.Background(), v.pending(t))
	txt := v.tg.byMethod("sendMessage")[0].Params["text"].(string)
	if strings.Contains(txt, "<Kumar>") || !strings.Contains(txt, "&lt;Kumar&gt;") {
		t.Fatalf("not escaped: %q", txt)
	}
	if !strings.Contains(txt, "iPhone") || !strings.Contains(txt, "49.36.1.2") {
		t.Fatalf("missing context: %q", txt)
	}
}

func TestOwnApproverCannotApproveAsOtherUser(t *testing.T) {
	v := setup(t)
	ctx := context.Background()
	v.ravi.ExtraCaps = uint64(perm.ApproveDevicesOwn)
	v.d.UpdateAccount(ctx, v.ravi)
	v.d.LinkChat(ctx, v.ravi.ID, 1000, "@ravi")
	p := v.pending(t)
	act := v.bot.newAction(ctx, "as_user", p, "office")
	tap(v, 1000, act)
	if v.hs.calls != 0 {
		t.Fatal("own-only approver registered a device under another user")
	}
	pick := v.bot.newAction(ctx, "pick", p, "")
	before := len(v.tg.byMethod("sendMessage"))
	tap(v, 1000, pick)
	if len(v.tg.byMethod("sendMessage")) != before {
		t.Fatal("own-only approver got the user picker")
	}
}
