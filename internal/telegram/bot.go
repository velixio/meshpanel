package telegram

import (
	"context"
	"errors"
	"fmt"
	"html"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/meshpanel/meshpanel/internal/auth"
	"github.com/meshpanel/meshpanel/internal/db"
	"github.com/meshpanel/meshpanel/internal/events"
	"github.com/meshpanel/meshpanel/internal/hs"
	"github.com/meshpanel/meshpanel/internal/perm"
	"github.com/meshpanel/meshpanel/internal/registration"
)

const (
	LinkTokenTTL = 10 * time.Minute
	refPending   = "pending"
)

type Options struct {
	API       *API
	DB        *db.DB
	Reg       *registration.Service
	Users     func() []hs.User // headscale users, for "approve as another user"
	PublicURL string
	BasePath  string
	GroupChat int64
}

type Bot struct {
	api       *API
	db        *db.DB
	reg       *registration.Service
	users     func() []hs.User
	publicURL string
	basePath  string
	group     int64
	now       func() time.Time
	limit     *limiter

	mu      sync.RWMutex
	botName string
}

func New(o Options) *Bot {
	return &Bot{
		api: o.API, db: o.DB, reg: o.Reg, users: o.Users, publicURL: o.PublicURL, basePath: o.BasePath,
		group: o.GroupChat, now: time.Now, limit: newLimiter(),
	}
}

func (b *Bot) SetGroupChat(id int64) { b.mu.Lock(); b.group = id; b.mu.Unlock() }

func (b *Bot) groupChat() int64 { b.mu.RLock(); defer b.mu.RUnlock(); return b.group }

// BotName returns the bot's @username, fetching it once.
func (b *Bot) BotName(ctx context.Context) (string, error) {
	b.mu.RLock()
	n := b.botName
	b.mu.RUnlock()
	if n != "" {
		return n, nil
	}
	me, err := b.api.GetMe(ctx)
	if err != nil {
		return "", err
	}
	b.mu.Lock()
	b.botName = me.Username
	b.mu.Unlock()
	return me.Username, nil
}

// LinkURL creates a single-use deep link that binds the tapping chat to accountID.
func (b *Bot) LinkURL(ctx context.Context, accountID int64) (string, error) {
	name, err := b.BotName(ctx)
	if err != nil {
		return "", fmt.Errorf("telegram bot unavailable: %w", err)
	}
	tok := auth.RandomToken(18)
	if err := b.db.CreateLinkToken(ctx, tok, accountID, LinkTokenTTL); err != nil {
		return "", err
	}
	return "https://t.me/" + name + "?start=" + tok, nil
}

// Run long-polls Telegram and follows registration events on the bus.
func (b *Bot) Run(ctx context.Context, bus *events.Bus) {
	if _, err := b.BotName(ctx); err != nil {
		slog.Error("telegram: getMe failed; bot disabled until restart", "err", err)
		return
	}
	go b.followBus(ctx, bus)
	var offset int64
	backoff := time.Second
	for ctx.Err() == nil {
		ups, err := b.api.GetUpdates(ctx, offset, 30)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			slog.Warn("telegram: getUpdates", "err", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			backoff = min(backoff*2, time.Minute)
			continue
		}
		backoff = time.Second
		for _, u := range ups {
			offset = u.UpdateID + 1
			b.HandleUpdate(ctx, u)
		}
	}
}

func (b *Bot) followBus(ctx context.Context, bus *events.Bus) {
	ch, cancel := bus.Subscribe(64)
	defer cancel()
	for {
		select {
		case <-ctx.Done():
			return
		case ev := <-ch:
			id, _ := ev.Data["id"].(int64)
			if id == 0 {
				continue
			}
			p, err := b.db.GetPending(ctx, id)
			if err != nil {
				continue
			}
			switch {
			case ev.Kind == events.RegistrationPending:
				// Self-approvers are decided right after creation; skip cards
				// for anything no longer open by the time we get here.
				if p.Open() {
					b.NotifyPending(ctx, p)
				}
			case ev.Kind == events.RegistrationDecided && ev.Channel != "telegram":
				b.OnDecided(ctx, p)
			}
		}
	}
}

type approver struct {
	acc  *db.Account
	chat int64
}

// approvers lists linked accounts allowed to decide p.
func (b *Bot) approvers(ctx context.Context, p *db.Pending) []approver {
	links, err := b.db.ListLinks(ctx)
	if err != nil {
		return nil
	}
	var out []approver
	for _, l := range links {
		acc, err := b.db.GetAccount(ctx, l.AccountID)
		if err != nil || acc.Disabled || acc.ID == p.RequesterID {
			continue
		}
		if mayDecide(acc, p) {
			out = append(out, approver{acc, l.ChatID})
		}
	}
	return out
}

func mayDecide(acc *db.Account, p *db.Pending) bool {
	caps := perm.Effective(acc.Role, perm.Cap(acc.ExtraCaps))
	if p.Kind == registration.KindSSH {
		return caps.Has(perm.ApproveSSH)
	}
	return perm.CanApprove(caps, acc.HSUser, p.HSUser)
}

func (b *Bot) newAction(ctx context.Context, kind string, p *db.Pending, arg string) string {
	id := auth.RandomToken(16)
	if err := b.db.CreateAction(ctx, db.TelegramAction{ID: id, Kind: kind, TargetID: p.ID, Arg: arg, ExpiresAt: p.ExpiresAt}); err != nil {
		slog.Error("telegram: create action", "err", err)
	}
	return "a:" + id
}

// NotifyPending sends the approval card to every approver and the group chat.
func (b *Bot) NotifyPending(ctx context.Context, p *db.Pending) {
	requester, err := b.db.GetAccount(ctx, p.RequesterID)
	if err != nil {
		return
	}
	text := CardText(p, requester, b.now())
	kb := &Keyboard{InlineKeyboard: [][]Button{
		{{Text: "✅ Approve", CallbackData: b.newAction(ctx, "approve", p, "")}, {Text: "❌ Deny", CallbackData: b.newAction(ctx, "deny", p, "")}},
	}}
	if p.Kind == registration.KindRegister {
		kb.InlineKeyboard = append(kb.InlineKeyboard, []Button{{Text: "👥 Approve as another user…", CallbackData: b.newAction(ctx, "pick", p, "")}})
	}
	if b.publicURL != "" {
		kb.InlineKeyboard = append(kb.InlineKeyboard, []Button{{Text: "Open in meshpanel", URL: b.publicURL + b.basePath + "/"}})
	}
	chats := map[int64]bool{}
	for _, a := range b.approvers(ctx, p) {
		chats[a.chat] = true
	}
	if g := b.groupChat(); g != 0 {
		chats[g] = true
	}
	for chat := range chats {
		id, err := b.send(ctx, chat, text, kb)
		if err != nil {
			slog.Warn("telegram: sending card", "chat", chat, "err", err)
			continue
		}
		_ = b.db.AddMessage(ctx, refPending, p.ID, chat, id)
	}
}

// OnDecided rewrites every copy of p's card to its outcome, removing buttons.
func (b *Bot) OnDecided(ctx context.Context, p *db.Pending) {
	_ = b.db.UseActionsFor(ctx, p.ID)
	requester, err := b.db.GetAccount(ctx, p.RequesterID)
	if err != nil {
		return
	}
	text := DecidedText(p, requester)
	msgs, _ := b.db.MessagesFor(ctx, refPending, p.ID)
	for _, m := range msgs {
		b.limit.wait(ctx, m.ChatID)
		if err := b.api.EditMessage(ctx, m.ChatID, m.MessageID, text, nil); err != nil {
			slog.Debug("telegram: edit card", "err", err)
		}
	}
}

// Send delivers a plain-text notification to an account's linked chat.
func (b *Bot) Send(ctx context.Context, accountID int64, text string) error {
	l, err := b.db.LinkForAccount(ctx, accountID)
	if err != nil {
		return err
	}
	_, err = b.send(ctx, l.ChatID, html.EscapeString(text), nil)
	return err
}

func (b *Bot) send(ctx context.Context, chat int64, text string, kb *Keyboard) (int, error) {
	for attempt := 0; ; attempt++ {
		b.limit.wait(ctx, chat)
		id, err := b.api.SendMessage(ctx, chat, text, kb)
		var ra *RetryAfterError
		if errors.As(err, &ra) && attempt < 3 {
			select {
			case <-ctx.Done():
				return 0, ctx.Err()
			case <-time.After(ra.After):
			}
			continue
		}
		return id, err
	}
}

func (b *Bot) reply(ctx context.Context, chat int64, text string) {
	if _, err := b.send(ctx, chat, text, nil); err != nil {
		slog.Debug("telegram: reply", "err", err)
	}
}

// HandleUpdate processes one incoming update.
func (b *Bot) HandleUpdate(ctx context.Context, u Update) {
	switch {
	case u.CallbackQuery != nil:
		b.handleCallback(ctx, u.CallbackQuery)
	case u.Message != nil && u.Message.From != nil:
		b.handleMessage(ctx, u.Message)
	}
}

func (b *Bot) handleMessage(ctx context.Context, m *Message) {
	cmd, arg, _ := strings.Cut(strings.TrimSpace(m.Text), " ")
	cmd = strings.SplitN(cmd, "@", 2)[0]
	private := m.Chat.Type == "private" || m.Chat.Type == ""
	switch cmd {
	case "/start":
		if arg == "" {
			b.reply(ctx, m.Chat.ID, "👋 This is your company's meshpanel bot.\n\nTo link your account, open meshpanel → <b>Alerts</b> → <b>Link Telegram</b>.")
			return
		}
		if !private {
			b.reply(ctx, m.Chat.ID, "Link your account in a private chat with me, not in a group.")
			return
		}
		accID, err := b.db.UseLinkToken(ctx, strings.TrimSpace(arg))
		if err != nil {
			b.reply(ctx, m.Chat.ID, "⚠️ This link expired or was already used. Create a new one in meshpanel.")
			return
		}
		if err := b.db.LinkChat(ctx, accID, m.From.ID, m.From.Display()); err != nil {
			b.reply(ctx, m.Chat.ID, "⚠️ Linking failed. Try again.")
			return
		}
		acc, _ := b.db.GetAccount(ctx, accID)
		name := ""
		if acc != nil {
			name = acc.Name()
		}
		b.reply(ctx, m.Chat.ID, "✅ Linked to <b>"+html.EscapeString(name)+"</b>. You'll get approvals and alerts here. Send /unlink to stop.")
	case "/unlink":
		_ = b.db.UnlinkChat(ctx, m.From.ID)
		b.reply(ctx, m.Chat.ID, "Unlinked. You won't get messages from meshpanel any more.")
	case "/pending":
		b.listPending(ctx, m)
	case "/help":
		b.reply(ctx, m.Chat.ID, "/pending: open device requests\n/unlink: stop messages\n\nApprovals arrive here automatically.")
	}
}

func (b *Bot) listPending(ctx context.Context, m *Message) {
	accID, err := b.db.AccountForChat(ctx, m.From.ID)
	if err != nil {
		b.reply(ctx, m.Chat.ID, "Link your account first: meshpanel → Alerts → Link Telegram.")
		return
	}
	acc, err := b.db.GetAccount(ctx, accID)
	if err != nil {
		return
	}
	ps, _ := b.db.ListPending(ctx, true, 20)
	n := 0
	for _, p := range ps {
		if acc.ID != p.RequesterID && mayDecide(acc, p) {
			b.NotifyPendingTo(ctx, p, m.Chat.ID)
			n++
		}
	}
	if n == 0 {
		b.reply(ctx, m.Chat.ID, "No open requests.")
	}
}

// NotifyPendingTo re-sends one card to one chat.
func (b *Bot) NotifyPendingTo(ctx context.Context, p *db.Pending, chat int64) {
	requester, err := b.db.GetAccount(ctx, p.RequesterID)
	if err != nil {
		return
	}
	kb := &Keyboard{InlineKeyboard: [][]Button{
		{{Text: "✅ Approve", CallbackData: b.newAction(ctx, "approve", p, "")}, {Text: "❌ Deny", CallbackData: b.newAction(ctx, "deny", p, "")}},
	}}
	if id, err := b.send(ctx, chat, CardText(p, requester, b.now()), kb); err == nil {
		_ = b.db.AddMessage(ctx, refPending, p.ID, chat, id)
	}
}

func (b *Bot) answer(ctx context.Context, id, text string, alert bool) {
	if err := b.api.AnswerCallback(ctx, id, text, alert); err != nil {
		slog.Debug("telegram: answer", "err", err)
	}
}

func (b *Bot) handleCallback(ctx context.Context, cb *CallbackQuery) {
	data, ok := strings.CutPrefix(cb.Data, "a:")
	if !ok {
		b.answer(ctx, cb.ID, "Unknown button.", false)
		return
	}
	act, err := b.db.GetAction(ctx, data)
	if err != nil {
		b.answer(ctx, cb.ID, "This button has expired.", false)
		return
	}
	// Identity is the tapping person, never the chat: in a group, anyone can
	// see the card but only linked approvers can act on it.
	accID, err := b.db.AccountForChat(ctx, cb.From.ID)
	if err != nil {
		b.answer(ctx, cb.ID, "Link your Telegram in meshpanel first (Alerts → Link Telegram).", true)
		return
	}
	acc, err := b.db.GetAccount(ctx, accID)
	if err != nil || acc.Disabled {
		b.answer(ctx, cb.ID, "Your meshpanel account is disabled.", true)
		return
	}
	p, err := b.db.GetPending(ctx, act.TargetID)
	if err != nil {
		b.answer(ctx, cb.ID, "This request no longer exists.", false)
		return
	}
	if !mayDecide(acc, p) {
		b.answer(ctx, cb.ID, "You don't have permission to approve this request.", true)
		return
	}
	if act.Kind == "pick" || act.Kind == "as_user" {
		caps := perm.Effective(acc.Role, perm.Cap(acc.ExtraCaps))
		if !perm.CanApproveAs(caps, acc.HSUser, p.HSUser, act.Arg) || (act.Kind == "pick" && !caps.Has(perm.ApproveDevices)) {
			b.answer(ctx, cb.ID, "Only full approvers can register a device under another user.", true)
			return
		}
	}
	switch act.Kind {
	case "pick":
		b.sendUserPicker(ctx, p, cb)
		b.answer(ctx, cb.ID, "", false)
		return
	case "approve", "deny", "as_user":
	default:
		b.answer(ctx, cb.ID, "Unknown button.", false)
		return
	}
	approve := act.Kind != "deny"
	decided, err := b.reg.Decide(ctx, p.ID, approve, acc, "telegram", act.Arg)
	var already *registration.AlreadyDecidedError
	switch {
	case errors.As(err, &already):
		b.answer(ctx, cb.ID, "Already "+already.Status+" by "+already.By+".", false)
	case errors.Is(err, registration.ErrNoHSUser):
		b.answer(ctx, cb.ID, "This person has no headscale user. Use \"Approve as another user\".", true)
		return
	case err != nil && decided == nil:
		b.answer(ctx, cb.ID, "Failed: "+err.Error(), true)
		return
	case err != nil:
		b.answer(ctx, cb.ID, "headscale refused: "+err.Error(), true)
	case approve:
		b.answer(ctx, cb.ID, "Approved ✅", false)
	default:
		b.answer(ctx, cb.ID, "Denied", false)
	}
	if decided != nil {
		b.OnDecided(ctx, decided)
	}
}

func (b *Bot) sendUserPicker(ctx context.Context, p *db.Pending, cb *CallbackQuery) {
	var rows [][]Button
	var row []Button
	if b.users != nil {
		for _, u := range b.users() {
			row = append(row, Button{Text: u.Name, CallbackData: b.newAction(ctx, "as_user", p, u.Name)})
			if len(row) == 3 {
				rows = append(rows, row)
				row = nil
			}
		}
	}
	if len(row) > 0 {
		rows = append(rows, row)
	}
	if len(rows) == 0 {
		b.reply(ctx, cb.From.ID, "No headscale users found.")
		return
	}
	chat := cb.From.ID
	if cb.Message != nil {
		chat = cb.Message.Chat.ID
	}
	id, err := b.send(ctx, chat, "👥 Register this device as which user?", &Keyboard{InlineKeyboard: rows})
	if err == nil {
		_ = b.db.AddMessage(ctx, refPending, p.ID, chat, id)
	}
}

// limiter keeps under Telegram's limits: ~25 msg/s overall, 1 msg/s per chat.
type limiter struct {
	mu      sync.Mutex
	last    time.Time
	perChat map[int64]time.Time
}

func newLimiter() *limiter { return &limiter{perChat: map[int64]time.Time{}} }

func (l *limiter) wait(ctx context.Context, chat int64) {
	if l == nil {
		return
	}
	l.mu.Lock()
	now := time.Now()
	at := now
	if g := l.last.Add(40 * time.Millisecond); g.After(at) {
		at = g
	}
	if c := l.perChat[chat].Add(time.Second); c.After(at) {
		at = c
	}
	l.last, l.perChat[chat] = at, at
	if len(l.perChat) > 5000 {
		l.perChat = map[int64]time.Time{}
	}
	l.mu.Unlock()
	if d := at.Sub(now); d > 0 {
		select {
		case <-ctx.Done():
		case <-time.After(d):
		}
	}
}
