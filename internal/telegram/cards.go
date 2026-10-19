package telegram

import (
	"fmt"
	"html"
	"strings"
	"time"

	"github.com/meshpanel/meshpanel/internal/db"
	"github.com/meshpanel/meshpanel/internal/registration"
)

func e(s string) string { return html.EscapeString(s) }

func cardBody(p *db.Pending, requester *db.Account) string {
	var b strings.Builder
	who := e(requester.Username)
	if requester.DisplayName != "" && requester.DisplayName != requester.Username {
		who += " (" + e(requester.DisplayName) + ")"
	}
	fmt.Fprintf(&b, "👤 %s\n", who)
	if p.Kind == registration.KindSSH {
		b.WriteString("🔑 SSH sign-in check\n")
	} else {
		fmt.Fprintf(&b, "📱 link opened on %s (not necessarily the joining device)\n", e(registration.DescribeUA(p.UserAgent)))
	}
	if p.IP != "" {
		fmt.Fprintf(&b, "🌐 %s\n", e(p.IP))
	}
	if p.HSUser != "" {
		fmt.Fprintf(&b, "🗂️ registers under user <code>%s</code>\n", e(p.HSUser))
	}
	return b.String()
}

// CardText is the open approval card.
func CardText(p *db.Pending, requester *db.Account, now time.Time) string {
	title := "🔔 <b>New device request</b>"
	if p.Kind == registration.KindSSH {
		title = "🔔 <b>SSH access request</b>"
	}
	left := int(p.ExpiresAt.Sub(now).Minutes())
	if left < 1 {
		left = 1
	}
	return fmt.Sprintf("%s\n%s⏳ expires in about %d min", title, cardBody(p, requester), left)
}

// DecidedText is the card after a decision; every copy is edited to this.
func DecidedText(p *db.Pending, requester *db.Account) string {
	at := p.DecidedAt.Format("15:04")
	var head string
	switch p.Status {
	case db.StatusApproved:
		head = fmt.Sprintf("✅ <b>Approved by %s</b> · %s", e(p.DecidedBy), at)
		if p.NodeName != "" {
			head += fmt.Sprintf("\n🖥️ %s %s", e(p.NodeName), e(p.NodeIP))
		}
	case db.StatusDenied:
		head = fmt.Sprintf("❌ <b>Denied by %s</b> · %s", e(p.DecidedBy), at)
	case db.StatusExpired:
		head = "⌛ <b>Expired</b>: nobody approved in time"
	case db.StatusCancelled:
		head = "🚫 <b>Cancelled</b> by the requester"
	case db.StatusFailed:
		head = fmt.Sprintf("⚠️ <b>Approval by %s failed</b>: %s", e(p.DecidedBy), e(p.Error))
	default:
		head = "⏳ <b>Processing…</b>"
	}
	return head + "\n" + cardBody(p, requester)
}
