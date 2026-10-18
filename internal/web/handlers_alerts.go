package web

import (
	"errors"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/meshpanel/meshpanel/internal/db"
	"github.com/meshpanel/meshpanel/internal/events"
	"github.com/meshpanel/meshpanel/internal/hs"
	"github.com/meshpanel/meshpanel/internal/perm"
)

type ruleRow struct {
	*db.WatchRule
	Owner   string
	Subject string
	Labels  []string
}

type alertsData struct {
	Telegram  *db.TelegramLink
	TGEnabled bool
	BotName   string
	LinkURL   string
	Rules     []ruleRow
	Feed      []*db.Notification
	Nodes     []hs.Node
	Users     []hs.User
	Kinds     []struct {
		Kind  events.Kind
		Label string
	}
	CanAll    bool
	Accounts  []*db.Account
	Timezones []string
}

var commonZones = []string{"UTC", "Asia/Kolkata", "Asia/Dhaka", "Asia/Singapore", "Asia/Tokyo", "Asia/Dubai", "Europe/London", "Europe/Berlin", "Europe/Moscow", "America/New_York", "America/Chicago", "America/Los_Angeles", "America/Sao_Paulo", "Australia/Sydney", "Africa/Lagos"}

func (s *Server) alertsData(r *http.Request) *alertsData {
	ctx := r.Context()
	id := who(r)
	d := &alertsData{
		TGEnabled: s.TG != nil, Nodes: id.Scope.Nodes(s.Poller.Snapshot()), CanAll: id.Caps.Has(perm.ManageNotifications),
		Timezones: commonZones,
	}
	for _, k := range events.WatchableKinds {
		d.Kinds = append(d.Kinds, struct {
			Kind  events.Kind
			Label string
		}{k.Kind, k.Label})
	}
	for _, u := range s.Poller.Users() {
		if u.ID != hs.TaggedDevicesUserID && id.Scope.User(u.Name) {
			d.Users = append(d.Users, u)
		}
	}
	if !contains(d.Timezones, id.Account.Timezone) {
		d.Timezones = append([]string{id.Account.Timezone}, d.Timezones...)
	}
	d.Telegram, _ = s.DB.LinkForAccount(ctx, id.Account.ID)
	if s.TG != nil {
		d.BotName, _ = s.TG.BotName(ctx)
	}
	owner := id.Account.ID
	if d.CanAll {
		owner = 0
		d.Accounts, _ = s.DB.ListAccounts(ctx)
	}
	rules, _ := s.DB.ListWatches(ctx, owner)
	names := map[int64]string{}
	for _, a := range d.Accounts {
		names[a.ID] = a.Name()
	}
	nodeNames := map[string]string{}
	for _, n := range s.Poller.Snapshot() {
		nodeNames[n.ID] = n.DisplayName()
	}
	labels := map[string]string{}
	for _, k := range events.WatchableKinds {
		labels[string(k.Kind)] = k.Label
	}
	for _, rule := range rules {
		row := ruleRow{WatchRule: rule, Owner: names[rule.AccountID]}
		switch rule.SubjectType {
		case "node":
			row.Subject = nodeNames[rule.Subject]
			if row.Subject == "" {
				row.Subject = "deleted device"
			}
		case "all":
			row.Subject = "Everything"
		default:
			row.Subject = rule.Subject
		}
		for _, e := range rule.Events {
			row.Labels = append(row.Labels, labels[e])
		}
		d.Rules = append(d.Rules, row)
	}
	d.Feed, _ = s.DB.ListNotifications(ctx, id.Account.ID, 50)
	return d
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

func (s *Server) alerts(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "alerts", s.page(w, r, "alerts", "Alerts", s.alertsData(r)))
}

var tagSubjectRe = regexp.MustCompile(`^tag:[a-zA-Z0-9][a-zA-Z0-9_-]*$`)

func (s *Server) ruleCreate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := who(r)
	here := s.base + "/alerts"
	r.ParseForm()
	rule := db.WatchRule{AccountID: id.Account.ID, SubjectType: r.PostFormValue("subject_type")}
	if forID, _ := strconv.ParseInt(r.PostFormValue("for_account"), 10, 64); forID != 0 && forID != id.Account.ID {
		if !id.Caps.Has(perm.ManageNotifications) {
			s.failed(w, r, here, errors.New("you can only create alerts for yourself"))
			return
		}
		rule.AccountID = forID
	}
	switch rule.SubjectType {
	case "node":
		rule.Subject = r.PostFormValue("node")
		n, ok := s.Poller.Node(rule.Subject)
		if !ok || !id.Scope.Node(n) {
			s.failed(w, r, here, errors.New("choose one of your devices"))
			return
		}
	case "user":
		rule.Subject = r.PostFormValue("user")
		if rule.Subject == "" || !id.Scope.User(rule.Subject) {
			s.failed(w, r, here, errors.New("choose a user you can see"))
			return
		}
	case "tag":
		rule.Subject = strings.TrimSpace(r.PostFormValue("tag"))
		if !strings.HasPrefix(rule.Subject, "tag:") {
			rule.Subject = "tag:" + rule.Subject
		}
		if !tagSubjectRe.MatchString(rule.Subject) || !id.Scope.All {
			s.failed(w, r, here, errors.New("tag alerts need a valid tag and permission to see all machines"))
			return
		}
	case "all":
		if !id.Scope.All {
			s.failed(w, r, here, errors.New("only people who can see every machine can watch everything"))
			return
		}
	default:
		s.failed(w, r, here, errors.New("choose what to watch"))
		return
	}
	valid := map[string]bool{}
	for _, k := range events.WatchableKinds {
		valid[string(k.Kind)] = true
	}
	for _, e := range r.PostForm["event"] {
		if valid[e] {
			rule.Events = append(rule.Events, e)
		}
	}
	if len(rule.Events) == 0 {
		s.failed(w, r, here, errors.New("pick at least one event"))
		return
	}
	mins, _ := strconv.Atoi(r.PostFormValue("debounce_min"))
	if mins < 0 || mins > 120 {
		mins = 2
	}
	rule.OfflineDebounce = time.Duration(mins) * time.Minute
	rule.NotSeenHours, _ = strconv.Atoi(r.PostFormValue("not_seen_hours"))
	if contains(rule.Events, string(events.NodeNotSeen)) && rule.NotSeenHours <= 0 {
		rule.NotSeenHours = 24
	}
	if _, err := s.DB.CreateWatch(ctx, rule); err != nil {
		s.failed(w, r, here, err)
		return
	}
	s.audit(r, "alert.create", rule.SubjectType+":"+rule.Subject, nil, rule.Events)
	s.ok(w, r, here, "Alert rule added.")
}

func (s *Server) ruleDelete(w http.ResponseWriter, r *http.Request) {
	id := who(r)
	rid, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	owner := id.Account.ID
	if id.Caps.Has(perm.ManageNotifications) {
		owner = 0
	}
	if err := s.DB.DeleteWatch(r.Context(), rid, owner); err != nil {
		s.failed(w, r, s.base+"/alerts", err)
		return
	}
	s.audit(r, "alert.delete", strconv.FormatInt(rid, 10), nil, nil)
	s.ok(w, r, s.base+"/alerts", "Alert rule removed.")
}

var hhmm = regexp.MustCompile(`^([01]\d|2[0-3]):[0-5]\d$`)

func (s *Server) quietPost(w http.ResponseWriter, r *http.Request) {
	id := who(r)
	acc := id.Account
	start, end, tz := r.PostFormValue("quiet_start"), r.PostFormValue("quiet_end"), r.PostFormValue("timezone")
	if r.PostFormValue("off") == "1" {
		start, end = "", ""
	} else if !hhmm.MatchString(start) || !hhmm.MatchString(end) {
		s.failed(w, r, s.base+"/alerts", errors.New("use times like 22:00 and 07:00"))
		return
	}
	if _, err := time.LoadLocation(tz); err != nil || tz == "" {
		tz = "UTC"
	}
	acc.QuietStart, acc.QuietEnd, acc.Timezone = start, end, tz
	if err := s.DB.UpdateAccount(r.Context(), acc); err != nil {
		s.failed(w, r, s.base+"/alerts", err)
		return
	}
	s.ok(w, r, s.base+"/alerts", "Quiet hours saved.")
}

func (s *Server) telegramLink(w http.ResponseWriter, r *http.Request) {
	if s.TG == nil {
		s.failed(w, r, s.base+"/alerts", errors.New("Telegram is not configured on this server"))
		return
	}
	link, err := s.TG.LinkURL(r.Context(), who(r).Account.ID)
	if err != nil {
		s.failed(w, r, s.base+"/alerts", err)
		return
	}
	d := s.alertsData(r)
	d.LinkURL = link
	s.render(w, r, "alerts", s.page(w, r, "alerts", "Alerts", d))
}

func (s *Server) telegramUnlink(w http.ResponseWriter, r *http.Request) {
	_ = s.DB.UnlinkAccount(r.Context(), who(r).Account.ID)
	s.audit(r, "telegram.unlink", who(r).Account.Username, nil, nil)
	s.ok(w, r, s.base+"/alerts", "Telegram unlinked.")
}
