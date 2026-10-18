// Package telegram is meshpanel's Telegram bot: account linking, approval
// cards with single-use signed buttons, and notification delivery. It uses
// long polling, so no public webhook is needed.
package telegram

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type API struct {
	token string
	base  string
	http  *http.Client
}

func NewAPI(token, base string) *API {
	if base == "" {
		base = "https://api.telegram.org"
	}
	return &API{token: token, base: strings.TrimRight(base, "/"), http: &http.Client{Timeout: 60 * time.Second}}
}

type User struct {
	ID        int64  `json:"id"`
	Username  string `json:"username"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
}

func (u *User) Display() string {
	if u == nil {
		return ""
	}
	if u.Username != "" {
		return "@" + u.Username
	}
	return strings.TrimSpace(u.FirstName + " " + u.LastName)
}

type Chat struct {
	ID   int64  `json:"id"`
	Type string `json:"type"`
}

type Message struct {
	MessageID int    `json:"message_id"`
	From      *User  `json:"from"`
	Chat      Chat   `json:"chat"`
	Text      string `json:"text"`
}

type CallbackQuery struct {
	ID      string   `json:"id"`
	From    User     `json:"from"`
	Message *Message `json:"message"`
	Data    string   `json:"data"`
}

type Update struct {
	UpdateID      int64          `json:"update_id"`
	Message       *Message       `json:"message"`
	CallbackQuery *CallbackQuery `json:"callback_query"`
}

type Button struct {
	Text         string `json:"text"`
	CallbackData string `json:"callback_data,omitempty"`
	URL          string `json:"url,omitempty"`
}

type Keyboard struct {
	InlineKeyboard [][]Button `json:"inline_keyboard"`
}

type apiResp struct {
	OK          bool            `json:"ok"`
	Result      json.RawMessage `json:"result"`
	Description string          `json:"description"`
	Parameters  *struct {
		RetryAfter int `json:"retry_after"`
	} `json:"parameters"`
}

// RetryAfterError is Telegram's 429 flood control.
type RetryAfterError struct{ After time.Duration }

func (e *RetryAfterError) Error() string {
	return fmt.Sprintf("telegram rate limit, retry after %s", e.After)
}

func (a *API) call(ctx context.Context, method string, params any, out any) error {
	b, err := json.Marshal(params)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.base+"/bot"+a.token+"/"+method, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := a.http.Do(req)
	if err != nil {
		// Never let the token leak into logs through the URL in the error.
		return errors.New(strings.ReplaceAll(err.Error(), a.token, "<token>"))
	}
	defer resp.Body.Close()
	var r apiResp
	if err := json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&r); err != nil {
		return fmt.Errorf("telegram %s: HTTP %d", method, resp.StatusCode)
	}
	if !r.OK {
		if r.Parameters != nil && r.Parameters.RetryAfter > 0 {
			return &RetryAfterError{After: time.Duration(r.Parameters.RetryAfter) * time.Second}
		}
		return fmt.Errorf("telegram %s: %s", method, r.Description)
	}
	if out != nil {
		return json.Unmarshal(r.Result, out)
	}
	return nil
}

func (a *API) GetMe(ctx context.Context) (User, error) {
	var u User
	err := a.call(ctx, "getMe", map[string]any{}, &u)
	return u, err
}

func (a *API) GetUpdates(ctx context.Context, offset int64, timeout int) ([]Update, error) {
	var ups []Update
	err := a.call(ctx, "getUpdates", map[string]any{
		"offset": offset, "timeout": timeout, "allowed_updates": []string{"message", "callback_query"},
	}, &ups)
	return ups, err
}

func (a *API) SendMessage(ctx context.Context, chatID int64, html string, kb *Keyboard) (int, error) {
	p := map[string]any{"chat_id": chatID, "text": html, "parse_mode": "HTML", "disable_web_page_preview": true}
	if kb != nil {
		p["reply_markup"] = kb
	}
	var m Message
	err := a.call(ctx, "sendMessage", p, &m)
	return m.MessageID, err
}

// EditMessage replaces a message's text; a nil keyboard removes the buttons.
func (a *API) EditMessage(ctx context.Context, chatID int64, msgID int, html string, kb *Keyboard) error {
	if kb == nil {
		kb = &Keyboard{InlineKeyboard: [][]Button{}}
	}
	err := a.call(ctx, "editMessageText", map[string]any{
		"chat_id": chatID, "message_id": msgID, "text": html, "parse_mode": "HTML", "reply_markup": kb,
	}, nil)
	if err != nil && strings.Contains(err.Error(), "message is not modified") {
		return nil
	}
	return err
}

func (a *API) AnswerCallback(ctx context.Context, id, text string, alert bool) error {
	return a.call(ctx, "answerCallbackQuery", map[string]any{"callback_query_id": id, "text": text, "show_alert": alert}, nil)
}
