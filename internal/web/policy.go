package web

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/tailscale/hujson"
)

// policyDoc is a parsed policy for the visual editor. Visual edits rewrite
// the file as plain JSON (comments are lost; the UI says so).
type policyDoc struct {
	raw map[string]any
}

func parsePolicy(text string) (*policyDoc, error) {
	if strings.TrimSpace(text) == "" {
		return &policyDoc{raw: map[string]any{}}, nil
	}
	std, err := hujson.Standardize([]byte(text))
	if err != nil {
		return nil, fmt.Errorf("the policy is not valid HuJSON: %w", err)
	}
	m := map[string]any{}
	dec := json.NewDecoder(bytes.NewReader(std))
	dec.UseNumber()
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("the policy must be a JSON object: %w", err)
	}
	return &policyDoc{raw: m}, nil
}

func (p *policyDoc) String() string {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	_ = enc.Encode(p.raw)
	return buf.String()
}

func toStrings(v any) []string {
	switch x := v.(type) {
	case []any:
		out := make([]string, 0, len(x))
		for _, e := range x {
			out = append(out, fmt.Sprint(e))
		}
		return out
	case string:
		return []string{x}
	}
	return nil
}

func toAnyList(s []string) []any {
	out := make([]any, len(s))
	for i, v := range s {
		out[i] = v
	}
	return out
}

func (p *policyDoc) listMap(key string) map[string][]string {
	out := map[string][]string{}
	if m, ok := p.raw[key].(map[string]any); ok {
		for k, v := range m {
			out[k] = toStrings(v)
		}
	}
	return out
}

func (p *policyDoc) setListMap(key string, m map[string][]string) {
	out := map[string]any{}
	for k, v := range m {
		out[k] = toAnyList(v)
	}
	p.raw[key] = out
}

type namedList struct {
	Name    string
	Members []string
}

func sortedLists(m map[string][]string) []namedList {
	var out []namedList
	for k, v := range m {
		out = append(out, namedList{k, v})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

type aclRule struct {
	Index  int
	Action string
	Src    []string
	Dst    []string
	Proto  string
	Users  []string // ssh only
}

func (p *policyDoc) rules(key string) []aclRule {
	var out []aclRule
	list, _ := p.raw[key].([]any)
	for i, e := range list {
		m, ok := e.(map[string]any)
		if !ok {
			continue
		}
		r := aclRule{Index: i, Src: toStrings(m["src"]), Dst: toStrings(m["dst"]), Users: toStrings(m["users"])}
		r.Action, _ = m["action"].(string)
		r.Proto, _ = m["proto"].(string)
		out = append(out, r)
	}
	return out
}

type policyView struct {
	Groups    []namedList
	TagOwners []namedList
	Hosts     []namedList
	ACLs      []aclRule
	SSH       []aclRule
}

func (p *policyDoc) view() policyView {
	v := policyView{
		Groups: sortedLists(p.listMap("groups")), TagOwners: sortedLists(p.listMap("tagOwners")),
		ACLs: p.rules("acls"), SSH: p.rules("ssh"),
	}
	if m, ok := p.raw["hosts"].(map[string]any); ok {
		hosts := map[string][]string{}
		for k, val := range m {
			hosts[k] = []string{fmt.Sprint(val)}
		}
		v.Hosts = sortedLists(hosts)
	}
	return v
}

func splitList(s string) []string {
	var out []string
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == '\n' || r == ' ' }) {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

// applyOp performs one visual-editor change. f returns a form field.
func (p *policyDoc) applyOp(op string, f func(string) string) error {
	name := strings.TrimSpace(f("name"))
	switch op {
	case "group_set", "tagowner_set":
		key, prefix := "groups", "group:"
		if op == "tagowner_set" {
			key, prefix = "tagOwners", "tag:"
		}
		if name == "" {
			return errors.New("a name is required")
		}
		if !strings.HasPrefix(name, prefix) {
			name = prefix + name
		}
		m := p.listMap(key)
		m[name] = splitList(f("members"))
		p.setListMap(key, m)
	case "group_delete", "tagowner_delete":
		key := "groups"
		if op == "tagowner_delete" {
			key = "tagOwners"
		}
		m := p.listMap(key)
		delete(m, name)
		p.setListMap(key, m)
	case "host_set":
		if name == "" || strings.TrimSpace(f("value")) == "" {
			return errors.New("host name and address are required")
		}
		m, _ := p.raw["hosts"].(map[string]any)
		if m == nil {
			m = map[string]any{}
		}
		m[name] = strings.TrimSpace(f("value"))
		p.raw["hosts"] = m
	case "host_delete":
		if m, ok := p.raw["hosts"].(map[string]any); ok {
			delete(m, name)
		}
	case "acl_add", "ssh_add":
		key := "acls"
		if op == "ssh_add" {
			key = "ssh"
		}
		src, dst := splitList(f("src")), splitList(f("dst"))
		if len(src) == 0 || len(dst) == 0 {
			return errors.New("both source and destination are required")
		}
		rule := map[string]any{"action": "accept", "src": toAnyList(src), "dst": toAnyList(dst)}
		if key == "ssh" {
			if a := f("action"); a == "check" {
				rule["action"] = "check"
			}
			users := splitList(f("users"))
			if len(users) == 0 {
				users = []string{"autogroup:nonroot"}
			}
			rule["users"] = toAnyList(users)
		} else if proto := strings.TrimSpace(f("proto")); proto != "" {
			rule["proto"] = proto
		}
		list, _ := p.raw[key].([]any)
		p.raw[key] = append(list, rule)
	case "acl_delete", "ssh_delete":
		key := "acls"
		if op == "ssh_delete" {
			key = "ssh"
		}
		i, err := strconv.Atoi(f("index"))
		list, _ := p.raw[key].([]any)
		if err != nil || i < 0 || i >= len(list) {
			return errors.New("that rule no longer exists")
		}
		p.raw[key] = append(list[:i:i], list[i+1:]...)
	default:
		return errors.New("unknown change")
	}
	return nil
}

type diffLine struct {
	Kind string // add | del | ctx
	Text string
}

// lineDiff is a small LCS diff, trimmed to changed lines plus context.
func lineDiff(a, b string) []diffLine {
	x, y := strings.Split(strings.TrimRight(a, "\n"), "\n"), strings.Split(strings.TrimRight(b, "\n"), "\n")
	if len(x)*len(y) > 4_000_000 {
		var out []diffLine
		for _, l := range y {
			out = append(out, diffLine{"add", l})
		}
		return out
	}
	n, m := len(x), len(y)
	lcs := make([][]int32, n+1)
	for i := range lcs {
		lcs[i] = make([]int32, m+1)
	}
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			if x[i] == y[j] {
				lcs[i][j] = lcs[i+1][j+1] + 1
			} else if lcs[i+1][j] >= lcs[i][j+1] {
				lcs[i][j] = lcs[i+1][j]
			} else {
				lcs[i][j] = lcs[i][j+1]
			}
		}
	}
	var all []diffLine
	i, j := 0, 0
	for i < n && j < m {
		switch {
		case x[i] == y[j]:
			all = append(all, diffLine{"ctx", x[i]})
			i, j = i+1, j+1
		case lcs[i+1][j] >= lcs[i][j+1]:
			all = append(all, diffLine{"del", x[i]})
			i++
		default:
			all = append(all, diffLine{"add", y[j]})
			j++
		}
	}
	for ; i < n; i++ {
		all = append(all, diffLine{"del", x[i]})
	}
	for ; j < m; j++ {
		all = append(all, diffLine{"add", y[j]})
	}
	const context = 3
	keep := make([]bool, len(all))
	for k, l := range all {
		if l.Kind != "ctx" {
			for c := max(0, k-context); c <= min(len(all)-1, k+context); c++ {
				keep[c] = true
			}
		}
	}
	var out []diffLine
	gap := false
	for k, l := range all {
		if keep[k] {
			out = append(out, l)
			gap = false
		} else if !gap {
			out = append(out, diffLine{"ctx", "…"})
			gap = true
		}
	}
	return out
}
