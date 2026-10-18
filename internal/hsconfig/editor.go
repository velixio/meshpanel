// Package hsconfig edits headscale's config.yaml and policy file in place,
// keeping comments, with timestamped backups and automatic rollback when
// headscale fails to come back after a change.
package hsconfig

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

const keepBackups = 10

// Change sets the value at a dotted path, creating maps as needed.
type Change struct {
	Path  string
	Value any
}

type Editor struct {
	Path string
	mu   sync.Mutex
}

func (e *Editor) Writable() bool {
	f, err := os.OpenFile(e.Path, os.O_WRONLY, 0)
	if err != nil {
		return false
	}
	f.Close()
	return true
}

func (e *Editor) load() (*yaml.Node, os.FileMode, error) {
	b, err := os.ReadFile(e.Path)
	if err != nil {
		return nil, 0, err
	}
	st, err := os.Stat(e.Path)
	if err != nil {
		return nil, 0, err
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(b, &doc); err != nil {
		return nil, 0, fmt.Errorf("parsing %s: %w", e.Path, err)
	}
	if doc.Kind == 0 {
		doc = yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{{Kind: yaml.MappingNode, Tag: "!!map"}}}
	}
	return &doc, st.Mode().Perm(), nil
}

// Decode unmarshals the whole file into v.
func (e *Editor) Decode(v any) error {
	b, err := os.ReadFile(e.Path)
	if err != nil {
		return err
	}
	return yaml.Unmarshal(b, v)
}

// Patch applies changes and returns nothing on success. Use PatchWithBackup
// when the caller needs to roll back.
func (e *Editor) Patch(changes []Change) error {
	_, err := e.PatchWithBackup(changes)
	return err
}

// PatchWithBackup writes the changes and returns the backup's path.
func (e *Editor) PatchWithBackup(changes []Change) (string, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	doc, mode, err := e.load()
	if err != nil {
		return "", err
	}
	root := doc.Content[0]
	for _, c := range changes {
		if err := set(root, strings.Split(c.Path, "."), c.Value); err != nil {
			return "", fmt.Errorf("%s: %w", c.Path, err)
		}
	}
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(doc); err != nil {
		return "", err
	}
	enc.Close()
	backup, err := e.backup()
	if err != nil {
		return "", err
	}
	if err := writeFile(e.Path, buf.Bytes(), mode); err != nil {
		return "", err
	}
	return backup, nil
}

func set(m *yaml.Node, path []string, value any) error {
	if m.Kind != yaml.MappingNode {
		return errors.New("not a map")
	}
	for i := 0; i < len(m.Content)-1; i += 2 {
		if m.Content[i].Value != path[0] {
			continue
		}
		val := m.Content[i+1]
		if len(path) > 1 {
			if val.Kind != yaml.MappingNode {
				*val = yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
			}
			return set(val, path[1:], value)
		}
		var nv yaml.Node
		if err := nv.Encode(value); err != nil {
			return err
		}
		nv.HeadComment, nv.LineComment, nv.FootComment = val.HeadComment, val.LineComment, val.FootComment
		if nv.Kind == yaml.SequenceNode && len(nv.Content) == 0 || nv.Kind == yaml.MappingNode && len(nv.Content) == 0 {
			nv.Style = yaml.FlowStyle
		}
		*val = nv
		return nil
	}
	key := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: path[0]}
	if len(path) > 1 {
		child := &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"}
		m.Content = append(m.Content, key, child)
		return set(child, path[1:], value)
	}
	var nv yaml.Node
	if err := nv.Encode(value); err != nil {
		return err
	}
	m.Content = append(m.Content, key, &nv)
	return nil
}

func (e *Editor) backup() (string, error) {
	return backupFile(e.Path)
}

func backupFile(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	dst := fmt.Sprintf("%s.meshpanel-%d.bak", path, time.Now().UnixNano())
	if err := os.WriteFile(dst, b, 0o600); err != nil {
		// The config directory may not be writable for us (only the file
		// is); keep the backup in the system temp directory instead.
		f, terr := os.CreateTemp("", "meshpanel-backup-*")
		if terr != nil {
			return "", fmt.Errorf("creating backup: %w", err)
		}
		f.Write(b)
		f.Close()
		return f.Name(), nil
	}
	pruneBackups(path)
	return dst, nil
}

func pruneBackups(path string) {
	list, _ := filepath.Glob(path + ".meshpanel-*.bak")
	if len(list) <= keepBackups {
		return
	}
	sort.Strings(list)
	for _, p := range list[:len(list)-keepBackups] {
		os.Remove(p)
	}
}

// Restore copies a backup back over path.
func Restore(path, backup string) error {
	b, err := os.ReadFile(backup)
	if err != nil {
		return err
	}
	st, err := os.Stat(path)
	mode := os.FileMode(0o640)
	if err == nil {
		mode = st.Mode().Perm()
	}
	return writeFile(path, b, mode)
}

// writeFile replaces path atomically when the directory allows it, and in
// place otherwise (e.g. /etc/headscale owned by root, file group-writable).
func writeFile(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if f, err := os.CreateTemp(dir, ".meshpanel-*"); err == nil {
		name := f.Name()
		_, werr := f.Write(data)
		cerr := f.Close()
		if werr == nil && cerr == nil {
			os.Chmod(name, mode)
			if st, err := os.Stat(path); err == nil {
				copyOwner(name, st)
			}
			if err := os.Rename(name, path); err == nil {
				return nil
			}
		}
		os.Remove(name)
	}
	return os.WriteFile(path, data, mode)
}
