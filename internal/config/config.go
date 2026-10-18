// Package config loads meshpanel's YAML configuration, applies MESHPANEL_*
// environment overrides and resolves *_path secret files.
package config

import (
	"errors"
	"fmt"
	"os"
	"reflect"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// ExampleSecret is the placeholder shipped in config.example.yaml. Validate
// refuses to start with it.
const ExampleSecret = "change-me-to-a-random-string-of-32-chars-or-more"

type Config struct {
	Server    Server    `yaml:"server"`
	Headscale Headscale `yaml:"headscale"`
	DB        DB        `yaml:"db"`
	Telegram  Telegram  `yaml:"telegram"`
	Agent     Agent     `yaml:"agent"`
	Log       Log       `yaml:"log"`
}

type Server struct {
	Listen            string   `yaml:"listen"`
	BasePath          string   `yaml:"base_path"`
	PublicURL         string   `yaml:"public_url"`
	CookieSecure      bool     `yaml:"cookie_secure"`
	TrustedProxies    []string `yaml:"trusted_proxies"`
	SessionSecret     string   `yaml:"session_secret"`
	SessionSecretPath string   `yaml:"session_secret_path"`
}

type Headscale struct {
	Socket         string        `yaml:"socket"`
	HTTPURL        string        `yaml:"http_url"`
	ConfigPath     string        `yaml:"config_path"`
	PolicyPath     string        `yaml:"policy_path"`
	Binary         string        `yaml:"binary"`
	ReloadCommand  string        `yaml:"reload_command"`
	RestartCommand string        `yaml:"restart_command"`
	PollInterval   time.Duration `yaml:"poll_interval"`
}

type DB struct {
	Path string `yaml:"path"`
}

type Telegram struct {
	Token       string `yaml:"token"`
	TokenPath   string `yaml:"token_path"`
	GroupChatID int64  `yaml:"group_chat_id"`
	APIBase     string `yaml:"api_base"`
}

type Agent struct {
	Enabled bool `yaml:"enabled"`
}

type Log struct {
	Level string `yaml:"level"`
}

// Default returns the configuration used when a key is not set anywhere.
func Default() *Config {
	return &Config{
		Server: Server{
			Listen:       ":8030",
			BasePath:     "/admin",
			CookieSecure: true,
		},
		Headscale: Headscale{
			Socket:         "/var/run/headscale/headscale.sock",
			HTTPURL:        "http://127.0.0.1:8080",
			Binary:         "headscale",
			ReloadCommand:  "sudo systemctl reload headscale",
			RestartCommand: "sudo systemctl restart headscale",
			PollInterval:   5 * time.Second,
		},
		DB:       DB{Path: "/var/lib/meshpanel/meshpanel.db"},
		Telegram: Telegram{APIBase: "https://api.telegram.org"},
		Log:      Log{Level: "info"},
	}
}

// Load reads path (empty means defaults only), then applies environment
// overrides and secret files.
func Load(path string) (*Config, error) {
	c := Default()
	if path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("reading config: %w", err)
		}
		if err := yaml.Unmarshal(b, c); err != nil {
			return nil, fmt.Errorf("parsing %s: %w", path, err)
		}
	}
	if err := applyEnv(reflect.ValueOf(c).Elem(), "MESHPANEL"); err != nil {
		return nil, err
	}
	var err error
	if c.Server.SessionSecretPath != "" {
		if c.Server.SessionSecret, err = readSecret(c.Server.SessionSecretPath); err != nil {
			return nil, err
		}
	}
	if c.Telegram.TokenPath != "" {
		if c.Telegram.Token, err = readSecret(c.Telegram.TokenPath); err != nil {
			return nil, err
		}
	}
	c.Server.BasePath = "/" + strings.Trim(c.Server.BasePath, "/")
	c.Server.PublicURL = strings.TrimRight(c.Server.PublicURL, "/")
	return c, nil
}

// Validate reports settings that make the panel unsafe or unable to run.
func (c *Config) Validate() error {
	var errs []error
	switch {
	case c.Server.SessionSecret == ExampleSecret:
		errs = append(errs, errors.New("server.session_secret is still the example value; generate one with: openssl rand -hex 32"))
	case len(c.Server.SessionSecret) < 32:
		errs = append(errs, errors.New("server.session_secret must be at least 32 characters; generate one with: openssl rand -hex 32"))
	}
	if c.Server.BasePath == "/" {
		errs = append(errs, errors.New("server.base_path must not be \"/\": /register and /auth live at the root"))
	}
	if c.Headscale.PollInterval < time.Second {
		errs = append(errs, errors.New("headscale.poll_interval must be at least 1s"))
	}
	return errors.Join(errs...)
}

func readSecret(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("reading secret file: %w", err)
	}
	return strings.TrimSpace(string(b)), nil
}

var durationType = reflect.TypeOf(time.Duration(0))

// applyEnv walks the struct and overrides each leaf from PREFIX_KEY_PATH,
// where the key path is the upper-cased yaml tag chain.
func applyEnv(v reflect.Value, prefix string) error {
	t := v.Type()
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		tag := strings.Split(f.Tag.Get("yaml"), ",")[0]
		if tag == "" || tag == "-" {
			continue
		}
		name := prefix + "_" + strings.ToUpper(tag)
		fv := v.Field(i)
		if f.Type.Kind() == reflect.Struct {
			if err := applyEnv(fv, name); err != nil {
				return err
			}
			continue
		}
		raw, ok := os.LookupEnv(name)
		if !ok {
			continue
		}
		if err := setFromString(fv, raw); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
	}
	return nil
}

func setFromString(fv reflect.Value, raw string) error {
	if fv.Type() == durationType {
		d, err := time.ParseDuration(raw)
		if err != nil {
			return err
		}
		fv.SetInt(int64(d))
		return nil
	}
	switch fv.Kind() {
	case reflect.String:
		fv.SetString(raw)
	case reflect.Bool:
		b, err := strconv.ParseBool(raw)
		if err != nil {
			return err
		}
		fv.SetBool(b)
	case reflect.Int, reflect.Int64:
		n, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			return err
		}
		fv.SetInt(n)
	case reflect.Slice:
		var parts []string
		for _, p := range strings.Split(raw, ",") {
			if p = strings.TrimSpace(p); p != "" {
				parts = append(parts, p)
			}
		}
		fv.Set(reflect.ValueOf(parts))
	default:
		return fmt.Errorf("unsupported type %s", fv.Type())
	}
	return nil
}
