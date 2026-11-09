package tools

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

const (
	DefaultPort     = 5100
	DefaultAccounts = "accounts.yaml"
	DefaultKeystore = "keystore.yaml"
	DefaultPublicV2 = "public-v2.key"
	DefaultPublicV3 = "public-v3.key"
	DefaultPIDFile  = "/var/run/regauth.pid"
	DefaultLogFile  = "/var/log/regauth.log"
)

type Config struct {
	Server ServerConfig `yaml:"server"`
	Paths  PathsConfig  `yaml:"paths"`

	path    string `yaml:"-"`
	created bool   `yaml:"-"`
}

type ServerConfig struct {
	Registry        string       `yaml:"registry"`
	Port            int          `yaml:"port"`
	Insecure        bool         `yaml:"insecure"`
	PIDFile         string       `yaml:"pid_file"`
	LogFile         string       `yaml:"logfile"`
	LogTerm         *bool        `yaml:"logterm"`
	Keystore        KeystoreExec `yaml:"keystore"`
	TLS             TLSConfig    `yaml:"tls"`
	KeysVersion     int          `yaml:"keys_version"`     // 2 or 3 (default: 3)
	AllowedServices []string     `yaml:"allowed_services"` // empty = allow all
}

type KeystoreExec struct {
	Rotate   []string `yaml:"rotate"`
	RotateV2 []string `yaml:"rotate_v2"`
	Revoke   []string `yaml:"revoke"`
	Delete   []string `yaml:"delete"`
	Cleanup  []string `yaml:"cleanup"`
}

type TLSConfig struct {
	Enabled  *bool  `yaml:"enabled"`
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
}

type PathsConfig struct {
	Accounts string `yaml:"accounts"`
	Keystore string `yaml:"keystore"`
	PublicV2 string `yaml:"public_v2"`
	PublicV3 string `yaml:"public_v3"`
}

func LoadConfig(explicitPath string) (*Config, error) {
	path, err := resolveConfigPath(explicitPath)
	if err != nil {
		return nil, err
	}
	cfg := &Config{path: path}

	data, err := os.ReadFile(path)

	needsInit := false
	if errors.Is(err, os.ErrNotExist) {
		needsInit = true
		slog.Info("config file not found, creating default", "path", path)
	} else if err == nil && strings.TrimSpace(string(data)) == "" {
		needsInit = true
		slog.Info("config file is empty, creating default", "path", path)
	} else if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}

	if needsInit {
		if err := cfg.createDefault(); err != nil {
			return nil, fmt.Errorf("create default config: %w", err)
		}
		cfg.created = true
		return cfg, nil
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	cfg.path = path
	cfg.applyDefaults()
	if err := cfg.ensureKeystore(); err != nil {
		return nil, fmt.Errorf("ensure keystore: %w", err)
	}
	return cfg, nil
}

func (c *Config) WasCreated() bool { return c.created }

func (c *Config) ConfigPath() string { return c.path }

func resolveConfigPath(explicit string) (string, error) {
	if explicit != "" {
		return filepath.Abs(explicit)
	}
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(exe), "config.yaml"), nil
}

func (c *Config) createDefault() error {
	c.Server = ServerConfig{
		Port:        DefaultPort,
		PIDFile:     DefaultPIDFile,
		LogFile:     DefaultLogFile,
		KeysVersion: 3,
	}
	c.Paths = PathsConfig{
		Accounts: DefaultAccounts,
		Keystore: DefaultKeystore,
		PublicV2: DefaultPublicV2,
		PublicV3: DefaultPublicV3,
	}
	if err := os.MkdirAll(filepath.Dir(c.path), 0o755); err != nil {
		return err
	}
	if err := c.save(); err != nil {
		return err
	}
	slog.Info("default config created", "path", c.path)
	return c.ensureKeystore()
}

func (c *Config) applyDefaults() {
	if c.Server.Port == 0 {
		c.Server.Port = DefaultPort
	}
	if c.Server.PIDFile == "" {
		c.Server.PIDFile = DefaultPIDFile
	}
	if c.Server.LogFile == "" {
		c.Server.LogFile = DefaultLogFile
	}
	if c.Server.KeysVersion == 0 {
		c.Server.KeysVersion = 3
	}
	if c.Paths.Accounts == "" {
		c.Paths.Accounts = DefaultAccounts
	}
	if c.Paths.Keystore == "" {
		c.Paths.Keystore = DefaultKeystore
	}
	if c.Paths.PublicV2 == "" {
		c.Paths.PublicV2 = DefaultPublicV2
	}
	if c.Paths.PublicV3 == "" {
		c.Paths.PublicV3 = DefaultPublicV3
	}
}

func (c *Config) LogToTerminal() bool {
	if c.Server.LogTerm == nil {
		return true
	}
	return *c.Server.LogTerm
}

// IsServiceAllowed reports whether the given service may receive tokens.
// An empty AllowedServices list means "allow all" (backward compatible).
func (c *Config) IsServiceAllowed(service string) bool {
	if len(c.Server.AllowedServices) == 0 {
		return true
	}
	for _, s := range c.Server.AllowedServices {
		if s == service {
			return true
		}
	}
	return false
}

func (c *Config) save() error {
	data, err := yaml.Marshal(c)
	if err != nil {
		return err
	}
	return AtomicWrite(c.path, data, 0o600)
}

func (c *Config) ensureKeystore() error {
	ks, err := LoadKeystore(c.KeystorePath())
	if err != nil {
		return err
	}
	changed := false

	if !ks.HasV2() {
		key, err := rsa.GenerateKey(rand.Reader, 4096)
		if err != nil {
			return err
		}
		ks.SetV2(key)
		slog.Info("generated RSA key for v2")
		changed = true
	}
	if _, err := ks.CurrentV3(); err != nil {
		key, err := rsa.GenerateKey(rand.Reader, 4096)
		if err != nil {
			return err
		}
		kid := ComputeLibtrustKid(&key.PublicKey)
		ks.AddCurrentV3(kid, key)
		slog.Info("generated RSA key for v3", "kid", kid)
		changed = true
	}

	if changed {
		if err := ks.Save(c.KeystorePath()); err != nil {
			return err
		}
	}
	if err := ks.WritePublicV2(c.PublicV2Path()); err != nil {
		return err
	}
	if err := ks.WriteJWKS(c.PublicV3Path()); err != nil {
		return err
	}
	return nil
}

func (c *Config) RotateV2() error {
	ks, err := LoadKeystore(c.KeystorePath())
	if err != nil {
		return err
	}
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return err
	}
	ks.SetV2(key)
	if err := ks.Save(c.KeystorePath()); err != nil {
		return err
	}
	if err := ks.WritePublicV2(c.PublicV2Path()); err != nil {
		return err
	}
	slog.Info("rotated v2 signing key")
	return nil
}

func (c *Config) RotateV3() (string, error) {
	ks, err := LoadKeystore(c.KeystorePath())
	if err != nil {
		return "", err
	}
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return "", err
	}
	kid := ComputeLibtrustKid(&key.PublicKey)
	ks.AddCurrentV3(kid, key)
	if err := ks.Save(c.KeystorePath()); err != nil {
		return "", err
	}
	if err := ks.WriteJWKS(c.PublicV3Path()); err != nil {
		return "", err
	}
	slog.Info("rotated v3 signing key", "kid", kid)
	return kid, nil
}

func (c *Config) RevokeV3(kid string) error {
	ks, err := LoadKeystore(c.KeystorePath())
	if err != nil {
		return err
	}
	if err := ks.MarkRevokedV3(kid); err != nil {
		return err
	}
	if err := ks.Save(c.KeystorePath()); err != nil {
		return err
	}
	if err := ks.WriteJWKS(c.PublicV3Path()); err != nil {
		return err
	}
	slog.Info("revoked v3 key", "kid", kid)
	return nil
}

func (c *Config) DeleteV3(kid string) error {
	ks, err := LoadKeystore(c.KeystorePath())
	if err != nil {
		return err
	}
	if err := ks.DeleteV3(kid); err != nil {
		return err
	}
	if err := ks.Save(c.KeystorePath()); err != nil {
		return err
	}
	slog.Info("deleted v3 key", "kid", kid)
	return nil
}

func (c *Config) CleanupV3() (int, error) {
	ks, err := LoadKeystore(c.KeystorePath())
	if err != nil {
		return 0, err
	}
	n := ks.CleanupV3()
	if err := ks.Save(c.KeystorePath()); err != nil {
		return 0, err
	}
	slog.Info("cleaned up v3 keys", "removed", n)
	return n, nil
}

func (c *Config) SigningKey() (*rsa.PrivateKey, string, error) {
	ks, err := LoadKeystore(c.KeystorePath())
	if err != nil {
		return nil, "", err
	}

	switch c.Server.KeysVersion {
	case 2:
		priv, err := ks.V2Private()
		if err != nil {
			return nil, "", err
		}
		kid := ComputeLibtrustKid(&priv.PublicKey)
		return priv, kid, nil
	case 3:
		priv, kid, err := ks.PrivateV3()
		if err != nil {
			return nil, "", err
		}
		return priv, kid, nil
	default:
		return nil, "", fmt.Errorf("unknown keys_version %d (allowed: 2, 3)", c.Server.KeysVersion)
	}
}

func (c *Config) AccountsPath() string {
	return ResolveRelative(filepath.Dir(c.path), c.Paths.Accounts)
}

func (c *Config) KeystorePath() string {
	return ResolveRelative(filepath.Dir(c.path), c.Paths.Keystore)
}

func (c *Config) PublicV2Path() string {
	return ResolveRelative(filepath.Dir(c.path), c.Paths.PublicV2)
}

func (c *Config) PublicV3Path() string {
	return ResolveRelative(filepath.Dir(c.path), c.Paths.PublicV3)
}

func (c *Config) PIDFilePath() string {
	return ResolveRelative(filepath.Dir(c.path), c.Server.PIDFile)
}

func (c *Config) LogFilePath() string {
	return ResolveRelative(filepath.Dir(c.path), c.Server.LogFile)
}
