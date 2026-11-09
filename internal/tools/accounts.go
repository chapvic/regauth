package tools

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"

	"golang.org/x/crypto/bcrypt"
	"gopkg.in/yaml.v3"
)

const Anonymous = "ANONYMOUS"
const BcryptCost = 12

var (
	ErrUserExists   = errors.New("user already exists")
	ErrUserNotFound = errors.New("user not found")
	ErrAnonymous    = errors.New("ANONYMOUS is a technical account, manage it manually in accounts.yaml")
	ErrEmptyPass    = errors.New("password must not be empty")
	ErrUserLocked   = errors.New("user is locked")
)

type AccountsFile struct {
	Users map[string]*Account `yaml:"users"`
}

type Account struct {
	Password string `yaml:"password,omitempty"`
	Locked   bool   `yaml:"locked,omitempty"`
	Rules    []Rule `yaml:"rules"`
}

type Rule struct {
	Pattern string   `yaml:"pattern"`
	Actions []string `yaml:"actions"`
	Access  string   `yaml:"access"`
}

type Store struct {
	mu   sync.Mutex
	path string
}

func NewStore(path string) *Store { return &Store{path: path} }

func (s *Store) Load() (*AccountsFile, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.loadLocked()
}

func (s *Store) loadLocked() (*AccountsFile, error) {
	data, err := os.ReadFile(s.path)
	if errors.Is(err, os.ErrNotExist) {
		f := defaultAccountsFile()
		if err := s.saveLocked(f); err != nil {
			return nil, err
		}
		return f, nil
	}
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(string(data)) == "" {
		f := defaultAccountsFile()
		if err := s.saveLocked(f); err != nil {
			return nil, err
		}
		return f, nil
	}
	var f AccountsFile
	if err := yaml.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("parse %s: %w", s.path, err)
	}
	if f.Users == nil {
		f.Users = map[string]*Account{}
	}
	if _, ok := f.Users[Anonymous]; !ok {
		f.Users[Anonymous] = &Account{
			Rules: []Rule{{Pattern: "**", Actions: []string{"pull"}, Access: "allow"}},
		}
		if err := s.saveLocked(&f); err != nil {
			return nil, err
		}
	}
	return &f, nil
}

func defaultAccountsFile() *AccountsFile {
	return &AccountsFile{Users: map[string]*Account{
		Anonymous: {Rules: []Rule{{Pattern: "**", Actions: []string{"pull"}, Access: "allow"}}},
	}}
}

func (s *Store) Add(username, password string) error {
	if username == Anonymous {
		return ErrAnonymous
	}
	if password == "" {
		return ErrEmptyPass
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := s.loadLocked()
	if err != nil {
		return err
	}
	if _, ok := f.Users[username]; ok {
		return ErrUserExists
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), BcryptCost)
	if err != nil {
		return err
	}
	f.Users[username] = &Account{Password: string(hash), Locked: false, Rules: []Rule{}}
	return s.saveLocked(f)
}

func (s *Store) Edit(username, password string) error {
	if username == Anonymous {
		return ErrAnonymous
	}
	if password == "" {
		return ErrEmptyPass
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := s.loadLocked()
	if err != nil {
		return err
	}
	u, ok := f.Users[username]
	if !ok {
		return ErrUserNotFound
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), BcryptCost)
	if err != nil {
		return err
	}
	u.Password = string(hash)
	return s.saveLocked(f)
}

func (s *Store) Del(username string) error {
	if username == Anonymous {
		return ErrAnonymous
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := s.loadLocked()
	if err != nil {
		return err
	}
	if _, ok := f.Users[username]; !ok {
		return ErrUserNotFound
	}
	delete(f.Users, username)
	return s.saveLocked(f)
}

// SetLocked устанавливает флаг locked у пользователя. Правила не трогаются.
func (s *Store) SetLocked(username string, locked bool) error {
	if username == Anonymous {
		return ErrAnonymous
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	f, err := s.loadLocked()
	if err != nil {
		return err
	}
	u, ok := f.Users[username]
	if !ok {
		return ErrUserNotFound
	}
	u.Locked = locked
	return s.saveLocked(f)
}

func (s *Store) Reset() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.saveLocked(defaultAccountsFile())
}

func (s *Store) saveLocked(f *AccountsFile) error {
	data, err := yaml.Marshal(f)
	if err != nil {
		return err
	}
	return AtomicWrite(s.path, data, 0o600)
}

// Authenticate: для ANONYMOUS всегда (user, true, true), пароль игнорируется.
// Заблокированный пользователь возвращает (nil, false, false).
func (s *Store) Authenticate(username, password string) (user *Account, isAnon bool, ok bool) {
	s.mu.Lock()
	f, err := s.loadLocked()
	s.mu.Unlock()
	if err != nil {
		return nil, false, false
	}
	if username == Anonymous {
		return f.Users[Anonymous], true, true
	}
	u, exists := f.Users[username]
	if !exists || u.Password == "" || u.Locked {
		return nil, false, false
	}
	if bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(password)) != nil {
		return nil, false, false
	}
	return u, false, true
}
