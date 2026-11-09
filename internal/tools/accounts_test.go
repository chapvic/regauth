package tools

import (
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestStore_AddEditDel(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "accounts.yaml")
	s := NewStore(path)

	// Load creates default with ANONYMOUS.
	f, err := s.Load()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := f.Users[Anonymous]; !ok {
		t.Fatal("expected ANONYMOUS in default file")
	}

	if err := s.Add("alice", "secret"); err != nil {
		t.Fatal(err)
	}
	if err := s.Add("alice", "other"); err == nil {
		t.Error("expected ErrUserExists on duplicate add")
	}
	if err := s.Add(Anonymous, "x"); err == nil {
		t.Error("expected ErrAnonymous")
	}
	if err := s.Add("bob", ""); err == nil {
		t.Error("expected ErrEmptyPass")
	}

	if err := s.Edit("alice", "newsecret"); err != nil {
		t.Fatal(err)
	}
	if err := s.Edit("nobody", "x"); err == nil {
		t.Error("expected ErrUserNotFound on edit")
	}
	if err := s.Edit(Anonymous, "x"); err == nil {
		t.Error("expected ErrAnonymous on edit")
	}

	if err := s.Del("alice"); err != nil {
		t.Fatal(err)
	}
	if err := s.Del("alice"); err == nil {
		t.Error("expected ErrUserNotFound on second del")
	}
	if err := s.Del(Anonymous); err == nil {
		t.Error("expected ErrAnonymous on del")
	}
}

func TestStore_Authenticate(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "accounts.yaml")
	s := NewStore(path)
	if err := s.Add("alice", "secret"); err != nil {
		t.Fatal(err)
	}

	if _, _, ok := s.Authenticate("alice", "secret"); !ok {
		t.Error("expected ok for correct password")
	}
	if _, _, ok := s.Authenticate("alice", "wrong"); ok {
		t.Error("expected fail for wrong password")
	}
	if _, _, ok := s.Authenticate("nobody", "x"); ok {
		t.Error("expected fail for unknown user")
	}

	// ANONYMOUS always ok, isAnon true, password ignored.
	u, isAnon, ok := s.Authenticate(Anonymous, "anything")
	if !ok || !isAnon {
		t.Error("ANONYMOUS must always authenticate as anonymous")
	}
	if u == nil {
		t.Error("ANONYMOUS user must not be nil")
	}
}

func TestStore_Locked(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "accounts.yaml")
	s := NewStore(path)
	if err := s.Add("alice", "secret"); err != nil {
		t.Fatal(err)
	}

	// Initially not locked.
	if _, _, ok := s.Authenticate("alice", "secret"); !ok {
		t.Error("expected ok before lock")
	}

	// Lock.
	if err := s.SetLocked("alice", true); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := s.Authenticate("alice", "secret"); ok {
		t.Error("expected fail for locked user (even with correct password)")
	}

	// Locked is persisted on disk.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var onDisk AccountsFile
	if err := yaml.Unmarshal(data, &onDisk); err != nil {
		t.Fatal(err)
	}
	if !onDisk.Users["alice"].Locked {
		t.Error("expected locked=true on disk")
	}

	// Rules must be preserved.
	if len(onDisk.Users["alice"].Rules) != 0 {
		t.Errorf("rules must not change on lock, got %d", len(onDisk.Users["alice"].Rules))
	}

	// Unlock.
	if err := s.SetLocked("alice", false); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := s.Authenticate("alice", "secret"); !ok {
		t.Error("expected ok after unlock")
	}
}

func TestStore_Locked_NotFound(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "accounts.yaml")
	s := NewStore(path)
	if err := s.SetLocked("nobody", true); err == nil {
		t.Error("expected ErrUserNotFound")
	}
}

func TestStore_Locked_Anonymous(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "accounts.yaml")
	s := NewStore(path)
	if err := s.SetLocked(Anonymous, true); err != ErrAnonymous {
		t.Errorf("expected ErrAnonymous, got %v", err)
	}
}

func TestStore_Reset(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "accounts.yaml")
	s := NewStore(path)
	if err := s.Add("alice", "secret"); err != nil {
		t.Fatal(err)
	}
	if err := s.Reset(); err != nil {
		t.Fatal(err)
	}
	f, err := s.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Users) != 1 {
		t.Errorf("after reset: %d users, want 1 (ANONYMOUS)", len(f.Users))
	}
	if _, ok := f.Users[Anonymous]; !ok {
		t.Error("after reset: ANONYMOUS missing")
	}
}

func TestStore_AtomicWrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "accounts.yaml")
	s := NewStore(path)
	if err := s.Add("alice", "secret"); err != nil {
		t.Fatal(err)
	}
	// No .tmp-* left behind.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if len(e.Name()) >= 5 && e.Name()[:5] == ".tmp-" {
			t.Errorf("leftover temp file: %s", e.Name())
		}
	}
}

func TestStore_EmptyFileRecreated(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "accounts.yaml")

	emptyData := []byte("  \n\r\n\t  \n")
	if err := os.WriteFile(path, emptyData, 0o600); err != nil {
		t.Fatal(err)
	}

	s := NewStore(path)
	f, err := s.Load()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := f.Users[Anonymous]; !ok {
		t.Error("expected ANONYMOUS in recreated accounts file")
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 {
		t.Error("file should not be empty after Load()")
	}
}

func TestStore_AnonymousMissingRecreated(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "accounts.yaml")

	f := &AccountsFile{Users: map[string]*Account{
		"alice": {Password: "$2a$12$dummy", Rules: []Rule{}},
	}}
	data, err := yaml.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}

	s := NewStore(path)
	loaded, err := s.Load()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := loaded.Users[Anonymous]; !ok {
		t.Error("expected ANONYMOUS to be recreated when missing")
	}

	u, isAnon, ok := s.Authenticate(Anonymous, "anything")
	if !ok || !isAnon || u == nil {
		t.Error("ANONYMOUS must authenticate as anonymous with non-nil user")
	}

	data, err = os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var onDisk AccountsFile
	if err := yaml.Unmarshal(data, &onDisk); err != nil {
		t.Fatal(err)
	}
	if _, ok := onDisk.Users[Anonymous]; !ok {
		t.Error("expected ANONYMOUS to be saved to disk")
	}
}
