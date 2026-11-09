package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"regauth/internal/tools"
)

func banner() string {
	return fmt.Sprintf(`RegAuth - Registry Authentication Provider, v%s
Copyright (c) 2026, Chapvic
`, tools.Version())
}

func main() {
	args := os.Args[1:]
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" {
		usage()
		return
	}

	switch args[0] {
	case "server":
		runServer(args[1:])
	case "keystore":
		runKeystore(args[1:])
	default:
		fmt.Fprintf(os.Stderr, "error: unknown command %q\n\n", args[0])
		usage()
		os.Exit(1)
	}
}

func runServer(args []string) {
	fs := flag.NewFlagSet("server", flag.ExitOnError)
	var (
		cfgPath  = fs.String("c", "", "path to config.yaml")
		insecure = fs.Bool("insecure", false, "disable Origin filtering (overrides config)")
	)
	fs.Usage = func() { usageServer(fs) }
	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}
	if fs.NArg() > 0 {
		fatal(fmt.Errorf("unexpected argument %q", fs.Arg(0)))
	}

	cfg, err := tools.LoadConfig(*cfgPath)
	if err != nil {
		fatal(err)
	}
	if *insecure {
		cfg.Server.Insecure = true
	}

	closeLog, _ := tools.InitLogger(cfg.LogFilePath(), cfg.LogToTerminal())
	defer closeLog()

	if cfg.Server.Registry == "" {
		if cfg.WasCreated() {
			store := tools.NewStore(cfg.AccountsPath())
			if _, err := store.Load(); err != nil {
				fatal(err)
			}
			tools.PrintBanner()
			fmt.Printf(`Config and keystore were created:
  config:     %s
  keystore:   %s
  accounts:   %s
  public v2:  %s
  public v3:  %s
  log:        %s

Set "server.registry" in the config file before starting the server.

`, cfg.ConfigPath(), cfg.KeystorePath(), cfg.AccountsPath(),
				cfg.PublicV2Path(), cfg.PublicV3Path(), cfg.LogFilePath())
			os.Exit(0)
		}
		fatal(fmt.Errorf("server.registry is required in config"))
	}

	useTLS := cfg.Server.TLS.CertFile != "" && cfg.Server.TLS.KeyFile != ""
	if cfg.Server.TLS.Enabled != nil {
		useTLS = *cfg.Server.TLS.Enabled
		if useTLS && (cfg.Server.TLS.CertFile == "" || cfg.Server.TLS.KeyFile == "") {
			fatal(fmt.Errorf("tls.enabled=true requires cert_file and key_file"))
		}
	}

	pidPath := cfg.PIDFilePath()
	if err := tools.AcquireLock(pidPath); err != nil {
		fatal(err)
	}
	defer tools.ReleaseLock(pidPath)

	store := tools.NewStore(cfg.AccountsPath())
	f, err := store.Load()
	if err != nil {
		fatal(err)
	}
	if err := validateAccounts(f); err != nil {
		fatal(err)
	}

	handler := tools.NewHandler(store, cfg, cfg.Server.Insecure, cfg.PublicV3Path())

	addr := fmt.Sprintf(":%d", cfg.Server.Port)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	go func() {
		for range hup {
			slog.Info("reload: SIGHUP received")
			newCfg, err := tools.LoadConfig(cfg.ConfigPath())
			if err != nil {
				slog.Error("reload: load config failed", "err", err)
				continue
			}
			newCfg.Server.Registry = cfg.Server.Registry
			newCfg.Server.Insecure = cfg.Server.Insecure
			if newCfg.Server.TLS.CertFile == "" {
				newCfg.Server.TLS.CertFile = cfg.Server.TLS.CertFile
			}
			if newCfg.Server.TLS.KeyFile == "" {
				newCfg.Server.TLS.KeyFile = cfg.Server.TLS.KeyFile
			}
			newStore := tools.NewStore(newCfg.AccountsPath())
			nf, err := newStore.Load()
			if err != nil {
				slog.Error("reload: load accounts failed", "err", err)
				continue
			}
			if err := validateAccounts(nf); err != nil {
				slog.Error("reload: accounts validation failed", "err", err)
				continue
			}
			handler.Reload(newStore, newCfg, newCfg.PublicV3Path())
			cfg = newCfg
			slog.Info("reload: done")
		}
	}()

	kidStr := "(not applicable)"
	if _, kid, err := cfg.SigningKey(); err == nil && kid != "" {
		kidStr = kid
	} else if err != nil {
		kidStr = "(error: " + err.Error() + ")"
	}

	tools.PrintBanner()
	tools.PrintStartupSummary(cfg.Server.Registry, addr, useTLS, cfg.Server.Insecure, pidPath, kidStr)

	slog.Info("regauth starting",
		"version", tools.Version(),
		"addr", addr,
		"registry", cfg.Server.Registry,
		"tls", useTLS,
		"insecure", cfg.Server.Insecure,
		"pid_file", pidPath,
		"log_file", cfg.LogFilePath(),
		"kid", kidStr,
	)
	if err := tools.RunServer(ctx, addr, handler, cfg.Server.TLS.CertFile, cfg.Server.TLS.KeyFile); err != nil {
		fatal(err)
	}
	slog.Info("regauth stopped")
}

func runKeystore(args []string) {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" {
		usageKeystore()
		return
	}
	sub := args[0]
	rest := args[1:]

	switch sub {
	case "list":
		keystoreList(rest)
	case "rotate":
		keystoreRotate(rest)
	case "rotate-v2":
		keystoreRotateV2(rest)
	case "revoke":
		keystoreRevoke(rest)
	case "delete":
		keystoreDelete(rest)
	case "cleanup":
		keystoreCleanup(rest)
	default:
		fmt.Fprintf(os.Stderr, "error: unknown keystore command %q\n\n", sub)
		usageKeystore()
		os.Exit(1)
	}
}

func keystoreList(args []string) {
	fs := flag.NewFlagSet("keystore list", flag.ExitOnError)
	cfgPath := fs.String("c", "", "path to config.yaml")
	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}
	cfg, err := tools.LoadConfig(*cfgPath)
	if err != nil {
		fatal(err)
	}
	ks, err := tools.LoadKeystore(cfg.KeystorePath())
	if err != nil {
		fatal(err)
	}

	fmt.Println("v2:")
	if ks.V2.Private == "" {
		fmt.Println("  (no key)")
	} else {
		fmt.Printf("  created: %s\n", ks.V2.CreatedAt.Format(time.RFC3339))
	}

	fmt.Println("v3:")
	if len(ks.V3.Keys) == 0 {
		fmt.Println("  (no keys)")
		return
	}
	fmt.Printf("  %-42s %-20s %-8s %-8s\n", "KID", "CREATED", "CURRENT", "REVOKED")
	current, revoked := 0, 0
	for _, e := range ks.V3.Keys {
		cur, rev := "no", "no"
		if e.Current {
			cur = "yes"
			current++
		}
		if e.Revoked {
			rev = "yes"
			revoked++
		}
		fmt.Printf("  %-42s %-20s %-8s %-8s\n",
			e.KID, e.CreatedAt.Format(time.RFC3339), cur, rev)
	}
	fmt.Printf("  total: %d, current: %d, revoked: %d\n", len(ks.V3.Keys), current, revoked)
}

func keystoreRotate(args []string) {
	fs := flag.NewFlagSet("keystore rotate", flag.ExitOnError)
	cfgPath := fs.String("c", "", "path to config.yaml")
	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}
	cfg, err := tools.LoadConfig(*cfgPath)
	if err != nil {
		fatal(err)
	}
	closeLog, _ := tools.InitLogger(cfg.LogFilePath(), cfg.LogToTerminal())
	defer closeLog()

	kid, err := cfg.RotateV3()
	if err != nil {
		fatal(err)
	}
	fmt.Printf("rotated v3 signing key: %s\n", kid)

	env := []string{
		"REGAUTH_OPERATION=rotate",
		"REGAUTH_KEY_VERSION=3",
		"REGAUTH_KID=" + kid,
	}

	pid, err := tools.NotifyRunning(cfg.PIDFilePath())
	if err != nil {
		fatal(err)
	}
	if pid == 0 {
		fmt.Println("no running regauth found; new key will be used on next start")
		return
	}
	fmt.Printf("SIGHUP sent to running regauth (pid %d)\n", pid)
	runExec(cfg.Server.Keystore.Rotate, env)
}

func keystoreRotateV2(args []string) {
	fs := flag.NewFlagSet("keystore rotate-v2", flag.ExitOnError)
	cfgPath := fs.String("c", "", "path to config.yaml")
	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}
	cfg, err := tools.LoadConfig(*cfgPath)
	if err != nil {
		fatal(err)
	}
	closeLog, _ := tools.InitLogger(cfg.LogFilePath(), cfg.LogToTerminal())
	defer closeLog()

	if err := cfg.RotateV2(); err != nil {
		fatal(err)
	}
	fmt.Println("rotated v2 signing key")
	fmt.Println("old v2 tokens will stop verifying after registry reloads rootcertbundle")

	env := []string{
		"REGAUTH_OPERATION=rotate-v2",
		"REGAUTH_KEY_VERSION=2",
	}
	runExec(cfg.Server.Keystore.RotateV2, env)
}

func keystoreRevoke(args []string) {
	fs := flag.NewFlagSet("keystore revoke", flag.ExitOnError)
	cfgPath := fs.String("c", "", "path to config.yaml")
	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}
	if fs.NArg() != 1 {
		fatal(fmt.Errorf("usage: regauth keystore revoke <kid> [-c <config>]"))
	}
	kid := fs.Arg(0)
	cfg, err := tools.LoadConfig(*cfgPath)
	if err != nil {
		fatal(err)
	}
	closeLog, _ := tools.InitLogger(cfg.LogFilePath(), cfg.LogToTerminal())
	defer closeLog()

	if err := cfg.RevokeV3(kid); err != nil {
		fatal(err)
	}
	fmt.Printf("revoked v3 key: %s\n", kid)

	env := []string{
		"REGAUTH_OPERATION=revoke",
		"REGAUTH_KEY_VERSION=3",
		"REGAUTH_KID=" + kid,
	}
	runExec(cfg.Server.Keystore.Revoke, env)
}

func keystoreDelete(args []string) {
	fs := flag.NewFlagSet("keystore delete", flag.ExitOnError)
	cfgPath := fs.String("c", "", "path to config.yaml")
	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}
	if fs.NArg() != 1 {
		fatal(fmt.Errorf("usage: regauth keystore delete <kid> [-c <config>]"))
	}
	kid := fs.Arg(0)
	cfg, err := tools.LoadConfig(*cfgPath)
	if err != nil {
		fatal(err)
	}
	closeLog, _ := tools.InitLogger(cfg.LogFilePath(), cfg.LogToTerminal())
	defer closeLog()

	if err := cfg.DeleteV3(kid); err != nil {
		fatal(err)
	}
	fmt.Printf("deleted v3 key: %s\n", kid)

	env := []string{
		"REGAUTH_OPERATION=delete",
		"REGAUTH_KEY_VERSION=3",
		"REGAUTH_KID=" + kid,
	}
	runExec(cfg.Server.Keystore.Delete, env)
}

func keystoreCleanup(args []string) {
	fs := flag.NewFlagSet("keystore cleanup", flag.ExitOnError)
	cfgPath := fs.String("c", "", "path to config.yaml")
	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}
	cfg, err := tools.LoadConfig(*cfgPath)
	if err != nil {
		fatal(err)
	}
	closeLog, _ := tools.InitLogger(cfg.LogFilePath(), cfg.LogToTerminal())
	defer closeLog()

	n, err := cfg.CleanupV3()
	if err != nil {
		fatal(err)
	}
	fmt.Printf("cleaned up %d revoked key(s)\n", n)

	env := []string{
		"REGAUTH_OPERATION=cleanup",
		"REGAUTH_KEY_VERSION=3",
		fmt.Sprintf("REGAUTH_REMOVED=%d", n),
	}
	runExec(cfg.Server.Keystore.Cleanup, env)
}

func runExec(argv []string, env []string) {
	if len(argv) == 0 {
		return
	}
	slog.Info("keystore: running exec", "argv", argv)
	if err := tools.RunCommand(argv, env); err != nil {
		fatal(err)
	}
	slog.Info("keystore: exec ok")
}

func validateAccounts(f *tools.AccountsFile) error {
	for name, u := range f.Users {
		if name == tools.Anonymous {
			if u.Password != "" {
				slog.Warn("ANONYMOUS entry has password field, it will be ignored")
			}
			continue
		}
		if u.Password == "" {
			return fmt.Errorf("user %q has no password", name)
		}
		for _, r := range u.Rules {
			if err := tools.ValidateRule(r); err != nil {
				return fmt.Errorf("user %q: %w", name, err)
			}
		}
	}
	return nil
}

func usage() {
	tools.PrintBanner()
	fmt.Print(`
Usage:
  regauth server [-c <config>] [-insecure]
  regauth keystore <command> [-c <config>]
  regauth -h

Commands:
  server                       Run the token server
  keystore list                List v2 and v3 keys
  keystore rotate              Rotate v3 signing key (old keys kept in JWKS)
  keystore rotate-v2           Rotate v2 signing key (single key; old tokens stop verifying)
  keystore revoke <kid>        Revoke a v3 key and remove it from JWKS
  keystore delete <kid>        Delete a revoked v3 key
  keystore cleanup             Delete all revoked v3 keys

Options:
  -c <path>        Path to config.yaml (default: next to binary)
  -insecure        server only: disable Origin filtering (overrides config, for tests)
  -h               Show this help

Endpoints (server):
  /token                       Docker Registry token endpoint
  /.well-known/jwks.json       JWKS (same content as public-v3.key)

Signals:
  SIGHUP           Reload config.yaml and accounts.yaml (new key takes effect)

Notes:
  keystore.yaml is the single source of truth for v2 and v3 private keys.
  public-v2.key and public-v3.key are derived from it and recreated on start.
  All server settings are read from config.yaml. CLI only overrides -c and -insecure.
  keys_version (2 or 3, default 3) selects the signing key for all tokens.
  keystore revoke removes the key from JWKS immediately; a running registry must
  reload JWKS to take effect (use server.keystore.*.exec).
  rotate-v2 replaces the single v2 key; old v2 tokens stop verifying after the
  registry reloads rootcertbundle (use server.keystore.rotate_v2.exec).

Exec hooks:
  server.keystore.*.exec are argv lists (no shell) run after the operation.
  The child process receives environment variables:
    REGAUTH_OPERATION   - rotate | rotate-v2 | revoke | delete | cleanup
    REGAUTH_KEY_VERSION - 3 (for v3 operations) or 2 (for rotate-v2)
    REGAUTH_KID         - the key id (for rotate, revoke, delete)
    REGAUTH_REMOVED     - number of removed keys (for cleanup)

User management:
  Use reguser add|edit|del|clean|hash.
`)
}

func usageServer(fs *flag.FlagSet) {
	tools.PrintBanner()
	fmt.Print(`
Usage:
  regauth server [-c <config>] [-insecure]

Options:
`)
	fs.PrintDefaults()
	fmt.Print(`
All other settings (registry, port, TLS, pid_file, logfile, logterm, keys_version) are in config.yaml.
Endpoints: /token and /.well-known/jwks.json.
`)
}

func usageKeystore() {
	tools.PrintBanner()
	fmt.Print(`
Usage:
  regauth keystore list [-c <config>]
  regauth keystore rotate [-c <config>]
  regauth keystore rotate-v2 [-c <config>]
  regauth keystore revoke <kid> [-c <config>]
  regauth keystore delete <kid> [-c <config>]
  regauth keystore cleanup [-c <config>]

Commands:
  list       List v2 and v3 keys (kid, created, current, revoked)
  rotate     Rotate v3 signing key; old keys kept in JWKS; SIGHUP running server
  rotate-v2  Rotate v2 signing key (single key; old tokens stop verifying)
  revoke     Revoke a v3 key and remove it from JWKS (cannot revoke current key)
  delete     Delete a revoked v3 key (only revoked keys can be deleted)
  cleanup    Delete all revoked v3 keys

Options:
  -c <path>   Path to config.yaml (default: next to binary)

Exec hooks (config):
  server.keystore.rotate, .rotate_v2, .revoke, .delete, .cleanup —
  argv lists (no shell) run after success.
  Environment for the child process:
    REGAUTH_OPERATION   - rotate | rotate-v2 | revoke | delete | cleanup
    REGAUTH_KEY_VERSION - 3 (for v3 operations) or 2 (for rotate-v2)
    REGAUTH_KID         - the key id (for rotate, revoke, delete)
    REGAUTH_REMOVED     - number of removed keys (for cleanup)
`)
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "error: %v\n", err)
	os.Exit(1)
}
