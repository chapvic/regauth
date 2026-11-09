package main

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strings"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/term"

	"regauth/internal/tools"
)

func banner() string {
	return fmt.Sprintf(`RegUser - RAP Account Manager, v%s
Copyright (c) 2026, Chapvic
`, tools.Version())
}

func main() {
	args := os.Args[1:]
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" {
		usage()
		return
	}

	cmd := args[0]
	switch cmd {
	case "list", "add", "edit", "del", "lock", "clean", "hash":
		// known
	default:
		fmt.Fprintf(os.Stderr, "error: unknown command %q\n\n", cmd)
		usage()
		os.Exit(1)
	}

	var (
		username string
		password string
		cfgPath  string
		force    bool
		hasPass  bool
		showAll  bool
		count    bool
		lockVal  *bool
	)

	rest := args[1:]
	for i := 0; i < len(rest); i++ {
		switch rest[i] {
		case "-p":
			if i+1 >= len(rest) {
				fatal(fmt.Errorf("-p requires a value"))
			}
			password = rest[i+1]
			hasPass = true
			i++
		case "-c":
			if i+1 >= len(rest) {
				fatal(fmt.Errorf("-c requires a value"))
			}
			cfgPath = rest[i+1]
			i++
		case "-f":
			force = true
		case "-all":
			showAll = true
		case "-count":
			count = true
		case "-lock":
			v := true
			lockVal = &v
		case "-unlock":
			v := false
			lockVal = &v
		default:
			if username == "" && !strings.HasPrefix(rest[i], "-") {
				username = rest[i]
			} else {
				fatal(fmt.Errorf("unexpected argument %q", rest[i]))
			}
		}
	}

	if cmd == "hash" {
		runHash(password, hasPass)
		return
	}

	if cmd != "list" && cmd != "clean" && username == "" {
		usage()
		fatal(fmt.Errorf("username required"))
	}

	cfg, err := tools.LoadConfig(cfgPath)
	if err != nil {
		fatal(err)
	}
	store := tools.NewStore(cfg.AccountsPath())

	switch cmd {
	case "list":
		runList(store, showAll, count)
	case "add":
		if !hasPass {
			password, err = promptPassword(true)
			if err != nil {
				fatal(err)
			}
		}
		if err := store.Add(username, password); err != nil {
			fatal(err)
		}
		fmt.Printf("user %q added\n", username)
	case "edit":
		if !hasPass {
			password, err = promptPassword(true)
			if err != nil {
				fatal(err)
			}
		}
		if err := store.Edit(username, password); err != nil {
			fatal(err)
		}
		fmt.Printf("user %q password updated\n", username)
	case "del":
		if err := store.Del(username); err != nil {
			fatal(err)
		}
		fmt.Printf("user %q deleted\n", username)
	case "lock":
		if lockVal == nil {
			fatal(fmt.Errorf("lock requires -lock or -unlock"))
		}
		if err := store.SetLocked(username, *lockVal); err != nil {
			fatal(err)
		}
		if *lockVal {
			fmt.Printf("user %q locked\n", username)
		} else {
			fmt.Printf("user %q unlocked\n", username)
		}
	case "clean":
		if !force {
			if !confirm("Delete ALL users and reset ANONYMOUS to default? [y/N]: ") {
				fmt.Println("aborted")
				return
			}
		}
		if err := store.Reset(); err != nil {
			fatal(err)
		}
		fmt.Printf("accounts reset: all users removed, ANONYMOUS recreated with default rules\n")
	}
}

func runList(store *tools.Store, showAll, countOnly bool) {
	f, err := store.Load()
	if err != nil {
		fatal(err)
	}

	var names []string
	for name := range f.Users {
		if name == tools.Anonymous && !showAll {
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)

	if countOnly {
		fmt.Println(len(names))
		return
	}

	if len(names) == 0 {
		fmt.Println("no users")
		return
	}

	fmt.Printf("%-20s %-10s %-6s %-6s\n", "USERNAME", "TYPE", "LOCKED", "RULES")
	fmt.Println(strings.Repeat("-", 44))
	for _, name := range names {
		u := f.Users[name]
		typ := "user"
		if name == tools.Anonymous {
			typ = "anonymous"
		}
		locked := "no"
		if u.Locked {
			locked = "yes"
		}
		fmt.Printf("%-20s %-10s %-6s %-6d\n", name, typ, locked, len(u.Rules))
	}
}

func runHash(password string, hasPass bool) {
	if !hasPass {
		pwd, err := promptPassword(true)
		if err != nil {
			fatal(err)
		}
		password = pwd
	}
	if password == "" {
		fatal(fmt.Errorf("empty password"))
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), tools.BcryptCost)
	if err != nil {
		fatal(err)
	}
	fmt.Println(string(hash))
}

func promptPassword(confirmPwd bool) (string, error) {
	fmt.Fprint(os.Stderr, "Password: ")
	p1, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	if !confirmPwd {
		return string(p1), nil
	}
	fmt.Fprint(os.Stderr, "Confirm: ")
	p2, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return "", err
	}
	if string(p1) != string(p2) {
		return "", fmt.Errorf("passwords do not match")
	}
	return string(p1), nil
}

func confirm(prompt string) bool {
	fmt.Fprint(os.Stderr, prompt)
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
	line = strings.TrimSpace(strings.ToLower(line))
	return line == "y" || line == "yes"
}

func usage() {
	fmt.Print(banner())
	fmt.Print(`
Usage:
  reguser list [-c <config>] [-all] [-count]
  reguser add <username> [-p <password>] [-c <config>]
  reguser edit <username> [-p <new-password>] [-c <config>]
  reguser del <username> [-c <config>]
  reguser lock <username> -lock|-unlock [-c <config>]
  reguser clean [-f] [-c <config>]
  reguser hash [-p <password>]
  reguser -h

Options:
  -p <password>   Password in plaintext (for automation; omit for interactive prompt)
  -c <config>     Path to config.yaml (default: next to binary)
  -f              For clean: do not ask for confirmation
  -all            For list: include ANONYMOUS in the output and count
  -count          For list: print only the number of users
  -lock           For lock: set locked=true
  -unlock         For lock: set locked=false
  -h              Show this help

Commands:
  list     List users (name, type, locked, rule count). ANONYMOUS excluded by default.
  add      Add a new user
  edit     Change user password
  del      Delete a user
  lock     Lock or unlock a user without touching rules
  clean    Delete ALL users and recreate ANONYMOUS with default rules
  hash     Print bcrypt hash for a password (no config needed)
`)
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "error: %v\n", err)
	os.Exit(1)
}
