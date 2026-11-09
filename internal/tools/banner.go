package tools

import (
	"fmt"
	"os"
)

// PrintBanner печатает баннер в stdout. Всегда, независимо от logterm.
func PrintBanner() {
	fmt.Printf("RegAuth - Registry Authentication Provider, v%s\n", Version())
	fmt.Println("Copyright (c) 2026, Chapvic")
	fmt.Println()
}

// PrintStartupSummary печатает основные технические детали старта в stderr.
// Всегда, независимо от logterm: даже если лог ушёл в файл, администратор
// должен видеть, что и где запущено.
func PrintStartupSummary(registry, addr string, tls, insecure bool, pidFile, kid string) {
	fmt.Fprintf(os.Stderr, "regauth v%s\n", Version())
	fmt.Fprintf(os.Stderr, "  registry:  %s\n", registry)
	fmt.Fprintf(os.Stderr, "  listen:    %s\n", addr)
	if tls {
		fmt.Fprintf(os.Stderr, "  protocol:  https\n")
	} else {
		fmt.Fprintf(os.Stderr, "  protocol:  http\n")
	}
	if insecure {
		fmt.Fprintf(os.Stderr, "  insecure:  true (Origin filtering disabled)\n")
	}
	fmt.Fprintf(os.Stderr, "  pid_file:  %s\n", pidFile)
	fmt.Fprintf(os.Stderr, "  kid:       %s\n", kid)
	fmt.Fprintln(os.Stderr)
}
