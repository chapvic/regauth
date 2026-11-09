package tools

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
)

// InitLogger настраивает log/slog.
// Если logFile создать не удалось — не падает, пишет WARN в stderr и логирует
// только в терминал (независимо от toTerminal).
// Возвращает функцию закрытия и признак «лог пишется в файл».
func InitLogger(logFile string, toTerminal bool) (closeFn func(), fileOK bool) {
	if err := os.MkdirAll(filepath.Dir(logFile), 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "WARN: cannot create log dir %s: %v; logging to terminal only\n",
			filepath.Dir(logFile), err)
		setTerminalLogger()
		return func() {}, false
	}
	f, err := os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "WARN: cannot open log file %s: %v; logging to terminal only\n",
			logFile, err)
		setTerminalLogger()
		return func() {}, false
	}

	var w io.Writer = f
	if toTerminal {
		w = io.MultiWriter(f, os.Stderr)
	}
	handler := slog.NewTextHandler(w, &slog.HandlerOptions{Level: slog.LevelInfo})
	slog.SetDefault(slog.New(handler))

	return func() { _ = f.Close() }, true
}

func setTerminalLogger() {
	handler := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})
	slog.SetDefault(slog.New(handler))
}
