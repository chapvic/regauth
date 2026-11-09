package tools

import (
	"fmt"
	"os"
	"os/exec"
)

// RunCommand запускает внешнюю команду без shell, передавая ей
// дополнительное окружение. Стримит stdout/stderr в консоль.
// Если argv пуст — ничего не запускает и возвращает nil.
func RunCommand(argv []string, extraEnv []string) error {
	if len(argv) == 0 {
		return nil
	}
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	cmd.Env = append(os.Environ(), extraEnv...)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("exec %v: %w", argv, err)
	}
	return nil
}
