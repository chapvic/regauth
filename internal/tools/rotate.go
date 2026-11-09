package tools

import (
	"fmt"
	"syscall"
)

// NotifyRunning посылает SIGHUP процессу из pid-файла, если это regauth
// (проверка по starttime). Возвращает (pid, nil) при успехе,
// (0, nil) если сервер не запущен (нет файла/мёртв/pid переиспользован),
// ошибку при проблемах с pid-файлом или сигналом.
func NotifyRunning(pidPath string) (int, error) {
	pid, err := ReadRunningPID(pidPath)
	if err != nil {
		return 0, err
	}
	if pid == 0 {
		return 0, nil
	}
	if err := syscall.Kill(pid, syscall.SIGHUP); err != nil {
		return pid, fmt.Errorf("send SIGHUP to pid %d: %w", pid, err)
	}
	return pid, nil
}
