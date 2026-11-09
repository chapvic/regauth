package tools

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

var ErrAlreadyRunning = errors.New("another regauth instance is already running")

// lockFile хранит fd на всё время работы сервера; flock снимается ядром
// при завершении процесса (включая SIGKILL).
type lockFile struct {
	path string
	file *os.File
}

var currentLock *lockFile

// AcquireLock берёт эксклюзивный flock на pidPath и записывает "pid starttime".
// Если lock занят — ErrAlreadyRunning.
func AcquireLock(pidPath string) error {
	f, err := os.OpenFile(pidPath, os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return fmt.Errorf("cannot acquire lock at %s: %w; set server.pid_file to a writable path", pidPath, err)
	}

	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			return fmt.Errorf("%w (%s)", ErrAlreadyRunning, pidPath)
		}
		return fmt.Errorf("cannot acquire lock at %s: %w", pidPath, err)
	}

	// Мы держим lock. Перезаписываем файл своим pid и starttime.
	start, err := processStartTicks(os.Getpid())
	if err != nil {
		// Не критично для блокировки: starttime нужен только для NotifyRunning.
		start = 0
	}
	if err := f.Truncate(0); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Seek(0, 0); err != nil {
		f.Close()
		return err
	}
	if _, err := fmt.Fprintf(f, "%d %d\n", os.Getpid(), start); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}

	currentLock = &lockFile{path: pidPath, file: f}
	return nil
}

// ReleaseLock снимает flock и удаляет pid-файл (если он наш).
func ReleaseLock(pidPath string) {
	if currentLock == nil || currentLock.path != pidPath {
		return
	}
	// Удаляем файл до снятия lock, чтобы не оставить "пустой" файл.
	_ = os.Remove(pidPath)
	_ = unix.Flock(int(currentLock.file.Fd()), unix.LOCK_UN)
	_ = currentLock.file.Close()
	currentLock = nil
}

// ReadRunningPID читает pid из pidPath и проверяет, что процесс жив И его
// starttime совпадает с записанным. Возвращает 0, nil если файла нет,
// процесс мёртв или pid переиспользован.
func ReadRunningPID(pidPath string) (int, error) {
	data, err := os.ReadFile(pidPath)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	parts := strings.Fields(strings.TrimSpace(string(data)))
	if len(parts) != 2 {
		return 0, fmt.Errorf("malformed pid file %s", pidPath)
	}
	pid, err := strconv.Atoi(parts[0])
	if err != nil || pid <= 0 {
		return 0, fmt.Errorf("malformed pid in %s", pidPath)
	}
	recordedStart, err := strconv.ParseUint(parts[1], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("malformed starttime in %s", pidPath)
	}

	if recordedStart == 0 {
		// starttime не был записан (не удалось прочитать при старте).
		// Проверяем только живость процесса — это менее надёжно, но лучше,
		// чем ничего.
		if !processAlive(pid) {
			return 0, nil
		}
		return pid, nil
	}

	actualStart, err := processStartTicks(pid)
	if err != nil {
		// Процесс мёртв или /proc недоступен.
		return 0, nil
	}
	if actualStart != recordedStart {
		// PID переиспользован другим процессом.
		return 0, nil
	}
	return pid, nil
}

// processStartTicks читает поле 22 (/proc/<pid>/stat, starttime) — тики
// с момента загрузки системы. Зафиксировано на всё время жизни процесса.
func processStartTicks(pid int) (uint64, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, err
	}
	// Поле comm (2) в скобках и может содержать пробелы и скобки.
	// Безопасный якорь — последняя ')'.
	rparen := strings.LastIndexByte(string(data), ')')
	if rparen < 0 || rparen+1 >= len(data) {
		return 0, fmt.Errorf("malformed /proc/%d/stat", pid)
	}
	fields := strings.Fields(string(data[rparen+1:]))
	// После comm идёт state (поле 3), поэтому starttime (поле 22) — индекс 19.
	const startTimeIdx = 19
	if len(fields) <= startTimeIdx {
		return 0, fmt.Errorf("/proc/%d/stat: too few fields", pid)
	}
	ticks, err := strconv.ParseUint(fields[startTimeIdx], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse starttime: %w", err)
	}
	return ticks, nil
}

func processAlive(pid int) bool {
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	return p.Signal(unix.Signal(0)) == nil
}
