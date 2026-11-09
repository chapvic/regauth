package tools

import (
	_ "embed"
	"strings"
)

//go:embed VERSION
var versionRaw string

// Version возвращает версию из файла VERSION (обрезает пробелы/переводы строк).
func Version() string {
	return strings.TrimSpace(versionRaw)
}
