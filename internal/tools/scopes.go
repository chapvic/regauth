package tools

import (
	"fmt"
	"strings"
)

type Scope struct {
	Type    string
	Name    string
	Actions []string
}

func ParseScope(s string) ([]Scope, error) {
	if s == "" {
		return nil, nil
	}
	var out []Scope
	for _, part := range strings.Fields(s) {
		segs := strings.SplitN(part, ":", 3)
		if len(segs) != 3 {
			return nil, fmt.Errorf("invalid scope %q", part)
		}
		out = append(out, Scope{
			Type:    segs[0],
			Name:    segs[1],
			Actions: strings.Split(segs[2], ","),
		})
	}
	return out, nil
}

// IsKnownType сообщает, поддерживается ли тип ресурса.
func IsKnownType(t string) bool {
	return t == "repository" || t == "registry"
}
