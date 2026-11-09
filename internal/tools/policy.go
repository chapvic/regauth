package tools

import (
	"fmt"
	"strings"
)

// Resource types.
const (
	ResourceRepository = "repository"
	ResourceRegistry   = "registry"
)

// CatalogName — имя ресурса типа registry для каталога.
const CatalogName = "catalog"

// Evaluate вычисляет, разрешено ли действие action для ресурса (type, name)
// на основе правил пользователя. Семантика:
//   - правило применимо, только если его тип ресурса совпадает с type;
//   - тип правила определяется по pattern: "catalog" → registry, иначе repository;
//   - deny перекрывает allow; нет allow — запрет (deny by default).
func Evaluate(rules []Rule, resourceType, name, action string) bool {
	allowed := false
	for _, r := range rules {
		if resourceTypeOf(r.Pattern) != resourceType {
			continue
		}
		if !Match(r.Pattern, name) {
			continue
		}
		if !actionMatches(r.Actions, action) {
			continue
		}
		switch r.Access {
		case "deny":
			return false
		case "allow":
			allowed = true
		}
	}
	return allowed
}

// GrantedActions возвращает подмножество requested, разрешённое правилами
// для ресурса (resourceType, name).
func GrantedActions(rules []Rule, resourceType, name string, requested []string) []string {
	out := make([]string, 0, len(requested))
	for _, a := range requested {
		if Evaluate(rules, resourceType, name, a) {
			out = append(out, a)
		}
	}
	return out
}

// resourceTypeOf определяет тип ресурса по pattern правила.
// "catalog" — registry, всё остальное — repository.
func resourceTypeOf(pattern string) string {
	if pattern == CatalogName {
		return ResourceRegistry
	}
	return ResourceRepository
}

// actionMatches сообщает, покрывает ли список actions действие action.
// Для pattern "catalog" пустой список actions трактуется как ["*"].
func actionMatches(actions []string, action string) bool {
	if len(actions) == 0 {
		// Пустой actions допустим только для catalog (см. ValidateRule),
		// где он трактуется как "*".
		return action == "*"
	}
	for _, a := range actions {
		if a == "*" || a == action {
			return true
		}
	}
	return false
}

func Match(pattern, name string) bool {
	return matchSegments(strings.Split(pattern, "/"), strings.Split(name, "/"))
}

func matchSegments(pat, seg []string) bool {
	if len(pat) == 0 {
		return len(seg) == 0
	}
	if pat[0] == "**" {
		for i := 0; i <= len(seg); i++ {
			if matchSegments(pat[1:], seg[i:]) {
				return true
			}
		}
		return false
	}
	if len(seg) == 0 {
		return false
	}
	if !wildcardMatch(pat[0], seg[0]) {
		return false
	}
	return matchSegments(pat[1:], seg[1:])
}

func wildcardMatch(p, s string) bool {
	if p == "" {
		return s == ""
	}
	switch p[0] {
	case '*':
		for i := 0; i <= len(s); i++ {
			if wildcardMatch(p[1:], s[i:]) {
				return true
			}
		}
		return false
	case '?':
		if s == "" {
			return false
		}
		return wildcardMatch(p[1:], s[1:])
	default:
		if s == "" || s[0] != p[0] {
			return false
		}
		return wildcardMatch(p[1:], s[1:])
	}
}

// ValidateRule проверяет корректность правила при загрузке.
// Для pattern == "catalog" поле actions необязательно (трактуется как ["*"]).
// Для остальных pattern actions обязателен и может содержать только
// pull/push/delete/*.
func ValidateRule(r Rule) error {
	if r.Pattern == "" {
		return fmt.Errorf("rule pattern is empty")
	}
	if r.Pattern != CatalogName && len(r.Actions) == 0 {
		return fmt.Errorf("rule actions is empty (pattern %q)", r.Pattern)
	}
	for _, a := range r.Actions {
		if a != "*" && a != "pull" && a != "push" && a != "delete" {
			return fmt.Errorf("unknown action %q (pattern %q)", a, r.Pattern)
		}
	}
	if r.Access != "allow" && r.Access != "deny" {
		return fmt.Errorf("access must be allow or deny, got %q (pattern %q)", r.Access, r.Pattern)
	}
	return nil
}
