package tools

import "testing"

func TestMatch(t *testing.T) {
	cases := []struct {
		pattern, name string
		want          bool
	}{
		{"**", "actions/project", true},
		{"**", "", true},
		{"actions/*", "actions/project", true},
		{"actions/*", "actions/project/v2", false},
		{"actions/**", "actions", true},
		{"actions/**", "actions/project/v2", true},
		{"actions/**", "actions/", true},
		{"actions/**", "other/project", false},
		{"library/ubuntu", "library/ubuntu", true},
		{"library/ubuntu", "library/ubuntu:latest", false},
		{"lib?ary", "library", true},
		{"lib?ary", "libary", false},
		{"*", "single", true},
		{"*", "a/b", false},
		{"**/secret/**", "actions/secret/project", true},
		{"**/secret/**", "actions/public/project", false},
	}
	for _, c := range cases {
		if got := Match(c.pattern, c.name); got != c.want {
			t.Errorf("Match(%q, %q) = %v, want %v", c.pattern, c.name, got, c.want)
		}
	}
}

func TestEvaluate_DenyWins(t *testing.T) {
	rules := []Rule{
		{Pattern: "actions/**", Actions: []string{"pull", "push"}, Access: "allow"},
		{Pattern: "actions/secret/**", Actions: []string{"*"}, Access: "deny"},
	}
	if !Evaluate(rules, ResourceRepository, "actions/public/x", "pull") {
		t.Error("expected allow for actions/public/x pull")
	}
	if Evaluate(rules, ResourceRepository, "actions/secret/x", "pull") {
		t.Error("expected deny for actions/secret/x pull (deny wins)")
	}
	if Evaluate(rules, ResourceRepository, "actions/secret/x", "push") {
		t.Error("expected deny for actions/secret/x push (deny wins)")
	}
}

func TestEvaluate_DenyByDefault(t *testing.T) {
	rules := []Rule{
		{Pattern: "library/*", Actions: []string{"pull"}, Access: "allow"},
	}
	if !Evaluate(rules, ResourceRepository, "library/ubuntu", "pull") {
		t.Error("expected allow for library/ubuntu pull")
	}
	if Evaluate(rules, ResourceRepository, "library/ubuntu", "push") {
		t.Error("expected deny for library/ubuntu push (action not granted)")
	}
	if Evaluate(rules, ResourceRepository, "other/repo", "pull") {
		t.Error("expected deny for other/repo pull (no matching rule)")
	}
	if Evaluate(rules, ResourceRepository, "library/ubuntu/v2", "pull") {
		t.Error("library/* must not match library/ubuntu/v2")
	}
}

func TestEvaluate_EmptyRules(t *testing.T) {
	if Evaluate(nil, ResourceRepository, "any", "pull") {
		t.Error("empty rules must deny")
	}
}

func TestEvaluate_RepositoryAndRegistrySeparated(t *testing.T) {
	rules := []Rule{
		{Pattern: "**", Actions: []string{"pull"}, Access: "allow"},
	}
	if !Evaluate(rules, ResourceRepository, "actions/x", "pull") {
		t.Error("** must allow repository pull")
	}
	if Evaluate(rules, ResourceRegistry, CatalogName, "*") {
		t.Error("** must not grant registry:catalog:* (needs explicit catalog rule)")
	}

	rulesWithCatalog := []Rule{
		{Pattern: "**", Actions: []string{"pull"}, Access: "allow"},
		{Pattern: "catalog", Actions: []string{"*"}, Access: "allow"},
	}
	if !Evaluate(rulesWithCatalog, ResourceRegistry, CatalogName, "*") {
		t.Error("catalog rule must allow registry:catalog:*")
	}
	if Evaluate([]Rule{{Pattern: "catalog", Actions: []string{"*"}, Access: "allow"}},
		ResourceRepository, "catalog", "pull") {
		t.Error("catalog rule must not grant repository access")
	}
}

func TestEvaluate_CatalogWithoutActions(t *testing.T) {
	rules := []Rule{
		{Pattern: "catalog", Access: "allow"}, // actions omitted
	}
	if !Evaluate(rules, ResourceRegistry, CatalogName, "*") {
		t.Error("catalog rule without actions must allow registry:catalog:*")
	}

	rulesDeny := []Rule{
		{Pattern: "catalog", Access: "deny"},
	}
	if Evaluate(rulesDeny, ResourceRegistry, CatalogName, "*") {
		t.Error("catalog rule without actions with deny must deny registry:catalog:*")
	}
}

func TestGrantedActions(t *testing.T) {
	rules := []Rule{
		{Pattern: "actions/**", Actions: []string{"pull"}, Access: "allow"},
		{Pattern: "actions/secret/**", Actions: []string{"*"}, Access: "deny"},
	}
	got := GrantedActions(rules, ResourceRepository, "actions/public/x", []string{"pull", "push", "delete"})
	if len(got) != 1 || got[0] != "pull" {
		t.Errorf("GrantedActions = %v, want [pull]", got)
	}
	got = GrantedActions(rules, ResourceRepository, "actions/secret/x", []string{"pull", "push"})
	if len(got) != 0 {
		t.Errorf("GrantedActions for secret = %v, want empty", got)
	}
}

func TestValidateRule(t *testing.T) {
	valid := []Rule{
		{Pattern: "**", Actions: []string{"pull"}, Access: "allow"},
		{Pattern: "catalog", Actions: []string{"*"}, Access: "deny"},
		{Pattern: "catalog", Access: "allow"}, // actions omitted — valid for catalog
		{Pattern: "a/b", Actions: []string{"pull", "push", "delete"}, Access: "allow"},
	}
	for _, r := range valid {
		if err := ValidateRule(r); err != nil {
			t.Errorf("ValidateRule(%+v) unexpected error: %v", r, err)
		}
	}
	invalid := []Rule{
		{Pattern: "", Actions: []string{"pull"}, Access: "allow"},
		{Pattern: "**", Actions: nil, Access: "allow"}, // actions required for non-catalog
		{Pattern: "**", Actions: []string{"read"}, Access: "allow"},
		{Pattern: "**", Actions: []string{"pull"}, Access: "permit"},
	}
	for _, r := range invalid {
		if err := ValidateRule(r); err == nil {
			t.Errorf("ValidateRule(%+v) expected error, got nil", r)
		}
	}
}
