package tools

import "testing"

func TestParseScope(t *testing.T) {
	cases := []struct {
		in      string
		want    []Scope
		wantErr bool
	}{
		{"", nil, false},
		{"repository:actions/project:pull", []Scope{{"repository", "actions/project", []string{"pull"}}}, false},
		{"repository:actions/project:pull,push", []Scope{{"repository", "actions/project", []string{"pull", "push"}}}, false},
		{"registry:catalog:*", []Scope{{"registry", "catalog", []string{"*"}}}, false},
		{"repository:a:pull repository:b:push", []Scope{
			{"repository", "a", []string{"pull"}},
			{"repository", "b", []string{"push"}},
		}, false},
		{"bad", nil, true},
		{"repository:a", nil, true},
	}
	for _, c := range cases {
		got, err := ParseScope(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("ParseScope(%q) expected error", c.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseScope(%q) unexpected error: %v", c.in, err)
			continue
		}
		if len(got) != len(c.want) {
			t.Errorf("ParseScope(%q) len = %d, want %d", c.in, len(got), len(c.want))
			continue
		}
		for i := range got {
			if got[i].Type != c.want[i].Type || got[i].Name != c.want[i].Name {
				t.Errorf("ParseScope(%q)[%d] = %+v, want %+v", c.in, i, got[i], c.want[i])
			}
			if len(got[i].Actions) != len(c.want[i].Actions) {
				t.Errorf("ParseScope(%q)[%d].Actions = %v, want %v", c.in, i, got[i].Actions, c.want[i].Actions)
			}
		}
	}
}

func TestIsKnownType(t *testing.T) {
	if !IsKnownType("repository") || !IsKnownType("registry") {
		t.Error("repository and registry must be known")
	}
	if IsKnownType("unknown") {
		t.Error("unknown must not be known")
	}
}
