package ginacl

import "testing"

func Test_SimpleRule(t *testing.T) {
	rs := RuleSet{
		"/api/": []Rule{
			{
				Targets: []string{"bad"},
				Action:  "DENY",
			},
			{
				Targets: []string{"good"},
				Action:  "ALLOW",
			},
		},
		"*": []Rule{
			{
				Targets: []string{},
				Action:  "DENY",
			},
		},
	}

	t.Log(`rs.ParseACL("/api/xyz", "bad")`)
	if rs.ParseACL("/api/xyz", []string{"bad"}) {
		t.Error("/api/xyz for bad == TRUE")
	}
	t.Log(`rs.ParseACL("/api/xyz", "good")`)
	if rs.ParseACL("/api/xyz", []string{"good"}) {
		t.Error("/api/xyz for good == FALSE")
	}
	t.Log(`rs.ParseACL("/something/else", "good")`)
	if rs.ParseACL("/something/else", []string{"good"}) {
		t.Error("fallthrough == TRUE")
	}
	t.Log(`rs.ParseACL("*", "good")`)
	if rs.ParseACL("*", []string{"good"}) {
		t.Error("fallthrough == TRUE")
	}
}
