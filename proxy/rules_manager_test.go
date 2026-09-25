package proxy

import "testing"

func TestBuildRulesPreservesFallbackMode(t *testing.T) {
	rm := NewRuleManager("", "")
	rm.siteGroups = []SiteGroup{
		{
			ID:           "youtube",
			Name:         "youtube",
			Mode:         "transparent",
			Transport:    "tline",
			FallbackMode: "tls-rf",
			Domains:      []string{"ggpht.com"},
			Enabled:      true,
		},
	}

	rm.buildRules()

	if len(rm.rules) != 1 {
		t.Fatalf("rules=%d, want 1", len(rm.rules))
	}

	rule := rm.rules[0]
	if rule.Transport != "tline" {
		t.Fatalf("Transport=%q, want tline", rule.Transport)
	}
	if rule.FallbackMode != "tls-rf" {
		t.Fatalf("FallbackMode=%q, want tls-rf", rule.FallbackMode)
	}
}
