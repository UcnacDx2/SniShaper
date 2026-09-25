package proxy

import (
	"context"
	"net"
	"testing"
)

func TestChinaMainlandIPClassification(t *testing.T) {
	tests := []struct {
		name string
		ip   string
		cn   bool
	}{
		{name: "mainland IPv4", ip: "1.2.4.8", cn: true},
		{name: "public foreign IPv4", ip: "8.8.8.8", cn: false},
		{name: "public reserved-test IPv4", ip: "203.0.113.10", cn: false},
	}
	for _, tt := range tests {
		got := isChinaMainlandIP(net.ParseIP(tt.ip))
		if got != tt.cn {
			t.Fatalf("%s: isChinaMainlandIP(%q)=%v, want %v", tt.name, tt.ip, got, tt.cn)
		}
	}
}

func TestLikelyChinaDomain(t *testing.T) {
	tests := []struct {
		host string
		want bool
	}{
		{"example.cn", true},
		{"www.example.com.cn", true},
		{"example.xn--fiqs8s", true},
		{"example.com", false},
	}
	for _, tt := range tests {
		if got := isLikelyChinaMainlandDomain(tt.host); got != tt.want {
			t.Fatalf("isLikelyChinaMainlandDomain(%q)=%v, want %v", tt.host, got, tt.want)
		}
	}
}

func TestDefaultRoutePolicy(t *testing.T) {
	rm := NewRuleManager("", "")
	rule := rm.matchRule("example.com", "direct")
	if rule.Mode != "transparent" || rule.Transport != "auto" || rule.FallbackMode != "tls-rf" {
		t.Fatalf("default rule=%+v, want transparent + auto + tls-rf", rule)
	}
}

func TestPrepareConnectMainlandPolicy(t *testing.T) {
	p := &ProxyServer{mode: "direct"}

	cnDomain := p.prepareConnect("www.example.cn", "203.0.113.10:443", Rule{
		Mode:         "transparent",
		Transport:    "auto",
		FallbackMode: "tls-rf",
	})
	if cnDomain.rule.Mode != "direct" || cnDomain.rule.Transport != "physical" || cnDomain.rule.FallbackMode != "" {
		t.Fatalf("CN domain rule=%+v, want direct + physical + no fallback", cnDomain.rule)
	}

	foreign := p.prepareConnect("example.com", "8.8.8.8:443", Rule{
		Mode:         "transparent",
		Transport:    "auto",
		FallbackMode: "tls-rf",
	})
	if foreign.rule.Mode != "transparent" || foreign.rule.Transport != "auto" || foreign.rule.FallbackMode != "tls-rf" {
		t.Fatalf("foreign rule=%+v, want transparent + auto + tls-rf", foreign.rule)
	}
}

func TestAutoDestinationLiteralIP(t *testing.T) {
	p := &ProxyServer{}
	if !p.isChinaMainlandDestination(context.Background(), "1.2.4.8:443") {
		t.Fatal("expected mainland IP to be direct")
	}
	if p.isChinaMainlandDestination(context.Background(), "8.8.8.8:443") {
		t.Fatal("expected foreign IP to use T-Line")
	}
}
