package proxy

import (
	_ "embed"
	"net"
	"strings"
	"sync"
)

// cnIPData is a generated CIDR snapshot of China mainland IPv4/IPv6 space.
// Source: carrnot/china-ip-list release/ip.txt (aggregated from public operator/IP data).
// Keep this file bundled so routing remains deterministic even when GitHub/raw
// endpoints are unreachable at runtime.
//
//go:embed data/cn_ip.txt
var cnIPData string

var (
	cnIPNetsOnce sync.Once
	cnIPNets     []*net.IPNet
)

func initChinaMainlandIPNets() {
	cnIPNetsOnce.Do(func() {
		for _, line := range strings.Split(cnIPData, "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			_, network, err := net.ParseCIDR(line)
			if err == nil && network != nil {
				cnIPNets = append(cnIPNets, network)
			}
		}
	})
}

func isChinaMainlandIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	initChinaMainlandIPNets()
	for _, network := range cnIPNets {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

func isPrivateOrLocalIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	return ip.IsPrivate() ||
		ip.IsLoopback() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsUnspecified() ||
		ip.IsInterfaceLocalMulticast()
}

func isLikelyChinaMainlandDomain(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if host == "" {
		return false
	}

	// Common mainland Chinese ccTLD/IDN suffixes. The IP classifier remains
	// authoritative for .com/.net/.org domains hosted inside mainland China.
	for _, suffix := range []string{
		".cn",
		".xn--fiqs8s", // 中国
		".xn--55qx5d", // 公司
		".xn--io0a7i", // 网络
	} {
		if strings.HasSuffix(host, suffix) || host == strings.TrimPrefix(suffix, ".") {
			return true
		}
	}
	return false
}
