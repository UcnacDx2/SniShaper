package proxy

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

const tlineSOCKS5Env = "SNISHAPER_TLINE_SOCKS5"

func tlineSOCKS5Addr() string {
	return strings.TrimSpace(os.Getenv(tlineSOCKS5Env))
}

func isTCPNetwork(network string) bool {
	switch strings.ToLower(strings.TrimSpace(network)) {
	case "tcp", "tcp4", "tcp6":
		return true
	default:
		return false
	}
}

func dialViaSOCKS5(ctx context.Context, proxyAddr, targetAddr string) (net.Conn, error) {
	targetHost, targetPort, err := net.SplitHostPort(targetAddr)
	if err != nil {
		return nil, fmt.Errorf("invalid SOCKS5 target %q: %w", targetAddr, err)
	}

	port, err := strconv.Atoi(targetPort)
	if err != nil || port < 1 || port > 65535 {
		return nil, fmt.Errorf("invalid target port %q", targetPort)
	}

	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	conn, err := dialer.DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("dial T-Line SOCKS5 %s: %w", proxyAddr, err)
	}

	deadline := time.Now().Add(10 * time.Second)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(deadline) {
		deadline = ctxDeadline
	}
	_ = conn.SetDeadline(deadline)
	defer conn.SetDeadline(time.Time{})

	if err := writeAll(conn, []byte{0x05, 0x01, 0x00}); err != nil {
		conn.Close()
		return nil, fmt.Errorf("SOCKS5 greeting write: %w", err)
	}
	greeting := make([]byte, 2)
	if _, err := io.ReadFull(conn, greeting); err != nil {
		conn.Close()
		return nil, fmt.Errorf("SOCKS5 greeting read: %w", err)
	}
	if greeting[0] != 0x05 || greeting[1] != 0x00 {
		conn.Close()
		return nil, fmt.Errorf("T-Line SOCKS5 does not accept no-authentication (version=%d method=%d)", greeting[0], greeting[1])
	}

	request := make([]byte, 0, 4+1+255+2)
	request = append(request, 0x05, 0x01, 0x00)

	if ip := net.ParseIP(targetHost); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			request = append(request, 0x01)
			request = append(request, ip4...)
		} else if ip16 := ip.To16(); ip16 != nil {
			request = append(request, 0x04)
			request = append(request, ip16...)
		} else {
			conn.Close()
			return nil, fmt.Errorf("unsupported target IP %q", targetHost)
		}
	} else {
		if len(targetHost) == 0 || len(targetHost) > 255 {
			conn.Close()
			return nil, fmt.Errorf("invalid SOCKS5 domain %q", targetHost)
		}
		request = append(request, 0x03, byte(len(targetHost)))
		request = append(request, targetHost...)
	}
	request = append(request, byte(port>>8), byte(port))

	if err := writeAll(conn, request); err != nil {
		conn.Close()
		return nil, fmt.Errorf("SOCKS5 CONNECT write: %w", err)
	}

	var replyHeader [4]byte
	if _, err := io.ReadFull(conn, replyHeader[:]); err != nil {
		conn.Close()
		return nil, fmt.Errorf("SOCKS5 CONNECT reply: %w", err)
	}
	if replyHeader[0] != 0x05 {
		conn.Close()
		return nil, fmt.Errorf("invalid SOCKS5 reply version %d", replyHeader[0])
	}
	if replyHeader[1] != 0x00 {
		conn.Close()
		return nil, fmt.Errorf("T-Line SOCKS5 CONNECT %s failed: %s", targetAddr, socks5ReplyText(replyHeader[1]))
	}

	switch replyHeader[3] {
	case 0x01:
		buf := make([]byte, 6)
		if _, err := io.ReadFull(conn, buf); err != nil {
			conn.Close()
			return nil, fmt.Errorf("SOCKS5 IPv4 bind reply: %w", err)
		}
	case 0x03:
		var n [1]byte
		if _, err := io.ReadFull(conn, n[:]); err != nil {
			conn.Close()
			return nil, fmt.Errorf("SOCKS5 domain bind reply length: %w", err)
		}
		buf := make([]byte, int(n[0])+2)
		if _, err := io.ReadFull(conn, buf); err != nil {
			conn.Close()
			return nil, fmt.Errorf("SOCKS5 domain bind reply: %w", err)
		}
	case 0x04:
		buf := make([]byte, 18)
		if _, err := io.ReadFull(conn, buf); err != nil {
			conn.Close()
			return nil, fmt.Errorf("SOCKS5 IPv6 bind reply: %w", err)
		}
	default:
		conn.Close()
		return nil, fmt.Errorf("unsupported SOCKS5 reply address type %d", replyHeader[3])
	}

	return conn, nil
}

func writeAll(conn net.Conn, payload []byte) error {
	for len(payload) > 0 {
		n, err := conn.Write(payload)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		payload = payload[n:]
	}
	return nil
}

func socks5ReplyText(code byte) string {
	switch code {
	case 0x01:
		return "general SOCKS server failure"
	case 0x02:
		return "connection not allowed by ruleset"
	case 0x03:
		return "network unreachable"
	case 0x04:
		return "host unreachable"
	case 0x05:
		return "connection refused"
	case 0x06:
		return "TTL expired"
	case 0x07:
		return "command not supported"
	case 0x08:
		return "address type not supported"
	default:
		return fmt.Sprintf("reply code 0x%02x", code)
	}
}
