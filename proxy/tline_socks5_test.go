package proxy

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestTLineSOCKS5OutboundLoop(t *testing.T) {
	targetLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer targetLn.Close()

	targetAddr := targetLn.Addr().String()
	targetDone := make(chan struct{})
	go func() {
		defer close(targetDone)
		conn, err := targetLn.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		buf := make([]byte, 64)
		n, err := conn.Read(buf)
		if err == nil && n > 0 {
			_, _ = conn.Write([]byte("TARGET_OK:" + string(buf[:n])))
		}
	}()

	socksLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer socksLn.Close()

	var mu sync.Mutex
	var seenTarget string
	socksDone := make(chan struct{})
	go func() {
		defer close(socksDone)
		conn, err := socksLn.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		br := bufio.NewReader(conn)
		greeting := make([]byte, 3)
		if _, err := io.ReadFull(br, greeting); err != nil {
			return
		}
		if greeting[0] != 0x05 || greeting[1] != 0x01 || greeting[2] != 0x00 {
			return
		}
		_, _ = conn.Write([]byte{0x05, 0x00})

		header := make([]byte, 4)
		if _, err := io.ReadFull(br, header); err != nil {
			return
		}
		if header[0] != 0x05 || header[1] != 0x01 || header[2] != 0x00 {
			return
		}

		var host string
		switch header[3] {
		case 0x01:
			b := make([]byte, 4)
			if _, err := io.ReadFull(br, b); err != nil {
				return
			}
			host = net.IP(b).String()
		case 0x03:
			n, err := br.ReadByte()
			if err != nil {
				return
			}
			b := make([]byte, int(n))
			if _, err := io.ReadFull(br, b); err != nil {
				return
			}
			host = string(b)
		case 0x04:
			b := make([]byte, 16)
			if _, err := io.ReadFull(br, b); err != nil {
				return
			}
			host = net.IP(b).String()
		default:
			return
		}

		portBytes := make([]byte, 2)
		if _, err := io.ReadFull(br, portBytes); err != nil {
			return
		}
		port := int(portBytes[0])<<8 | int(portBytes[1])
		requested := net.JoinHostPort(host, fmt.Sprintf("%d", port))
		mu.Lock()
		seenTarget = requested
		mu.Unlock()

		upstream, err := net.DialTimeout("tcp", requested, 3*time.Second)
		if err != nil {
			_, _ = conn.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
			return
		}
		defer upstream.Close()

		local := upstream.LocalAddr().(*net.TCPAddr)
		ip4 := local.IP.To4()
		if ip4 == nil {
			ip4 = net.IPv4(127, 0, 0, 1).To4()
		}
		reply := []byte{0x05, 0x00, 0x00, 0x01, ip4[0], ip4[1], ip4[2], ip4[3], byte(local.Port >> 8), byte(local.Port)}
		if _, err := conn.Write(reply); err != nil {
			return
		}

		errCh := make(chan error, 2)
		go func() { _, err := io.Copy(upstream, br); errCh <- err }()
		go func() { _, err := io.Copy(conn, upstream); errCh <- err }()
		<-errCh
	}()

	t.Setenv(tlineSOCKS5Env, socksLn.Addr().String())

	p := NewProxyServer("127.0.0.1:0")
	conn, err := p.dialWithRule(context.Background(), "tcp", targetAddr, Rule{Mode: "tls-rf"})
	if err != nil {
		t.Fatalf("SniShaper -> T-Line SOCKS5 dial failed: %v", err)
	}
	defer conn.Close()

	payload := "hello-from-snishaper"
	if _, err := io.WriteString(conn, payload); err != nil {
		t.Fatal(err)
	}

	resp, err := io.ReadAll(io.LimitReader(conn, 64))
	if err != nil {
		t.Fatal(err)
	}
	want := "TARGET_OK:" + payload
	if string(resp) != want {
		t.Fatalf("unexpected target response: got %q want %q", string(resp), want)
	}

	mu.Lock()
	gotTarget := seenTarget
	mu.Unlock()
	if gotTarget != targetAddr {
		t.Fatalf("T-Line SOCKS5 received target %q, want %q", gotTarget, targetAddr)
	}

	select {
	case <-targetDone:
	case <-time.After(3 * time.Second):
		t.Fatal("target server did not finish")
	}
	select {
	case <-socksDone:
	case <-time.After(3 * time.Second):
		t.Fatal("SOCKS5 server did not finish")
	}
}

func TestTLineSOCKS5DisabledUsesDirectDial(t *testing.T) {
	if strings.TrimSpace(os.Getenv(tlineSOCKS5Env)) != "" {
		t.Skip("environment already enables T-Line SOCKS5")
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = conn.Write([]byte("DIRECT_OK"))
	}()

	p := NewProxyServer("127.0.0.1:1")
	conn, err := p.dialWithRule(context.Background(), "tcp", ln.Addr().String(), Rule{})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	buf := make([]byte, 16)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "DIRECT_OK" {
		t.Fatalf("unexpected direct response %q", string(buf[:n]))
	}

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("direct target did not finish")
	}
}

func TestTLineFiltersIPv6Candidates(t *testing.T) {
	t.Setenv(tlineSOCKS5Env, "127.0.0.1:10809")

	p := NewProxyServer("127.0.0.1:0")
	candidates := []string{
		"[2404:6800:4012:40b::4]:443",
		"142.251.80.52:443",
		"[2001:db8::1]:443",
	}

	got := p.filterTLineDialCandidates(candidates)
	want := []string{"142.251.80.52:443"}
	if len(got) != len(want) || got[0] != want[0] {
		t.Fatalf("unexpected filtered candidates: got %v want %v", got, want)
	}
}

func TestTLineKeepsIPv6CandidatesWhenDisabled(t *testing.T) {
	t.Setenv(tlineSOCKS5Env, "")

	p := NewProxyServer("127.0.0.1:0")
	candidates := []string{
		"[2404:6800:4012:40b::4]:443",
		"142.251.80.52:443",
	}

	got := p.filterTLineDialCandidates(candidates)
	if len(got) != len(candidates) || got[0] != candidates[0] || got[1] != candidates[1] {
		t.Fatalf("T-Line disabled should preserve candidates: got %v want %v", got, candidates)
	}
}
