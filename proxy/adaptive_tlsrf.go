package proxy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"snishaper/pkg/tlsfrag"
)

const adaptiveTLSRFProbeTimeout = 8 * time.Second

type tlsHandshakeAlertError struct {
	Level       byte
	Description byte
}

func (e *tlsHandshakeAlertError) Error() string {
	return fmt.Sprintf("TLS alert level=%d description=%d", e.Level, e.Description)
}

func isPersistentTLSRFSignal(err error) bool {
	var alertErr *tlsHandshakeAlertError
	return errors.As(err, &alertErr) && alertErr.Description != 0 // close_notify is not a block signal
}


// handleAdaptiveTLSRF implements the default foreign HTTPS policy:
//  1. send the original ClientHello over the normal transport;
//  2. if the TLS response path fails, reconnect and resend the same ClientHello
//     with TLS-RF fragmentation;
//  3. keep the successful upstream connection and tunnel the rest transparently.
//
// Domestic targets are never upgraded to TLS-RF. For the automatic policy,
// .cn/Chinese-IDN domains are forced to physical transport in prepareConnect,
// while resolved mainland IPs are selected per candidate by Transport=auto.
func (p *ProxyServer) handleAdaptiveTLSRF(clientConn net.Conn, host, targetAddr string, rule Rule) {
	defer clientConn.Close()

	record, err := tlsfrag.ReadInitialTLSRecord(clientConn)
	if err != nil {
		p.tracef("[AutoRoute] Failed to read initial TLS record for %s: %v", host, err)
		return
	}

	if _, sniPos, sniLen, _, parseErr := tlsfrag.ParseClientHello(record); parseErr != nil || sniPos <= 0 || sniLen <= 0 {
		// Not a parseable ClientHello: no safe TLS-RF replay. Preserve the
		// original bytes and use the ordinary upstream path.
		p.tracef("[AutoRoute] No usable ClientHello/SNI for %s; ordinary tunnel", host)
		conn, dialErr := p.dialFirstCandidate(host, targetAddr, rule, nil)
		if dialErr != nil {
			p.tracef("[AutoRoute] Ordinary dial failed for %s: %v", host, dialErr)
			return
		}
		if err := writeFull(conn, record); err != nil {
			conn.Close()
			return
		}
		p.directTunnel(clientConn, conn)
		return
	}

	candidates := p.buildDialCandidates(
		context.Background(),
		host,
		ensureAddrWithPort(targetAddr, "443"),
		rule,
		"transparent",
	)
	if len(candidates) == 0 {
		candidates = []string{ensureAddrWithPort(targetAddr, "443")}
	}
	candidates = dedupeDialCandidates(candidates)

	// Ordinary path first. A persistent cache entry is created only when
	// the upstream has already accepted the TCP connection and then returns
	// an explicit TLS alert. DNS, TCP connect, SOCKS5, timeout, and EOF errors
	// are deliberately excluded because they are not reliable TLS-block signals.
	for _, candidate := range candidates {
		conn, dialErr := p.dialWithRule(context.Background(), "tcp", candidate, rule)
		if dialErr != nil {
			p.tracef("[AutoRoute] Ordinary dial failed host=%s addr=%s err=%v", host, candidate, dialErr)
			continue
		}

		// A mainland IP selected by Transport=auto must stay physical and must
		// not be subjected to TLS-RF fallback.
		if strings.EqualFold(rule.Transport, "auto") && p.isChinaMainlandDestination(context.Background(), candidate) {
			p.tracef("[AutoRoute] Mainland candidate %s -> physical direct", candidate)
			if err := writeFull(conn, record); err != nil {
				conn.Close()
				continue
			}
			p.directTunnel(clientConn, conn)
			return
		}

		response, probeErr := probeTLSResponse(conn, record)
		if probeErr == nil {
			p.tracef("[AutoRoute] Ordinary TLS succeeded host=%s addr=%s", host, candidate)
			p.directTunnel(clientConn, &bufferedReadConn{
				Conn:   conn,
				reader: io.MultiReader(bytes.NewReader(response), conn),
			})
			return
		}

		if isPersistentTLSRFSignal(probeErr) && p.rules != nil {
			// Persist only an explicit TLS Alert. Network-layer failures do not
			// poison the cache, and the cache has no automatic TTL.
			_ = p.rules.markTLSRF(host, probeErr.Error())
		}
		p.tracef("[AutoRoute] Ordinary TLS failed host=%s addr=%s: %v; trying TLS-RF", host, candidate, probeErr)
		conn.Close()
	}

	// TLS-RF retry on the same resolved candidates.
	for _, candidate := range candidates {
		conn, dialErr := p.dialWithRule(context.Background(), "tcp", candidate, rule)
		if dialErr != nil {
			p.tracef("[TLS-RF] Retry dial failed host=%s addr=%s err=%v", host, candidate, dialErr)
			continue
		}

		fragmented := append([]byte(nil), record...)
		if _, sniPos, sniLen, _, parseErr := tlsfrag.ParseClientHello(fragmented); parseErr != nil || sniPos <= 0 || sniLen <= 0 {
			conn.Close()
			continue
		} else if err := tlsfrag.SendRecords(
			conn,
			fragmented,
			sniPos,
			sniLen,
			tlsfrag.DefaultTLSRFNumRecords,
			tlsfrag.DefaultTLSRFNumSegments,
			tlsfrag.DefaultTLSRFOOB,
			tlsfrag.DefaultTLSRFOOBEx,
			tlsfrag.DefaultTLSRFModMinorVer,
			tlsfrag.DefaultTLSRFSendInterval,
		); err != nil {
			p.tracef("[TLS-RF] Fragmented ClientHello failed host=%s addr=%s err=%v", host, candidate, err)
			conn.Close()
			continue
		}

		response, probeErr := readTLSResponse(conn, adaptiveTLSRFProbeTimeout)
		if probeErr != nil {
			p.tracef("[TLS-RF] Probe failed host=%s addr=%s err=%v", host, candidate, probeErr)
			conn.Close()
			continue
		}

		p.tracef("[TLS-RF] Adaptive retry succeeded host=%s addr=%s", host, candidate)
		p.directTunnel(clientConn, &bufferedReadConn{
			Conn:   conn,
			reader: io.MultiReader(bytes.NewReader(response), conn),
		})
		return
	}

	p.tracef("[AutoRoute] Exhausted ordinary + TLS-RF attempts for %s", host)
}

func (p *ProxyServer) dialFirstCandidate(host, targetAddr string, rule Rule, tried map[string]struct{}) (net.Conn, error) {
	candidates := p.buildDialCandidates(
		context.Background(),
		host,
		ensureAddrWithPort(targetAddr, "443"),
		rule,
		"transparent",
	)
	if len(candidates) == 0 {
		candidates = []string{ensureAddrWithPort(targetAddr, "443")}
	}

	var lastErr error
	for _, candidate := range dedupeDialCandidates(candidates) {
		if tried != nil {
			if _, ok := tried[candidate]; ok {
				continue
			}
		}
		conn, err := p.dialWithRule(context.Background(), "tcp", candidate, rule)
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no dial candidates for %s", host)
	}
	return nil, lastErr
}

func probeTLSResponse(conn net.Conn, clientHello []byte) ([]byte, error) {
	if err := writeFull(conn, clientHello); err != nil {
		return nil, err
	}
	return readTLSResponse(conn, adaptiveTLSRFProbeTimeout)
}

func readTLSResponse(conn net.Conn, timeout time.Duration) ([]byte, error) {
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	defer conn.SetReadDeadline(time.Time{})

	var header [5]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return nil, err
	}

	contentType := header[0]
	length := int(header[3])<<8 | int(header[4])
	if length <= 0 || length > 18432 {
		return nil, fmt.Errorf("invalid TLS record length %d", length)
	}
	if contentType != 20 && contentType != 21 && contentType != 22 && contentType != 23 {
		return nil, fmt.Errorf("unexpected TLS record type %d", contentType)
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return nil, err
	}
	record := make([]byte, 0, 5+length)
	record = append(record, header[:]...)
	record = append(record, payload...)

	if contentType == 21 {
		level := byte(0)
		description := byte(0)
		if len(payload) >= 2 {
			level = payload[0]
			description = payload[1]
		}
		return nil, &tlsHandshakeAlertError{
			Level:       level,
			Description: description,
		}
	}
	return record, nil
}

func writeFull(conn net.Conn, data []byte) error {
	for len(data) > 0 {
		n, err := conn.Write(data)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrUnexpectedEOF
		}
		data = data[n:]
	}
	return nil
}
