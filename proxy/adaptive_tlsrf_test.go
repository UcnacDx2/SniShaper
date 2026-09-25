package proxy

import (
	"crypto/x509"
	"encoding/pem"
	"net/http/httptest"
	"testing"
)

const ysnetRootPEM = `-----BEGIN CERTIFICATE-----
MIIDazCCAlOgAwIBAgIUV2YAGu7rvWZHa25mDwcG/8MvEn0wDQYJKoZIhvcNAQEL
BQAwRTELMAkGA1UEBhMCQ04xEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM
GFlzbmV0IFRydXN0IFNlcnZpY2VzIExMQzAeFw0yMzA1MTcwODIxMzJaFw0zMzA1
MTQwODIxMzJaMEUxCzAJBgNVBAYTAkNOMRMwEQYDVQQIDApTb21lLVN0YXRlMSEw
HwYDVQQKDBhZc25ldCBUcnVzdCBTZXJ2aWNlcyBMTEMwggEiMA0GCSqGSIb3DQEB
AQUAA4IBDwAwggEKAoIBAQCpNbYB124g5GvRiuJeM/WWiVBrM7dEIhbD65Pr1kuu
BwYk38Jf7P35qUlJ72V4ysKR4SzEFcpyBGFo+V/DyLzN/0yPoKqp2oP2GrMc3x8H
bsNE9GaWwJh54jolQ7Vi2po0TwIpvKI4m05QEQTMw14OgIQUwGEMDJoxy7AwyMlb
I15YnZ26o5A8bRfONOtu3qPY7Fkrh1V2M3SMLLoC0n60rkVPw4tL8OfNs8pt1noQ
v0hvRGSUtSocXuxAuqdTM+RAxRX5Mz2ZKVCoO4uXiyK8k4ncAHCmUOcqXweqdk/9
+zDKAhARkh6rwjVTW3iyPXipfbkH3vQMdGvqiO7F3eIRAgMBAAGjUzBRMB0GA1Ud
DgQWBBTyDsveqxgmGmQ/Dm0TgtfruMhUFzAfBgNVHSMEGDAWgBTyDsveqxgmGmQ/
Dm0TgtfruMhUFzAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQCf
3kXtNLL3oz5aE+B12+YY94dfYLLP8IgAcj0in39+hd6U9ruuw0K5cc8hE+rWLgoV
figIT2StRcDfRpknnNHgAMxsiopBwrSCSQJLx/767xteFJK5+MbqfojW/FnTAgRK
nGfW3rLBCpaMC5ql9M9DZ/S/pZqSDhrLvii95f4EdnUfAHu7keddCMtJpZUo2vJQ
0xgOWjNVI24A4uvI0R6mmelw/GdlCdXG0IqvUE97A7WgkS4iKTCjNK8OysWHCwPH
huG3F+gjPnh1WEgjucdNlvtD7A/4Am9EEdnb0n2R2QOGFz1mkQjTeh6ReaFbVfKH
pu+A3TGUO/u/yZ/DhyLU
-----END CERTIFICATE-----`

func TestKnownTLSRFInterceptionRoot(t *testing.T) {
	block, _ := pem.Decode([]byte(ysnetRootPEM))
	if block == nil {
		t.Fatal("failed to decode embedded Ysnet root")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	if !isKnownTLSRFInterceptionRoot(cert) {
		t.Fatalf("Ysnet root fingerprint was not recognized")
	}
}

func TestProbeTLSCertificateRejectsUntrustedLeaf(t *testing.T) {
	server := httptest.NewTLSServer(nil)
	defer server.Close()

	p := &ProxyServer{}
	result, err := p.probeTLSCertificate("localhost", server.Listener.Addr().String(), Rule{Transport: "physical"})
	if err != nil {
		t.Fatalf("probeTLSCertificate: %v", err)
	}
	if !result.suspicious {
		t.Fatalf("expected self-signed test certificate to be suspicious, reason=%q", result.reason)
	}
}
