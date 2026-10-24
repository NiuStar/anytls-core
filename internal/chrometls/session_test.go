//go:build with_utls

package chrometls

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"testing"
	"time"
)

// These are backend observations against a Go loopback peer, not a Chrome
// comparison. The adapter deliberately has no ClientSessionCache by default.
func TestSequentialTLSRecordsAndNoDefaultResumption(t *testing.T) {
	certificate, caPEM := sessionTestCertificate(t)
	for _, version := range []uint16{tls.VersionTLS12, tls.VersionTLS13} {
		for _, explicitMinimum := range []bool{false, true} {
			t.Run(fmt.Sprintf("TLS%x/explicit_min12=%t", version, explicitMinimum), func(t *testing.T) {
				o := chromeOptions()
				o.ServerName = "session.example.test"
				o.Certificate = []string{string(caPEM)}
				if explicitMinimum {
					o.MinVersion = "1.2"
				}
				cfg, err := (Factory{}).NewChromeClient(context.Background(), o.ServerName, o)
				if err != nil {
					t.Fatal(err)
				}
				backend := cfg.(*clientConfig)
				if backend.config.InsecureSkipVerify || backend.config.RootCAs == nil {
					t.Fatal("fixture must exercise strict CA and hostname verification")
				}
				if backend.config.ClientSessionCache != nil || backend.config.SessionTicketsDisabled {
					t.Fatal("default policy changed: expected tickets enabled but no client session cache")
				}
				serverConfig := &tls.Config{
					Certificates:           []tls.Certificate{certificate},
					MinVersion:             version,
					MaxVersion:             version,
					SessionTicketsDisabled: false,
				}
				var ticketKey [32]byte
				if _, err := rand.Read(ticketKey[:]); err != nil {
					t.Fatal(err)
				}
				serverConfig.SetSessionTicketKeys([][32]byte{ticketKey})
				listener, err := net.Listen("tcp", "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				defer listener.Close()
				// Reuse the exact adapter and server configurations, with stable
				// ticket keys. Reading the echo also consumes post-handshake
				// NewSessionTicket messages before the next connection starts.
				for attempt := 0; attempt < 2; attempt++ {
					sessionTestExchange(t, listener, serverConfig, backend, version, attempt)
				}
				t.Log("cache_policy=none tickets_enabled=true sequential_connections=2; no browser-equivalence claim")
			})
		}
	}
}

func TestSessionVersionPolicyRejectsNarrowMinimum(t *testing.T) {
	o := chromeOptions()
	o.MinVersion = "1.3"
	if _, err := (Factory{}).NewChromeClient(context.Background(), "session.example.test", o); err == nil {
		t.Fatal("must reject unsupported narrow minimum rather than silently advertise TLS1.2")
	}
}

func sessionTestExchange(t *testing.T, listener net.Listener, serverConfig *tls.Config, cfg *clientConfig, version uint16, attempt int) {
	t.Helper()
	payload := bytes.Repeat([]byte{0x41, 0x00, 0xff, byte(attempt)}, 12*1024)
	type result struct {
		state tls.ConnectionState
		err   error
	}
	done := make(chan result, 1)
	go func() {
		var r result
		defer func() { done <- r }()
		raw, err := listener.Accept()
		if err != nil {
			r.err = err
			return
		}
		defer raw.Close()
		if err := raw.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
			r.err = err
			return
		}
		peer := tls.Server(raw, serverConfig)
		if err := peer.HandshakeContext(context.Background()); err != nil {
			r.err = err
			return
		}
		r.state = peer.ConnectionState()
		got := make([]byte, len(payload))
		if _, err := io.ReadFull(peer, got); err != nil {
			r.err = err
			return
		}
		if !bytes.Equal(got, payload) {
			r.err = fmt.Errorf("server payload mismatch")
			return
		}
		n, err := peer.Write(got)
		if err != nil {
			r.err = err
		} else if n != len(got) {
			r.err = io.ErrShortWrite
		}
	}()
	var raw net.Conn
	defer func() {
		if raw != nil {
			raw.Close()
		} else {
			// Unblock Accept on any dial failure before joining the worker.
			listener.Close()
		}
		select {
		case r := <-done:
			if r.err != nil {
				t.Errorf("server exchange: %v", r.err)
				return
			}
			if !r.state.HandshakeComplete || r.state.Version != version || r.state.ServerName != "session.example.test" || r.state.DidResume {
				t.Errorf("server state: complete=%t version=%x sni=%q did_resume=%t", r.state.HandshakeComplete, r.state.Version, r.state.ServerName, r.state.DidResume)
			}
			t.Logf("attempt=%d server_did_resume=%t version=%x", attempt+1, r.state.DidResume, r.state.Version)
		case <-time.After(4 * time.Second):
			t.Error("server worker did not join within deadline")
		}
	}()
	var err error
	raw, err = net.DialTimeout("tcp", listener.Addr().String(), 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := raw.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	records := &sessionRecordConn{Conn: raw}
	conn, err := cfg.Client(records)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := conn.HandshakeContext(ctx); err != nil {
		t.Fatal(err)
	}
	state := conn.ConnectionState()
	if !state.HandshakeComplete || state.Version != version || state.DidResume || state.ServerName != "session.example.test" || len(state.VerifiedChains) == 0 {
		t.Fatalf("client state: complete=%t version=%x did_resume=%t sni=%q verified_chains=%d", state.HandshakeComplete, state.Version, state.DidResume, state.ServerName, len(state.VerifiedChains))
	}
	handshakeRecords := len(records.records)
	if records.err != nil || records.remaining != 0 || records.headerBytes != 0 || handshakeRecords == 0 || records.records[0].kind != 22 {
		t.Fatalf("incomplete or invalid handshake record observation: %v", records.err)
	}
	n, err := conn.Write(payload)
	if err != nil || n != len(payload) {
		t.Fatalf("client payload write: n=%d err=%v", n, err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("client echo mismatch")
	}
	if records.err != nil || records.remaining != 0 || records.headerBytes != 0 {
		t.Fatalf("invalid application record observation: %v", records.err)
	}
	applicationRecords := records.records[handshakeRecords:]
	if len(applicationRecords) < 2 {
		t.Fatal("large payload did not produce multiple encrypted application records")
	}
	lengths := make([]int, len(applicationRecords))
	for i, record := range applicationRecords {
		lengths[i] = record.length
		// TLS1.3 ciphertext includes its inner content type and AEAD
		// overhead. This is a protocol bound, not a Chrome size oracle.
		limit := 16384 + 2048
		if version == tls.VersionTLS13 {
			limit = 16384 + 256
		}
		if record.kind != 23 || record.length <= 0 || record.length > limit {
			t.Errorf("invalid encrypted application record: type=%d length=%d limit=%d", record.kind, record.length, limit)
		}
	}
	t.Logf("attempt=%d client_did_resume=%t payload_bytes=%d handshake_record_metadata=%+v app_record_ciphertext_lengths=%v", attempt+1, state.DidResume, len(payload), records.records[:handshakeRecords], lengths)
}

// Keep only five header bytes and bounded type/length metadata. Ciphertext and
// application payloads are never retained by this wire observer. Stream parsing
// does not assume that a net.Conn.Write corresponds to a TLS record boundary.
type sessionRecordConn struct {
	net.Conn
	header      [5]byte
	headerBytes int
	remaining   int
	records     []sessionRecord
	err         error
}

type sessionRecord struct {
	kind   byte
	length int
}

func (c *sessionRecordConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	data := p[:n]
	for len(data) > 0 && c.err == nil {
		if c.remaining > 0 {
			count := min(c.remaining, len(data))
			c.remaining -= count
			data = data[count:]
			continue
		}
		count := min(5-c.headerBytes, len(data))
		copy(c.header[c.headerBytes:], data[:count])
		c.headerBytes += count
		data = data[count:]
		if c.headerBytes != 5 {
			continue
		}
		length := int(c.header[3])<<8 | int(c.header[4])
		if c.header[1] != 3 || c.header[0] < 20 || c.header[0] > 23 || length > 16384+2048 || len(c.records) >= 4096 {
			c.err = fmt.Errorf("invalid or excessive TLS record metadata")
			break
		}
		c.records = append(c.records, sessionRecord{kind: c.header[0], length: length})
		c.remaining = length
		c.headerBytes = 0
	}
	return n, err
}

func sessionTestCertificate(t *testing.T) (tls.Certificate, []byte) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "session test CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(2), DNSNames: []string{"session.example.test"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{leafDER}, PrivateKey: leafKey}, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
}
