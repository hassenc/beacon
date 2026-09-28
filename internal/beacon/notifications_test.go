package beacon

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

type smtpTestMode int

const (
	smtpTestSuccess smtpTestMode = iota
	smtpTestAuthFailure
	smtpTestDropDuringData
)

func startTestSTARTTLSServer(t *testing.T, mode smtpTestMode) (address string, certificate *x509.Certificate, messages <-chan string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	tlsCertificate := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	received := make(chan string, 1)
	t.Cleanup(func() { listener.Close() })
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		reader := bufio.NewReader(conn)
		write := func(line string) error {
			_, err := fmt.Fprintf(conn, "%s\r\n", line)
			return err
		}
		if err := write("220 test beacon smtp"); err != nil {
			return
		}
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				return
			}
			command := strings.ToUpper(strings.TrimSpace(line))
			switch {
			case strings.HasPrefix(command, "EHLO"), strings.HasPrefix(command, "HELO"):
				if err := write("250-test beacon"); err != nil {
					return
				}
				if err := write("250-STARTTLS"); err != nil {
					return
				}
				if err := write("250 AUTH PLAIN"); err != nil {
					return
				}
			case command == "STARTTLS":
				if err := write("220 ready for tls"); err != nil {
					return
				}
				tlsConn := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{tlsCertificate}})
				if err := tlsConn.Handshake(); err != nil {
					return
				}
				conn = tlsConn
				reader = bufio.NewReader(conn)
				write = func(line string) error {
					_, err := fmt.Fprintf(conn, "%s\r\n", line)
					return err
				}
			case strings.HasPrefix(command, "AUTH "):
				if mode == smtpTestAuthFailure {
					write("535 authentication failed")
					return
				}
				if err := write("235 authentication accepted"); err != nil {
					return
				}
			case strings.HasPrefix(command, "MAIL FROM:"):
				if err := write("250 sender accepted"); err != nil {
					return
				}
			case strings.HasPrefix(command, "RCPT TO:"):
				if err := write("250 recipient accepted"); err != nil {
					return
				}
			case command == "DATA":
				if mode == smtpTestDropDuringData {
					return
				}
				if err := write("354 send data"); err != nil {
					return
				}
				var data strings.Builder
				for {
					line, err := reader.ReadString('\n')
					if err != nil {
						return
					}
					if strings.TrimRight(line, "\r\n") == "." {
						break
					}
					data.WriteString(line)
				}
				received <- data.String()
				if err := write("250 message accepted"); err != nil {
					return
				}
			case command == "QUIT":
				write("221 goodbye")
				return
			}
		}
	}()
	return listener.Addr().String(), certificate, received
}

func TestSMTPStartTLSDeliveryAndFailureModes(t *testing.T) {
	tests := []struct {
		name       string
		mode       smtpTestMode
		rootCAs    bool
		username   string
		wantErr    bool
		wantSecret bool
	}{
		{name: "success", mode: smtpTestSuccess, rootCAs: true, wantSecret: true},
		{name: "certificate rejection", mode: smtpTestSuccess, wantErr: true},
		{name: "authentication failure", mode: smtpTestAuthFailure, rootCAs: true, username: "operator", wantErr: true},
		{name: "disconnect during data", mode: smtpTestDropDuringData, rootCAs: true, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			address, certificate, messages := startTestSTARTTLSServer(t, tt.mode)
			config := SMTPConfig{Address: address, From: "beacon@example.test", Username: tt.username, Password: "wrong-password"}
			if tt.rootCAs {
				pool := x509.NewCertPool()
				pool.AddCert(certificate)
				config.TLSRootCAs = pool
			}
			err := config.Send(context.Background(), "operator@example.test", "message-id", "Beacon update", "sentinel report body")
			if tt.wantErr && err == nil {
				t.Fatal("expected SMTP failure")
			}
			if !tt.wantErr && err != nil {
				t.Fatal(err)
			}
			if tt.wantSecret {
				select {
				case message := <-messages:
					if !strings.Contains(message, "sentinel report body") {
						t.Fatal("successful SMTP server did not receive the message")
					}
				case <-time.After(5 * time.Second):
					t.Fatal("timed out waiting for the SMTP message")
				}
			}
		})
	}
}

func TestSMTPRejectsInvalidConfiguration(t *testing.T) {
	err := (SMTPConfig{Address: "127.0.0.1:1", From: "not-an-email"}).Send(context.Background(), "operator@example.test", "id", "subject", "body")
	if err == nil || !strings.Contains(err.Error(), "SMTP sender") {
		t.Fatalf("invalid SMTP configuration returned %v", err)
	}
}
