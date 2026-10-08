package mail

import (
	"bufio"
	"context"
	"encoding/base64"
	"io"
	"mime/quotedprintable"
	"net"
	"strings"
	"sync"
	"testing"
)

// relay is a minimal plaintext SMTP server on loopback that records one message.
type relay struct {
	listener net.Listener
	mu       sync.Mutex
	commands []string
	data     string
	auth     string
}

func startRelay(t *testing.T) *relay {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := &relay{listener: listener}
	t.Cleanup(func() { _ = listener.Close() })
	go server.serve()
	return server
}

func (server *relay) port() int {
	return server.listener.Addr().(*net.TCPAddr).Port
}

func (server *relay) serve() {
	conn, err := server.listener.Accept()
	if err != nil {
		return
	}
	defer conn.Close()
	reader := bufio.NewReader(conn)
	write := func(line string) { _, _ = conn.Write([]byte(line + "\r\n")) }
	write("220 relay.test ESMTP")
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		server.mu.Lock()
		server.commands = append(server.commands, strings.SplitN(line, " ", 2)[0])
		server.mu.Unlock()
		switch {
		case strings.HasPrefix(line, "EHLO"):
			write("250-relay.test")
			write("250 AUTH PLAIN")
		case strings.HasPrefix(line, "AUTH PLAIN"):
			server.mu.Lock()
			server.auth = strings.TrimPrefix(line, "AUTH PLAIN ")
			server.mu.Unlock()
			write("235 2.7.0 accepted")
		case strings.HasPrefix(line, "MAIL FROM"), strings.HasPrefix(line, "RCPT TO"):
			write("250 ok")
		case line == "DATA":
			write("354 go ahead")
			var data strings.Builder
			for {
				part, err := reader.ReadString('\n')
				if err != nil {
					return
				}
				if part == ".\r\n" {
					break
				}
				data.WriteString(part)
			}
			server.mu.Lock()
			server.data = data.String()
			server.mu.Unlock()
			write("250 queued")
		case line == "QUIT":
			write("221 bye")
			return
		default:
			write("502 unknown")
		}
	}
}

func TestSendsAPlainTextMessageThroughALoopbackRelay(t *testing.T) {
	server := startRelay(t)
	sender, err := NewSMTPSender(Config{Host: "127.0.0.1", Port: server.port(), Username: "relay-user", Password: "test-only-relay-password", From: "Latchway <noreply@example.test>", TLS: TLSNone})
	if err != nil {
		t.Fatal(err)
	}
	if err := sender.Send(context.Background(), Message{To: "Ada <ada@example.test>", Subject: "You're invited to Acmé", Body: "Join here:\nhttps://console.example.test/invitation#token\n"}); err != nil {
		t.Fatal(err)
	}
	server.mu.Lock()
	defer server.mu.Unlock()
	if strings.Join(server.commands, " ") != "EHLO AUTH MAIL RCPT DATA QUIT" {
		t.Fatalf("commands=%v", server.commands)
	}
	decoded, err := base64.StdEncoding.DecodeString(server.auth)
	if err != nil || string(decoded) != "\x00relay-user\x00test-only-relay-password" {
		t.Fatalf("auth=%q", decoded)
	}
	for _, header := range []string{"From: \"Latchway\" <noreply@example.test>\r\n", "To: \"Ada\" <ada@example.test>\r\n", "Subject: =?utf-8?q?You're_invited_to_Acm=C3=A9?=\r\n", "Content-Type: text/plain; charset=UTF-8\r\n", "Auto-Submitted: auto-generated\r\n"} {
		if !strings.Contains(server.data, header) {
			t.Fatalf("missing %q in\n%s", header, server.data)
		}
	}
	body := server.data[strings.Index(server.data, "\r\n\r\n")+4:]
	plain, err := io.ReadAll(quotedprintable.NewReader(strings.NewReader(body)))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(plain), "https://console.example.test/invitation#token") {
		t.Fatalf("body=%q", plain)
	}
}

func TestConfigurationRefusesUnsafeRelays(t *testing.T) {
	for name, config := range map[string]Config{
		"plaintext remote": {Host: "smtp.example.test", Port: 25, From: "noreply@example.test", TLS: TLSNone},
		"bad from":         {Host: "smtp.example.test", Port: 587, From: "not an address", TLS: TLSStartTLS},
		"half credentials": {Host: "smtp.example.test", Port: 587, From: "noreply@example.test", TLS: TLSStartTLS, Username: "user"},
		"unknown mode":     {Host: "smtp.example.test", Port: 587, From: "noreply@example.test", TLS: "opportunistic"},
		"bad port":         {Host: "smtp.example.test", Port: 0, From: "noreply@example.test", TLS: TLSStartTLS},
	} {
		if err := config.Validate(); err == nil {
			t.Fatalf("%s: accepted %+v", name, config)
		}
	}
	if err := (Config{Host: "localhost", Port: 1025, From: "noreply@example.test", TLS: TLSNone}).Validate(); err != nil {
		t.Fatalf("loopback relay refused: %v", err)
	}
}

func TestStartTLSIsRequiredWhenConfigured(t *testing.T) {
	server := startRelay(t)
	sender, err := NewSMTPSender(Config{Host: "127.0.0.1", Port: server.port(), From: "noreply@example.test", TLS: TLSStartTLS})
	if err != nil {
		t.Fatal(err)
	}
	if err := sender.Send(context.Background(), Message{To: "ada@example.test", Subject: "x", Body: "y"}); err == nil || !strings.Contains(err.Error(), "STARTTLS") {
		t.Fatalf("err=%v", err)
	}
}

func TestMessagesCantInjectHeaders(t *testing.T) {
	sender, err := NewSMTPSender(Config{Host: "127.0.0.1", Port: 1, From: "noreply@example.test", TLS: TLSNone})
	if err != nil {
		t.Fatal(err)
	}
	for _, message := range []Message{
		{To: "ada@example.test\r\nBcc: eve@example.test", Subject: "x", Body: "y"},
		{To: "ada@example.test", Subject: "x\r\nBcc: eve@example.test", Body: "y"},
	} {
		if err := sender.Send(context.Background(), message); err == nil || err.Error() != "email message is invalid" {
			t.Fatalf("message %+v err=%v", message, err)
		}
	}
}
