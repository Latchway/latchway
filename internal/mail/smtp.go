// Package mail sends the few plain-text emails the control plane needs, such
// as administrator invitations, through an operator-configured SMTP relay.
package mail

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"mime"
	"mime/quotedprintable"
	"net"
	netmail "net/mail"
	"net/smtp"
	"strconv"
	"strings"
	"time"
)

// TLSMode is how the connection to the relay is protected.
type TLSMode string

const (
	// TLSStartTLS upgrades a plain connection and refuses relays that can't.
	TLSStartTLS TLSMode = "starttls"
	// TLSImplicit connects with TLS from the start, usually on port 465.
	TLSImplicit TLSMode = "implicit"
	// TLSNone is accepted only for a relay on the loopback interface.
	TLSNone TLSMode = "none"
)

// Config is the relay. The password is a secret and is never logged.
type Config struct {
	Host     string
	Port     int
	Username string
	Password string
	From     string
	TLS      TLSMode
}

// Message is one plain-text email to one recipient.
type Message struct {
	To      string
	Subject string
	Body    string
}

// Sender delivers messages.
type Sender interface {
	Send(ctx context.Context, message Message) error
}

// IsLoopbackHost reports whether host names the local machine.
func IsLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// Validate checks a relay configuration without connecting.
func (config Config) Validate() error {
	if config.Host == "" || strings.ContainsAny(config.Host, " /\r\n") {
		return errors.New("SMTP host is required")
	}
	if config.Port < 1 || config.Port > 65535 {
		return errors.New("SMTP port must be between 1 and 65535")
	}
	if _, err := netmail.ParseAddress(config.From); err != nil {
		return errors.New("SMTP from address must be an email address, optionally with a name")
	}
	switch config.TLS {
	case TLSStartTLS, TLSImplicit:
	case TLSNone:
		if !IsLoopbackHost(config.Host) {
			return errors.New("SMTP without TLS is allowed only for a relay on localhost")
		}
	default:
		return errors.New("SMTP TLS mode must be starttls, implicit or none")
	}
	if (config.Username == "") != (config.Password == "") {
		return errors.New("SMTP username and password must be set together")
	}
	return nil
}

// SMTPSender delivers through one relay.
type SMTPSender struct {
	config Config
	from   *netmail.Address
}

// NewSMTPSender validates config and returns a sender.
func NewSMTPSender(config Config) (*SMTPSender, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}
	from, _ := netmail.ParseAddress(config.From)
	return &SMTPSender{config: config, from: from}, nil
}

// Send delivers one message, failing within 30 seconds.
func (sender *SMTPSender) Send(ctx context.Context, message Message) error {
	to, err := netmail.ParseAddress(message.To)
	if err != nil || strings.ContainsAny(message.Subject, "\r\n") || len(message.Subject) > 200 || len(message.Body) > 64<<10 {
		return errors.New("email message is invalid")
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	address := net.JoinHostPort(sender.config.Host, strconv.Itoa(sender.config.Port))
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return fmt.Errorf("connect to SMTP relay: %w", err)
	}
	defer conn.Close()
	deadline, _ := ctx.Deadline()
	if err := conn.SetDeadline(deadline); err != nil {
		return fmt.Errorf("set SMTP deadline: %w", err)
	}
	tlsConfig := &tls.Config{ServerName: sender.config.Host, MinVersion: tls.VersionTLS12}
	if sender.config.TLS == TLSImplicit {
		secured := tls.Client(conn, tlsConfig)
		if err := secured.HandshakeContext(ctx); err != nil {
			return fmt.Errorf("SMTP TLS handshake: %w", err)
		}
		conn = secured
	}
	client, err := smtp.NewClient(conn, sender.config.Host)
	if err != nil {
		return fmt.Errorf("SMTP greeting: %w", err)
	}
	defer client.Close()
	if err := client.Hello(heloName(sender.from.Address)); err != nil {
		return fmt.Errorf("SMTP EHLO: %w", err)
	}
	if sender.config.TLS == TLSStartTLS {
		if ok, _ := client.Extension("STARTTLS"); !ok {
			return errors.New("the SMTP relay doesn't offer STARTTLS")
		}
		if err := client.StartTLS(tlsConfig); err != nil {
			return fmt.Errorf("SMTP STARTTLS: %w", err)
		}
	}
	if sender.config.Username != "" {
		if err := client.Auth(smtp.PlainAuth("", sender.config.Username, sender.config.Password, sender.config.Host)); err != nil {
			return errors.New("SMTP authentication failed")
		}
	}
	if err := client.Mail(sender.from.Address); err != nil {
		return fmt.Errorf("SMTP MAIL FROM: %w", err)
	}
	if err := client.Rcpt(to.Address); err != nil {
		return fmt.Errorf("SMTP RCPT TO: %w", err)
	}
	writer, err := client.Data()
	if err != nil {
		return fmt.Errorf("SMTP DATA: %w", err)
	}
	encoded, err := compose(sender.from, to, message, time.Now())
	if err != nil {
		return err
	}
	if _, err := writer.Write(encoded); err != nil {
		return fmt.Errorf("SMTP message: %w", err)
	}
	if err := writer.Close(); err != nil {
		return fmt.Errorf("SMTP message accepted: %w", err)
	}
	return client.Quit()
}

func heloName(from string) string {
	if at := strings.LastIndex(from, "@"); at >= 0 && at < len(from)-1 {
		return from[at+1:]
	}
	return "localhost"
}

// compose renders headers and a quoted-printable UTF-8 body.
func compose(from, to *netmail.Address, message Message, now time.Time) ([]byte, error) {
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return nil, err
	}
	var buffer bytes.Buffer
	headers := [][2]string{
		{"From", from.String()},
		{"To", to.String()},
		{"Subject", mime.QEncoding.Encode("utf-8", message.Subject)},
		{"Date", now.UTC().Format(time.RFC1123Z)},
		{"Message-ID", "<" + hex.EncodeToString(id) + "@" + heloName(from.Address) + ">"},
		{"Auto-Submitted", "auto-generated"},
		{"MIME-Version", "1.0"},
		{"Content-Type", "text/plain; charset=UTF-8"},
		{"Content-Transfer-Encoding", "quoted-printable"},
	}
	for _, header := range headers {
		buffer.WriteString(header[0] + ": " + header[1] + "\r\n")
	}
	buffer.WriteString("\r\n")
	body := quotedprintable.NewWriter(&buffer)
	if _, err := body.Write([]byte(strings.ReplaceAll(message.Body, "\n", "\r\n"))); err != nil {
		return nil, err
	}
	if err := body.Close(); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}
