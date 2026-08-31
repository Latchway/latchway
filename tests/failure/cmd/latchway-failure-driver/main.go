// latchway-failure-driver owns application-specific traffic and database
// assertions for the six destructive release scenarios. Its daemon retains
// in-flight requests and PostgreSQL locks between bounded controller phases.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "failure driver operation failed")
		os.Exit(1)
	}
}

func run(arguments []string) error {
	if len(arguments) == 1 && arguments[0] == "serve" {
		return serve()
	}
	if len(arguments) == 2 && arguments[0] == "probe" {
		return probe(arguments[1])
	}
	if len(arguments) != 2 {
		return errors.New("failure driver requires serve, probe URL, or PHASE SCENARIO")
	}
	if _, ok := scenarioAssertions[arguments[1]]; !ok {
		return errors.New("failure driver scenario is invalid")
	}
	if _, err := phaseMarker(arguments[0]); err != nil {
		return err
	}
	return requestPhase(arguments[0], arguments[1])
}

func serve() error {
	if _, err := os.Lstat(driverSocket); !errors.Is(err, os.ErrNotExist) {
		return errors.New("failure driver socket path is not empty")
	}
	listener, err := net.Listen("unix", driverSocket)
	if err != nil {
		return errors.New("create failure driver socket")
	}
	defer func() { _ = listener.Close() }()
	if err := os.Chmod(driverSocket, 0o600); err != nil {
		return errors.New("protect failure driver socket")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	driver, err := newDriver(ctx)
	if err != nil {
		return err
	}
	defer driver.close()
	server := &http.Server{
		Handler: http.HandlerFunc(driver.servePhase), ReadHeaderTimeout: 2 * time.Second,
		ReadTimeout: 10 * time.Minute, WriteTimeout: 10 * time.Minute,
		IdleTimeout: 10 * time.Second, MaxHeaderBytes: 8 << 10,
	}
	result := make(chan error, 1)
	go func() { result <- server.Serve(listener) }()
	select {
	case err := <-result:
		if !errors.Is(err, http.ErrServerClosed) {
			return errors.New("failure driver server stopped unexpectedly")
		}
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdown); err != nil {
			return errors.New("failure driver shutdown failed")
		}
	}
	return nil
}

func requestPhase(phase, scenarioID string) error {
	payload, err := json.Marshal(phaseRequest{ScenarioID: scenarioID, Phase: phase})
	if err != nil {
		return err
	}
	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "unix", driverSocket)
		},
	}
	client := &http.Client{Transport: transport, Timeout: 10 * time.Minute}
	request, err := http.NewRequest(http.MethodPost, "http://failure-driver/phase", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return errors.New("failure driver daemon unavailable")
	}
	defer func() { _ = response.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(response.Body, 512<<10+1))
	if err != nil || len(body) == 0 || len(body) > 512<<10 || response.StatusCode != http.StatusOK || !json.Valid(body) {
		return errors.New("failure driver phase failed")
	}
	_, err = os.Stdout.Write(body)
	return err
}

func probe(rawURL string) error {
	if len(rawURL) < 12 || len(rawURL) > 256 || !strings.HasPrefix(rawURL, "http://") || strings.ContainsAny(rawURL, "\r\n\x00") {
		return errors.New("probe URL is invalid")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	client := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{Proxy: nil}}
	for {
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
		if err == nil {
			response, requestErr := client.Do(request)
			if requestErr == nil {
				_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64<<10))
				_ = response.Body.Close()
				if response.StatusCode == http.StatusOK {
					return nil
				}
			}
		}
		select {
		case <-ctx.Done():
			return errors.New("probe timed out")
		case <-ticker.C:
		}
	}
}
