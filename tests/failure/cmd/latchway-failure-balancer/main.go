// latchway-failure-balancer is an internal-only deterministic reverse proxy
// used exclusively by the destructive release failure matrix. It exposes no
// host port and its counters are available only with a per-run control token.
package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

const (
	routeHeader = "X-Latchway-Failure-Backend"
	statsPath   = "/__latchway_failure/stats"
)

type repeatedFlag []string

func (values *repeatedFlag) String() string { return strings.Join(*values, ",") }
func (values *repeatedFlag) Set(value string) error {
	*values = append(*values, value)
	return nil
}

type balancer struct {
	backends []*url.URL
	proxies  []*httputil.ReverseProxy
	counts   []atomic.Int64
	next     atomic.Uint64
	token    string
}

func main() {
	var listen, tokenEnvironment string
	var rawBackends repeatedFlag
	var acknowledge bool
	flag.StringVar(&listen, "listen", "", "exact isolated-network listen address")
	flag.Var(&rawBackends, "backend", "exact private HTTP backend URL (repeat 2-4 times)")
	flag.StringVar(&tokenEnvironment, "control-token-env", "LATCHWAY_FAILURE_BALANCER_CONTROL_TOKEN", "control-token environment variable")
	flag.BoolVar(&acknowledge, "acknowledge-isolated-container-network", false, "permit one non-loopback address on an internal-only container bridge")
	flag.Parse()
	serverHandler, err := newBalancer(listen, rawBackends, os.Getenv(tokenEnvironment), acknowledge)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	server := &http.Server{
		Addr: listen, Handler: serverHandler, ReadHeaderTimeout: 2 * time.Second,
		ReadTimeout: 5 * time.Minute, WriteTimeout: 5 * time.Minute,
		IdleTimeout: 30 * time.Second, MaxHeaderBytes: 32 << 10,
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	result := make(chan error, 1)
	go func() { result <- server.ListenAndServe() }()
	select {
	case err := <-result:
		if !errors.Is(err, http.ErrServerClosed) {
			fmt.Fprintln(os.Stderr, "failure balancer stopped unexpectedly")
			os.Exit(1)
		}
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdown); err != nil {
			fmt.Fprintln(os.Stderr, "failure balancer shutdown failed")
			os.Exit(1)
		}
	}
}

func newBalancer(listen string, rawBackends []string, token string, acknowledge bool) (*balancer, error) {
	if err := validateListen(listen, acknowledge, token); err != nil {
		return nil, err
	}
	if len(rawBackends) < 2 || len(rawBackends) > 4 {
		return nil, errors.New("failure balancer requires two to four exact backends")
	}
	if len(token) < 32 || len(token) > 256 || strings.ContainsAny(token, "\r\n\x00") {
		return nil, errors.New("failure balancer control token is invalid")
	}
	result := &balancer{
		backends: make([]*url.URL, 0, len(rawBackends)),
		proxies:  make([]*httputil.ReverseProxy, 0, len(rawBackends)),
		counts:   make([]atomic.Int64, len(rawBackends)), token: token,
	}
	seen := make(map[string]struct{}, len(rawBackends))
	transport := &http.Transport{
		Proxy: nil, DialContext: (&net.Dialer{Timeout: 2 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		MaxIdleConns: 128, MaxIdleConnsPerHost: 64, IdleConnTimeout: 30 * time.Second,
		ResponseHeaderTimeout: 3 * time.Minute,
	}
	for _, raw := range rawBackends {
		backend, err := validateBackend(raw)
		if err != nil {
			return nil, err
		}
		if _, exists := seen[backend.String()]; exists {
			return nil, errors.New("failure balancer backends must be unique")
		}
		seen[backend.String()] = struct{}{}
		proxy := &httputil.ReverseProxy{
			Rewrite: func(request *httputil.ProxyRequest) {
				request.Out.Header.Del(routeHeader)
				request.SetURL(backend)
				request.SetXForwarded()
			},
		}
		proxy.Transport = transport
		proxy.ErrorHandler = func(writer http.ResponseWriter, _ *http.Request, _ error) {
			writer.Header().Set("Content-Type", "application/problem+json")
			writer.Header().Set("Cache-Control", "no-store")
			writer.WriteHeader(http.StatusBadGateway)
			_, _ = io.WriteString(writer, `{"code":"failure_backend_unavailable","status":502}`+"\n")
		}
		result.backends = append(result.backends, backend)
		result.proxies = append(result.proxies, proxy)
	}
	return result, nil
}

func validateListen(value string, acknowledge bool, token string) error {
	host, port, err := net.SplitHostPort(value)
	if err != nil || port != "18080" {
		return errors.New("failure balancer listen address must contain one explicit host and port")
	}
	address := net.ParseIP(host)
	if address == nil || address.IsMulticast() || address.IsLinkLocalUnicast() || address.IsLinkLocalMulticast() {
		return errors.New("failure balancer listen host must be one IP address")
	}
	if address.IsLoopback() {
		return nil
	}
	if (!address.IsPrivate() && !address.IsUnspecified()) || !acknowledge || len(token) < 32 {
		return errors.New("non-loopback failure balancer requires isolated-network acknowledgement and control token")
	}
	return nil
}

func validateBackend(raw string) (*url.URL, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "http" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") {
		return nil, errors.New("failure balancer backend must be one exact HTTP origin")
	}
	host := parsed.Hostname()
	address := net.ParseIP(host)
	if address == nil || address.To4() == nil || (!address.IsPrivate() && !address.IsLoopback()) || parsed.Port() != "8080" || host != address.String() {
		return nil, errors.New("failure balancer backend must use one exact private IP and port")
	}
	parsed.Path = ""
	return parsed, nil
}

func (value *balancer) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if request.URL.Path == statsPath {
		value.serveStats(writer, request)
		return
	}
	index, ok := value.backendIndex(request.Header.Get(routeHeader))
	if !ok {
		writer.Header().Set("Content-Type", "application/problem+json")
		writer.Header().Set("Cache-Control", "no-store")
		writer.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(writer, `{"code":"failure_backend_selection_invalid","status":400}`+"\n")
		return
	}
	value.counts[index].Add(1)
	value.proxies[index].ServeHTTP(writer, request)
}

func (value *balancer) backendIndex(header string) (int, bool) {
	if header == "" {
		return int((value.next.Add(1) - 1) % uint64(len(value.proxies))), true
	}
	parsed, err := strconv.Atoi(header)
	if err != nil || parsed < 1 || parsed > len(value.proxies) || strconv.Itoa(parsed) != header {
		return 0, false
	}
	return parsed - 1, true
}

func (value *balancer) serveStats(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet || !constantBearer(request.Header.Get("Authorization"), value.token) {
		http.NotFound(writer, request)
		return
	}
	counts := make([]int64, len(value.counts))
	var total int64
	for index := range value.counts {
		counts[index] = value.counts[index].Load()
		total += counts[index]
	}
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(writer).Encode(map[string]any{
		"schema_version": 1, "backend_count": len(counts), "requests_by_backend": counts, "total": total,
	})
}

func constantBearer(header, token string) bool {
	want := "Bearer " + token
	return len(header) == len(want) && subtle.ConstantTimeCompare([]byte(header), []byte(want)) == 1
}
