package server

import (
	"bytes"
	"io/fs"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/go-chi/chi/v5/middleware"
)

type consoleHandler struct {
	assets fs.FS
}

func newConsoleHandler(assets fs.FS) *consoleHandler {
	return &consoleHandler{assets: assets}
}

func (h *consoleHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if isReservedServerPath(r.URL.Path) {
		writeJSON(w, http.StatusNotFound, map[string]any{
			"type":       "about:blank",
			"title":      "Route Not Found",
			"status":     http.StatusNotFound,
			"code":       "route_not_found",
			"request_id": middleware.GetReqID(r.Context()),
		})
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{
			"type":       "about:blank",
			"title":      "Method Not Allowed",
			"status":     http.StatusMethodNotAllowed,
			"code":       "method_not_allowed",
			"request_id": middleware.GetReqID(r.Context()),
		})
		return
	}

	assetName := strings.TrimPrefix(path.Clean("/"+r.URL.Path), "/")
	if assetName == "." || assetName == "" {
		assetName = "index.html"
	}
	if !fs.ValidPath(assetName) {
		http.NotFound(w, r)
		return
	}
	contents, err := fs.ReadFile(h.assets, assetName)
	if err != nil {
		if strings.HasPrefix(assetName, "assets/") || strings.Contains(path.Base(assetName), ".") {
			http.NotFound(w, r)
			return
		}
		assetName = "index.html"
		contents, err = fs.ReadFile(h.assets, assetName)
		if err != nil {
			http.Error(w, "admin console unavailable", http.StatusServiceUnavailable)
			return
		}
	}

	setConsoleHeaders(w, assetName)
	http.ServeContent(w, r, assetName, time.Time{}, bytes.NewReader(contents))
}

func setConsoleHeaders(w http.ResponseWriter, assetName string) {
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
	w.Header().Set("Permissions-Policy", "camera=(), geolocation=(), microphone=(), payment=(), usb=()")
	if strings.HasPrefix(assetName, "assets/") {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	} else {
		w.Header().Set("Cache-Control", "no-store")
	}
}

func isReservedServerPath(requestPath string) bool {
	for _, reserved := range []string{"/admin", "/client", "/v1", "/proxy", "/metrics", "/healthz", "/readyz", "/.well-known"} {
		if requestPath == reserved || strings.HasPrefix(requestPath, reserved+"/") {
			return true
		}
	}
	return false
}
