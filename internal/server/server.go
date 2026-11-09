package server

import (
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"strings"
	"time"

	"github.com/code-with-amitk/proto-ephemeral-ssh/internal/ca"
	"golang.org/x/crypto/ssh"
)

const maxDurationMinutes = 15

//go:embed web/*
var webFiles embed.FS

// AccessRequest is the API payload for certificate issuance.
type AccessRequest struct {
	Identity        string `json:"identity"`
	TargetUser      string `json:"target_user"`
	DurationMinutes int    `json:"duration_minutes"`
	PublicKey       string `json:"public_key"`
}

// AccessResponse contains the signed OpenSSH user certificate.
type AccessResponse struct {
	Certificate string `json:"certificate"`
}

// Server handles certificate issuance requests.
type Server struct {
	issuer *ca.CA
}

// New creates a certificate-signing HTTP handler.
func New(issuer *ca.CA) *Server {
	return &Server{issuer: issuer}
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self'; script-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")

	switch r.URL.Path {
	case "/":
		s.serveWebFile(w, r, "index.html", "text/html; charset=utf-8")
	case "/why":
		s.serveWebFile(w, r, "why.html", "text/html; charset=utf-8")
	case "/app.js":
		s.serveWebFile(w, r, "app.js", "text/javascript; charset=utf-8")
	case "/styles.css":
		s.serveWebFile(w, r, "styles.css", "text/css; charset=utf-8")
	case "/ca.pub":
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/vnd.openssh.pubkey")
		w.Header().Set("Content-Disposition", `attachment; filename="jit_ca.pub"`)
		if r.Method == http.MethodGet {
			_, _ = w.Write(ssh.MarshalAuthorizedKey(s.issuer.PublicKey()))
		}
	case "/healthz":
		w.WriteHeader(http.StatusNoContent)
	case "/api/v1/request-access":
		s.serveAccessRequest(w, r)
	default:
		writeJSONError(w, http.StatusNotFound, "not found")
	}
}

func (s *Server) serveAccessRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeJSONError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	var req AccessRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid JSON request body")
		return
	}
	if err := validateRequest(req); err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	cert, err := s.issuer.Sign(req.Identity, req.TargetUser, req.PublicKey, time.Duration(req.DurationMinutes)*time.Minute)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, AccessResponse{Certificate: ca.MarshalCertificate(cert)})
}

func (s *Server) serveWebFile(w http.ResponseWriter, r *http.Request, name, contentType string) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	data, err := fs.ReadFile(webFiles, "web/"+name)
	if err != nil {
		http.Error(w, "web page unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", contentType)
	if name == "app.js" || name == "styles.css" {
		w.Header().Set("Cache-Control", "public, max-age=3600")
	}
	if r.Method == http.MethodHead {
		w.Header().Set("Content-Length", fmt.Sprint(len(data)))
		return
	}
	_, _ = w.Write(data)
}

func validateRequest(req AccessRequest) error {
	if strings.TrimSpace(req.Identity) == "" {
		return errors.New("identity is required")
	}
	if strings.TrimSpace(req.TargetUser) == "" {
		return errors.New("target_user is required")
	}
	if strings.TrimSpace(req.PublicKey) == "" {
		return errors.New("public_key is required")
	}
	if len(req.Identity) > 256 || len(req.TargetUser) > 256 {
		return errors.New("identity and target_user must be smaller than 256 characters")
	}
	if len(req.PublicKey) > 8192 {
		return errors.New("public_key is too large")
	}
	if req.DurationMinutes <= 0 {
		return errors.New("duration_minutes must be positive")
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		http.Error(w, "failed to encode response", http.StatusInternalServerError)
	}
}

func writeJSONError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func ValidateDurationMinutes(value int) (int, error) {
	if value <= 0 {
		return 0, fmt.Errorf("duration_minutes must be positive")
	}
	if value > maxDurationMinutes {
		return maxDurationMinutes, nil
	}
	return value, nil
}
