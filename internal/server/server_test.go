package server

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/code-with-amitk/proto-ephemeral-ssh/internal/ca"
)

func TestAccessRequestSuccess(t *testing.T) {
	issuer, err := ca.New(filepath.Join(t.TempDir(), "ca-key"))
	if err != nil {
		t.Fatalf("create issuer: %v", err)
	}
	h := New(issuer)

	payload, err := json.Marshal(map[string]any{
		"identity":         "alice",
		"target_user":      "ubuntu",
		"duration_minutes": 5,
		"public_key":       publicKeyString(t),
	})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/request-access", bytes.NewReader(payload))
	res := httptest.NewRecorder()

	h.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d body=%s", res.Code, res.Body.String())
	}

	var body AccessResponse
	if err := json.Unmarshal(res.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode JSON response: %v", err)
	}
	if body.Certificate == "" {
		t.Fatal("certificate is empty")
	}
	if strings.HasSuffix(body.Certificate, "\n") || strings.HasSuffix(body.Certificate, "\r") {
		t.Fatalf("certificate must not include trailing newline: %q", body.Certificate)
	}
	parsed, _, _, _, err := ssh.ParseAuthorizedKey([]byte(body.Certificate))
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	cert, ok := parsed.(*ssh.Certificate)
	if !ok {
		t.Fatal("parsed key is not an SSH certificate")
	}
	if cert.KeyId != "alice" {
		t.Fatalf("unexpected KeyId: %q", cert.KeyId)
	}
	if len(cert.ValidPrincipals) != 1 || cert.ValidPrincipals[0] != "ubuntu" {
		t.Fatalf("unexpected principals: %#v", cert.ValidPrincipals)
	}
	if time.Until(time.Unix(int64(cert.ValidBefore), 0)) > 15*time.Minute+time.Minute {
		t.Fatalf("validity exceeds 15-minute maximum: %v", time.Until(time.Unix(int64(cert.ValidBefore), 0)))
	}
}

func TestAccessRequestMalformedJSON(t *testing.T) {
	issuer, err := ca.New(filepath.Join(t.TempDir(), "ca-key"))
	if err != nil {
		t.Fatalf("create issuer: %v", err)
	}
	h := New(issuer)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/request-access", bytes.NewReader([]byte("{bad json")))
	res := httptest.NewRecorder()
	h.ServeHTTP(res, req)
	if res.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", res.Code, res.Body.String())
	}
}

func TestAccessRequestUnsupportedMethod(t *testing.T) {
	issuer, err := ca.New(filepath.Join(t.TempDir(), "ca-key"))
	if err != nil {
		t.Fatalf("create issuer: %v", err)
	}
	h := New(issuer)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/request-access", nil)
	res := httptest.NewRecorder()
	h.ServeHTTP(res, req)
	if res.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d: %s", res.Code, res.Body.String())
	}
}

func TestAccessRequestInvalidPublicKey(t *testing.T) {
	issuer, err := ca.New(filepath.Join(t.TempDir(), "ca-key"))
	if err != nil {
		t.Fatalf("create issuer: %v", err)
	}
	h := New(issuer)

	payload, err := json.Marshal(map[string]any{
		"identity":         "alice",
		"target_user":      "ubuntu",
		"duration_minutes": 5,
		"public_key":       "not-a-valid-key",
	})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/request-access", bytes.NewReader(payload))
	res := httptest.NewRecorder()
	h.ServeHTTP(res, req)
	if res.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", res.Code, res.Body.String())
	}
}

func TestAccessRequestRejectsZeroOrNegativeDuration(t *testing.T) {
	issuer, err := ca.New(filepath.Join(t.TempDir(), "ca-key"))
	if err != nil {
		t.Fatalf("create issuer: %v", err)
	}
	h := New(issuer)
	for _, minutes := range []int{0, -1} {
		payload, err := json.Marshal(map[string]any{
			"identity":         "alice",
			"target_user":      "ubuntu",
			"duration_minutes": minutes,
			"public_key":       publicKeyString(t),
		})
		if err != nil {
			t.Fatalf("marshal payload: %v", err)
		}
		req := httptest.NewRequest(http.MethodPost, "/api/v1/request-access", bytes.NewReader(payload))
		res := httptest.NewRecorder()
		h.ServeHTTP(res, req)
		if res.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for duration %d, got %d: %s", minutes, res.Code, res.Body.String())
		}
	}
}

func TestAccessRequestCapsOverLimitDuration(t *testing.T) {
	issuer, err := ca.New(filepath.Join(t.TempDir(), "ca-key"))
	if err != nil {
		t.Fatalf("create issuer: %v", err)
	}
	h := New(issuer)

	payload, err := json.Marshal(map[string]any{
		"identity":         "alice",
		"target_user":      "ubuntu",
		"duration_minutes": 30,
		"public_key":       publicKeyString(t),
	})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/request-access", bytes.NewReader(payload))
	res := httptest.NewRecorder()
	h.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("unexpected status: %d body=%s", res.Code, res.Body.String())
	}

	var body AccessResponse
	if err := json.Unmarshal(res.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode JSON response: %v", err)
	}
	parsed, _, _, _, err := ssh.ParseAuthorizedKey([]byte(body.Certificate))
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	cert := parsed.(*ssh.Certificate)
	if cert.ValidBefore > uint64(time.Now().Add(15*time.Minute).Unix()) {
		t.Fatalf("certificate should be capped to 15 minutes, got validity end %d", cert.ValidBefore)
	}
}

func TestWebPagesAndCAKeyDownload(t *testing.T) {
	issuer, err := ca.New(filepath.Join(t.TempDir(), "ca-key"))
	if err != nil {
		t.Fatalf("create issuer: %v", err)
	}
	handler := New(issuer)

	for path, expected := range map[string][]string{
		"/":    {"Short-lived SSH access", `id="access-form"`, `href="/why"`, `href="/ca.pub"`},
		"/why": {"Why this product exists", "Not a replacement for every PAM program"},
	} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		res := httptest.NewRecorder()
		handler.ServeHTTP(res, req)
		if res.Code != http.StatusOK {
			t.Fatalf("GET %s status = %d, want 200", path, res.Code)
		}
		for _, text := range expected {
			if !strings.Contains(res.Body.String(), text) {
				t.Errorf("GET %s body does not contain %q", path, text)
			}
		}
		if res.Header().Get("Content-Security-Policy") == "" {
			t.Errorf("GET %s missing content security policy", path)
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/ca.pub", nil)
	res := httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	want := string(ssh.MarshalAuthorizedKey(issuer.PublicKey()))
	if res.Code != http.StatusOK || res.Body.String() != want {
		t.Fatalf("CA download status/body mismatch: status=%d body=%q want=%q", res.Code, res.Body.String(), want)
	}
	if got := res.Header().Get("Content-Disposition"); !strings.Contains(got, "jit_ca.pub") {
		t.Errorf("unexpected CA download disposition: %q", got)
	}
	if strings.Contains(res.Body.String(), "PRIVATE KEY") {
		t.Fatal("CA download exposed private key material")
	}

	req = httptest.NewRequest(http.MethodGet, "/healthz", nil)
	res = httptest.NewRecorder()
	handler.ServeHTTP(res, req)
	if res.Code != http.StatusNoContent {
		t.Errorf("health check status = %d, want 204", res.Code)
	}
}

func publicKeyString(t *testing.T) string {
	t.Helper()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate keypair: %v", err)
	}
	publicKey, err := ssh.NewPublicKey(privateKey.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatalf("convert public key: %v", err)
	}
	return string(ssh.MarshalAuthorizedKey(publicKey))
}
