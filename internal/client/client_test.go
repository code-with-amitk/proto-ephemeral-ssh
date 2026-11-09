package client

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/code-with-amitk/proto-ephemeral-ssh/internal/ca"
	"golang.org/x/crypto/ssh"
)

func TestAccessRequestsCertificateAndWritesRestrictedFiles(t *testing.T) {
	issuer, err := ca.New(filepath.Join(t.TempDir(), "ca-key"))
	if err != nil {
		t.Fatalf("create CA: %v", err)
	}
	home := t.TempDir()
	var received requestPayload
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/request-access" {
			t.Errorf("unexpected API request: %s %s", r.Method, r.URL.Path)
		}
		if _, err := os.Stat(filepath.Join(home, ".ssh", "jit", privateKeyFilename)); !os.IsNotExist(err) {
			t.Errorf("private key existed before successful certificate response: %v", err)
		}
		if err := json.NewDecoder(r.Body).Decode(&received); err != nil {
			t.Errorf("decode request: %v", err)
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		cert, err := issuer.Sign(received.Identity, received.TargetUser, received.PublicKey, 15*60*1e9)
		if err != nil {
			t.Errorf("sign certificate: %v", err)
			http.Error(w, "sign failed", http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(responsePayload{Certificate: ca.MarshalCertificate(cert)})
	}))
	defer api.Close()

	result, err := Access(context.Background(), Options{
		Identity:  "developer",
		User:      "ubuntu",
		Host:      "target.internal",
		Duration:  "15m",
		ServerURL: api.URL,
		HomeDir:   home,
	})
	if err != nil {
		t.Fatalf("request access: %v", err)
	}
	if received.Identity != "developer" || received.TargetUser != "ubuntu" || received.DurationMinutes != 15 {
		t.Fatalf("unexpected API request fields: %+v", received)
	}
	if result.PrivateKeyPath != filepath.Join(home, ".ssh", "jit", privateKeyFilename) {
		t.Fatalf("unexpected private key path: %s", result.PrivateKeyPath)
	}
	if result.CertificatePath != filepath.Join(home, ".ssh", "jit", certificateFilename) {
		t.Fatalf("unexpected certificate path: %s", result.CertificatePath)
	}
	wantCommand := "ssh -i '" + result.PrivateKeyPath + "' -o 'CertificateFile=" + result.CertificatePath + "' 'ubuntu@target.internal'"
	if result.SSHCommand != wantCommand {
		t.Fatalf("unexpected SSH command:\n got: %s\nwant: %s", result.SSHCommand, wantCommand)
	}

	assertMode(t, filepath.Join(home, ".ssh", "jit"), 0o700)
	assertMode(t, result.PrivateKeyPath, 0o600)
	assertMode(t, result.CertificatePath, 0o600)

	privateBytes, err := os.ReadFile(result.PrivateKeyPath)
	if err != nil {
		t.Fatalf("read saved private key: %v", err)
	}
	signer, err := ssh.ParsePrivateKey(privateBytes)
	if err != nil {
		t.Fatalf("parse saved private key: %v", err)
	}
	if !bytes.Equal(signer.PublicKey().Marshal(), mustParsePublicKey(t, received.PublicKey).Marshal()) {
		t.Fatal("saved private key does not match the public key sent to API")
	}
	certBytes, err := os.ReadFile(result.CertificatePath)
	if err != nil {
		t.Fatalf("read saved certificate: %v", err)
	}
	if strings.HasSuffix(string(certBytes), "\n\n") {
		t.Fatal("saved certificate has an extra blank line")
	}
	if _, _, _, _, err := ssh.ParseAuthorizedKey(certBytes); err != nil {
		t.Fatalf("saved certificate is not parseable: %v", err)
	}
	entries, err := os.ReadDir(filepath.Join(home, ".ssh", "jit"))
	if err != nil {
		t.Fatalf("list credential directory: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("expected only private key and certificate in credential directory, got %d entries", len(entries))
	}
	privateKeyCopies := 0
	if err := filepath.WalkDir(home, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if bytes.Equal(data, privateBytes) {
			privateKeyCopies++
			if path != result.PrivateKeyPath {
				t.Errorf("private key was also written to %s", path)
			}
		}
		return nil
	}); err != nil {
		t.Fatalf("search temporary home for private key copies: %v", err)
	}
	if privateKeyCopies != 1 {
		t.Fatalf("found %d copies of generated private key, want exactly one", privateKeyCopies)
	}
}

func TestAccessRejectsInvalidDurationsBeforeRequest(t *testing.T) {
	apiCalled := false
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		apiCalled = true
		_, _ = w.Write([]byte(`{"certificate":"invalid"}`))
	}))
	defer api.Close()

	for _, duration := range []string{"0m", "-1m", "90s", "invalid"} {
		_, err := Access(context.Background(), Options{
			Identity:  "developer",
			User:      "ubuntu",
			Host:      "target.internal",
			Duration:  duration,
			ServerURL: api.URL,
			HomeDir:   t.TempDir(),
		})
		if err == nil {
			t.Errorf("expected duration %q to fail", duration)
		}
	}
	if apiCalled {
		t.Fatal("API should not be called for invalid duration")
	}
}

func TestAccessHandlesAPIAndCertificateErrorsWithoutWritingKeys(t *testing.T) {
	tests := []struct {
		name        string
		status      int
		certificate string
	}{
		{name: "API error", status: http.StatusBadRequest, certificate: `{"error":"bad request"}`},
		{name: "malformed response", status: http.StatusOK, certificate: `not json`},
		{name: "invalid certificate", status: http.StatusOK, certificate: `{"certificate":"not an SSH key"}`},
		{name: "missing certificate", status: http.StatusOK, certificate: `{"certificate":""}`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			home := t.TempDir()
			api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(test.status)
				_, _ = w.Write([]byte(test.certificate))
			}))
			defer api.Close()

			_, err := Access(context.Background(), Options{
				Identity:  "developer",
				User:      "ubuntu",
				Host:      "target.internal",
				Duration:  "5m",
				ServerURL: api.URL,
				HomeDir:   home,
			})
			if err == nil {
				t.Fatal("expected request to fail")
			}
			if _, err := os.Stat(filepath.Join(home, ".ssh", "jit")); !os.IsNotExist(err) {
				t.Fatalf("credentials directory should not be created before valid response: %v", err)
			}
		})
	}
}

func TestAccessRemovesNewPrivateKeyWhenCertificateCannotBeSaved(t *testing.T) {
	issuer, err := ca.New(filepath.Join(t.TempDir(), "ca-key"))
	if err != nil {
		t.Fatalf("create CA: %v", err)
	}
	home := t.TempDir()
	credentialDir := filepath.Join(home, ".ssh", "jit")
	if err := os.MkdirAll(credentialDir, 0o700); err != nil {
		t.Fatalf("create credential directory: %v", err)
	}
	certPath := filepath.Join(credentialDir, certificateFilename)
	if err := os.WriteFile(certPath, []byte("existing certificate"), 0o600); err != nil {
		t.Fatalf("create existing certificate: %v", err)
	}
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload requestPayload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("decode request: %v", err)
			return
		}
		cert, err := issuer.Sign(payload.Identity, payload.TargetUser, payload.PublicKey, 5*60*1e9)
		if err != nil {
			t.Errorf("sign certificate: %v", err)
			return
		}
		_ = json.NewEncoder(w).Encode(responsePayload{Certificate: ca.MarshalCertificate(cert)})
	}))
	defer api.Close()

	_, err = Access(context.Background(), Options{
		Identity:  "developer",
		User:      "ubuntu",
		Host:      "target.internal",
		Duration:  "5m",
		ServerURL: api.URL,
		HomeDir:   home,
	})
	if err == nil {
		t.Fatal("expected credential collision to fail")
	}
	if _, err := os.Stat(filepath.Join(credentialDir, privateKeyFilename)); !os.IsNotExist(err) {
		t.Fatalf("new private key was not removed after certificate-save failure: %v", err)
	}
	existing, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read existing certificate: %v", err)
	}
	if string(existing) != "existing certificate" {
		t.Fatal("existing certificate was modified")
	}
}

func TestAccessRejectsCertificateForDifferentKey(t *testing.T) {
	issuer, err := ca.New(filepath.Join(t.TempDir(), "ca-key"))
	if err != nil {
		t.Fatalf("create CA: %v", err)
	}
	_, unrelatedPrivateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generate unrelated key: %v", err)
	}
	unrelatedPublicKey, err := ssh.NewPublicKey(unrelatedPrivateKey.Public())
	if err != nil {
		t.Fatalf("convert unrelated key: %v", err)
	}
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload requestPayload
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("decode request: %v", err)
			return
		}
		cert, err := issuer.Sign(payload.Identity, payload.TargetUser, string(ssh.MarshalAuthorizedKey(unrelatedPublicKey)), 5*60*1e9)
		if err != nil {
			t.Errorf("sign certificate: %v", err)
			return
		}
		_ = json.NewEncoder(w).Encode(responsePayload{Certificate: ca.MarshalCertificate(cert)})
	}))
	defer api.Close()
	home := t.TempDir()

	_, err = Access(context.Background(), Options{
		Identity:  "developer",
		User:      "ubuntu",
		Host:      "target.internal",
		Duration:  "5m",
		ServerURL: api.URL,
		HomeDir:   home,
	})
	if err == nil || !strings.Contains(err.Error(), "different client key") {
		t.Fatalf("expected mismatched key error, got %v", err)
	}
	if _, err := os.Stat(filepath.Join(home, ".ssh", "jit")); !os.IsNotExist(err) {
		t.Fatalf("credentials directory should not be created: %v", err)
	}
}

func mustParsePublicKey(t *testing.T, value string) ssh.PublicKey {
	t.Helper()
	key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(value))
	if err != nil {
		t.Fatalf("parse public key: %v", err)
	}
	return key
}

func assertMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	if got := info.Mode().Perm(); got != want {
		t.Fatalf("%s permissions = %04o, want %04o", path, got, want)
	}
}
