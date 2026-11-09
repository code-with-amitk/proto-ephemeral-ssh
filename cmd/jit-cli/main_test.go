package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/code-with-amitk/proto-ephemeral-ssh/internal/ca"
)

func TestAccessCommandPrintsSSHCommand(t *testing.T) {
	issuer, err := ca.New(filepath.Join(t.TempDir(), "ca-key"))
	if err != nil {
		t.Fatalf("create CA: %v", err)
	}
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload struct {
			Identity        string `json:"identity"`
			TargetUser      string `json:"target_user"`
			DurationMinutes int    `json:"duration_minutes"`
			PublicKey       string `json:"public_key"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("decode API request: %v", err)
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		cert, err := issuer.Sign(payload.Identity, payload.TargetUser, payload.PublicKey, 15*60*1e9)
		if err != nil {
			t.Errorf("sign API response: %v", err)
			http.Error(w, "sign failed", http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(struct {
			Certificate string `json:"certificate"`
		}{Certificate: ca.MarshalCertificate(cert)})
	}))
	defer api.Close()

	home := t.TempDir()
	t.Setenv("HOME", home)
	var stdout, stderr bytes.Buffer
	code := run([]string{
		"access",
		"--identity", "developer",
		"--user", "ubuntu",
		"--host", "target.internal",
		"--duration", "15m",
		"--server", api.URL,
	}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("command failed with %d: %s", code, stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("unexpected stderr: %s", stderr.String())
	}
	wantPrivate := filepath.Join(home, ".ssh", "jit", "id_jit_ephemeral")
	wantCert := filepath.Join(home, ".ssh", "jit", "id_jit_ephemeral-cert.pub")
	wantCommand := "ssh -i '" + wantPrivate + "' -o 'CertificateFile=" + wantCert + "' 'ubuntu@target.internal'\n"
	if stdout.String() != wantCommand {
		t.Fatalf("unexpected output:\n got: %q\nwant: %q", stdout.String(), wantCommand)
	}
	for _, path := range []string{wantPrivate, wantCert} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("expected credential file %s: %v", path, err)
		}
	}
}

func TestTopLevelHelpAndInvalidInvocation(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"--help"}, &stdout, &stderr); code != 0 {
		t.Fatalf("help returned %d", code)
	}
	if !strings.Contains(stdout.String(), "access") {
		t.Fatalf("help does not list access command: %s", stdout.String())
	}

	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"access", "--help"}, &stdout, &stderr); code != 0 {
		t.Fatalf("access help returned %d: %s", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "--duration") || !strings.Contains(stderr.String(), "--host") {
		t.Fatalf("access help is missing flags: %s", stderr.String())
	}

	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"unknown"}, &stdout, &stderr); code == 0 {
		t.Fatal("unknown command should fail")
	}
	if !strings.Contains(stderr.String(), "unknown command") {
		t.Fatalf("unexpected unknown command output: %s", stderr.String())
	}
}
