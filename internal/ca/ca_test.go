package ca

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestNewCreatesAndLoadsCA(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ca-key")

	first, err := New(path)
	if err != nil {
		t.Fatalf("create CA: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("CA key file missing: %v", err)
	}
	if first.Fingerprint() == "" {
		t.Fatal("CA fingerprint should not be empty")
	}

	second, err := New(path)
	if err != nil {
		t.Fatalf("reload CA: %v", err)
	}
	if first.Fingerprint() != second.Fingerprint() {
		t.Fatalf("CA identity changed across restart: %s != %s", first.Fingerprint(), second.Fingerprint())
	}
	keyPEM, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read CA key: %v", err)
	}
	block, _ := pem.Decode(keyPEM)
	if block == nil || block.Type != "OPENSSH PRIVATE KEY" {
		t.Fatalf("CA key is not in OpenSSH private-key format")
	}
	if got, err := exec.LookPath("ssh-keygen"); err == nil {
		output, err := exec.Command(got, "-y", "-f", path).Output()
		if err != nil {
			t.Fatalf("ssh-keygen could not read generated CA key: %v", err)
		}
		pub, _, _, _, err := ssh.ParseAuthorizedKey(output)
		if err != nil {
			t.Fatalf("parse ssh-keygen public key: %v", err)
		}
		if ssh.FingerprintSHA256(pub) != first.Fingerprint() {
			t.Fatalf("ssh-keygen derived a different CA public key")
		}
	}
}

func TestEmptyAndInvalidPublicKeyRejected(t *testing.T) {
	ca, err := New(filepath.Join(t.TempDir(), "ca-key"))
	if err != nil {
		t.Fatalf("create CA: %v", err)
	}

	for _, badKey := range []string{"", "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC invalid", "not-a-real-key"} {
		if _, err := ca.Sign("alice", "ubuntu", badKey, 5*time.Minute); err == nil {
			t.Fatalf("expected invalid key to fail for %q", badKey)
		}
	}
}

func TestCertificateFieldsAndLifetime(t *testing.T) {
	ca, err := New(filepath.Join(t.TempDir(), "ca-key"))
	if err != nil {
		t.Fatalf("create CA: %v", err)
	}

	publicKey := createPublicKey(t)
	cert, err := ca.Sign("alice", "ubuntu", publicKey, 5*time.Minute)
	if err != nil {
		t.Fatalf("sign certificate: %v", err)
	}

	if cert.KeyId != "alice" {
		t.Fatalf("unexpected KeyId: %q", cert.KeyId)
	}
	if len(cert.ValidPrincipals) != 1 || cert.ValidPrincipals[0] != "ubuntu" {
		t.Fatalf("unexpected principals: %#v", cert.ValidPrincipals)
	}
	if cert.Permissions.Extensions["permit-pty"] != "" {
		t.Fatalf("permit-pty extension value mismatch: %q", cert.Permissions.Extensions["permit-pty"])
	}
	if len(cert.Permissions.CriticalOptions) != 0 {
		t.Fatalf("critical options should remain reserved for restrictions, got %#v", cert.Permissions.CriticalOptions)
	}

	if cert.ValidAfter > uint64(time.Now().Add(-1*time.Minute).Unix())+5 {
		t.Fatalf("valid-after should be near issuance time; got %d", cert.ValidAfter)
	}
	if cert.ValidBefore > uint64(time.Now().Add(15*time.Minute).Unix())+5 {
		t.Fatalf("valid-before exceeded 15-minute maximum; got %d", cert.ValidBefore)
	}
	if cert.ValidBefore < uint64(time.Now().Add(5*time.Minute).Unix())-5 {
		t.Fatalf("valid-before should cover the requested lifetime: got %d", cert.ValidBefore)
	}

	encoded := ssh.MarshalAuthorizedKey(cert)
	parsedKey, _, _, _, err := ssh.ParseAuthorizedKey(encoded)
	if err != nil {
		t.Fatalf("parse signed certificate: %v", err)
	}
	parsedCert, ok := parsedKey.(*ssh.Certificate)
	if !ok {
		t.Fatal("parsed key is not an SSH certificate")
	}
	if !bytes.Equal(parsedCert.SignatureKey.Marshal(), ca.PublicKey().Marshal()) {
		t.Fatal("certificate signature key does not match CA public key")
	}
}

func createPublicKey(t *testing.T) string {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	pubKey, err := ssh.NewPublicKey(priv.Public().(ed25519.PublicKey))
	if err != nil {
		t.Fatalf("convert key: %v", err)
	}
	return string(ssh.MarshalAuthorizedKey(pubKey))
}
