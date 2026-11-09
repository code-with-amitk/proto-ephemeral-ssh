package ca

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

const maxCertificateLifetime = 15 * time.Minute

// DefaultKeyPath returns the default key location for the SSH CA outside the project tree.
func DefaultKeyPath() string {
	if value := strings.TrimSpace(os.Getenv("JIT_CA_KEY_PATH")); value != "" {
		return value
	}
	return filepath.Join(os.TempDir(), "jit-ssh-ca")
}

// CA is a persistent SSH certificate authority for issuing user certificates.
type CA struct {
	keyPath     string
	privateKey  ed25519.PrivateKey
	publicKey   ssh.PublicKey
	fingerprint string
}

// New creates a new CA at keyPath or loads an existing CA key from disk.
func New(keyPath string) (*CA, error) {
	if keyPath == "" {
		keyPath = DefaultKeyPath()
	}

	if info, err := os.Stat(keyPath); err == nil {
		if !info.Mode().IsRegular() {
			return nil, fmt.Errorf("CA key path is not a regular file: %s", keyPath)
		}
		bytes, err := os.ReadFile(keyPath)
		if err != nil {
			return nil, fmt.Errorf("read CA key: %w", err)
		}
		parsed, err := ssh.ParseRawPrivateKey(bytes)
		if err != nil {
			return nil, fmt.Errorf("parse CA key: %w", err)
		}
		var priv ed25519.PrivateKey
		switch key := parsed.(type) {
		case ed25519.PrivateKey:
			priv = key
		case *ed25519.PrivateKey:
			if key != nil {
				priv = *key
			}
		}
		if len(priv) != ed25519.PrivateKeySize {
			return nil, fmt.Errorf("unsupported CA key type: %T", parsed)
		}
		return newCAFromPrivate(keyPath, priv)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("check CA key path: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(keyPath), 0o700); err != nil {
		return nil, fmt.Errorf("create CA key directory: %w", err)
	}

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate CA key: %w", err)
	}

	if err := writePrivateKey(keyPath, priv); err != nil {
		return nil, err
	}
	return newCAFromPrivate(keyPath, priv)
}

func newCAFromPrivate(keyPath string, priv ed25519.PrivateKey) (*CA, error) {
	publicKey, err := ssh.NewPublicKey(priv.Public().(ed25519.PublicKey))
	if err != nil {
		return nil, fmt.Errorf("derive CA public key: %w", err)
	}
	return &CA{
		keyPath:     keyPath,
		privateKey:  priv,
		publicKey:   publicKey,
		fingerprint: ssh.FingerprintSHA256(publicKey),
	}, nil
}

func writePrivateKey(path string, priv ed25519.PrivateKey) error {
	block, err := ssh.MarshalPrivateKey(priv, "jit SSH certificate authority")
	if err != nil {
		return fmt.Errorf("marshal CA private key: %w", err)
	}
	pemBytes := pem.EncodeToMemory(block)
	if err := os.WriteFile(path, pemBytes, 0o600); err != nil {
		return fmt.Errorf("write CA private key: %w", err)
	}
	return nil
}

// KeyPath returns the canonical path used for the CA private key.
func (c *CA) KeyPath() string { return c.keyPath }

// PublicKey returns the CA public key.
func (c *CA) PublicKey() ssh.PublicKey { return c.publicKey }

// Fingerprint returns the SHA256 fingerprint of the CA public key.
func (c *CA) Fingerprint() string { return c.fingerprint }

// ParseAuthorizedPublicKey validates and parses an OpenSSH public key string.
func ParseAuthorizedPublicKey(value string) (ssh.PublicKey, error) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return nil, errors.New("public key is empty")
	}
	key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(trimmed))
	if err != nil {
		return nil, fmt.Errorf("parse public key: %w", err)
	}
	return key, nil
}

// MarshalCertificate returns the SSH certificate in its canonical OpenSSH form without a trailing newline.
func MarshalCertificate(cert *ssh.Certificate) string {
	return strings.TrimRight(string(ssh.MarshalAuthorizedKey(cert)), "\r\n")
}

// Sign signs a user certificate for the supplied public key and target account.
func (c *CA) Sign(identity, targetUser, publicKeyValue string, requestedDuration time.Duration) (*ssh.Certificate, error) {
	if identity == "" {
		return nil, errors.New("identity is required")
	}
	if targetUser == "" {
		return nil, errors.New("target user is required")
	}
	publicKey, err := ParseAuthorizedPublicKey(publicKeyValue)
	if err != nil {
		return nil, err
	}

	certDuration := requestedDuration
	if certDuration <= 0 {
		certDuration = maxCertificateLifetime
	}
	if certDuration > maxCertificateLifetime {
		certDuration = maxCertificateLifetime
	}

	now := time.Now()
	cert := &ssh.Certificate{
		Key:             publicKey,
		Serial:          1,
		CertType:        ssh.UserCert,
		KeyId:           identity,
		ValidPrincipals: []string{targetUser},
		ValidAfter:      uint64(now.Add(-1 * time.Minute).Unix()),
		ValidBefore:     uint64(now.Add(certDuration).Unix()),
		Permissions: ssh.Permissions{
			CriticalOptions: map[string]string{},
			Extensions: map[string]string{
				"permit-pty": "",
			},
		},
	}
	if cert.ValidBefore > uint64(now.Add(maxCertificateLifetime).Unix()) {
		cert.ValidBefore = uint64(now.Add(maxCertificateLifetime).Unix())
	}

	signer, err := ssh.NewSignerFromKey(c.privateKey)
	if err != nil {
		return nil, fmt.Errorf("create SSH signer: %w", err)
	}
	if err := cert.SignCert(rand.Reader, signer); err != nil {
		return nil, fmt.Errorf("sign certificate: %w", err)
	}
	return cert, nil
}
