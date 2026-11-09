package client

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	privateKeyFilename  = "id_jit_ephemeral"
	certificateFilename = "id_jit_ephemeral-cert.pub"
)

type requestPayload struct {
	Identity        string `json:"identity"`
	TargetUser      string `json:"target_user"`
	DurationMinutes int    `json:"duration_minutes"`
	PublicKey       string `json:"public_key"`
}

type responsePayload struct {
	Certificate string `json:"certificate"`
}

// Options configures one certificate issuance operation.
type Options struct {
	Identity   string
	User       string
	Host       string
	Duration   string
	ServerURL  string
	HomeDir    string
	HTTPClient *http.Client
}

// Result describes the credential files and SSH command created by an access request.
type Result struct {
	PrivateKeyPath  string
	CertificatePath string
	SSHCommand      string
}

// Access requests a certificate, stores the resulting credentials, and formats an SSH command.
func Access(ctx context.Context, options Options) (Result, error) {
	if err := validateOptions(&options); err != nil {
		return Result{}, err
	}

	duration, err := time.ParseDuration(options.Duration)
	if err != nil {
		return Result{}, fmt.Errorf("parse --duration: %w", err)
	}
	if duration <= 0 {
		return Result{}, errors.New("--duration must be positive")
	}
	if duration%time.Minute != 0 {
		return Result{}, errors.New("--duration must be a whole number of minutes")
	}
	minutes := duration / time.Minute
	if uint64(minutes) > uint64(^uint(0)>>1) {
		return Result{}, errors.New("--duration is too large")
	}
	durationMinutes := int(minutes)

	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return Result{}, fmt.Errorf("generate client key: %w", err)
	}
	signer, err := ssh.NewSignerFromKey(privateKey)
	if err != nil {
		return Result{}, fmt.Errorf("create client key signer: %w", err)
	}
	privateKeyBlock, err := ssh.MarshalPrivateKey(privateKey, "jit ephemeral key")
	if err != nil {
		return Result{}, fmt.Errorf("marshal client private key: %w", err)
	}
	var privateKeyPEM bytes.Buffer
	if err := pem.Encode(&privateKeyPEM, privateKeyBlock); err != nil {
		return Result{}, fmt.Errorf("encode client private key: %w", err)
	}

	payload := requestPayload{
		Identity:        options.Identity,
		TargetUser:      options.User,
		DurationMinutes: durationMinutes,
		PublicKey:       string(ssh.MarshalAuthorizedKey(signer.PublicKey())),
	}
	certificate, err := requestCertificate(ctx, options, payload)
	if err != nil {
		return Result{}, err
	}
	parsedKey, _, _, rest, err := ssh.ParseAuthorizedKey([]byte(certificate))
	if err != nil {
		return Result{}, fmt.Errorf("server returned an invalid OpenSSH certificate: %w", err)
	}
	if strings.TrimSpace(string(rest)) != "" {
		return Result{}, errors.New("server returned extra data after the OpenSSH certificate")
	}
	cert, ok := parsedKey.(*ssh.Certificate)
	if !ok || cert.CertType != ssh.UserCert {
		return Result{}, errors.New("server response is not an SSH user certificate")
	}
	if !bytes.Equal(cert.Key.Marshal(), signer.PublicKey().Marshal()) {
		return Result{}, errors.New("server returned a certificate for a different client key")
	}
	if cert.Signature == nil || cert.SignatureKey == nil {
		return Result{}, errors.New("server returned an unsigned certificate")
	}
	if !contains(cert.ValidPrincipals, options.User) {
		return Result{}, errors.New("server returned a certificate for a different target user")
	}

	credentialDir := filepath.Join(options.HomeDir, ".ssh", "jit")
	if err := os.MkdirAll(credentialDir, 0o700); err != nil {
		return Result{}, fmt.Errorf("create credential directory: %w", err)
	}
	if err := os.Chmod(credentialDir, 0o700); err != nil {
		return Result{}, fmt.Errorf("restrict credential directory permissions: %w", err)
	}

	privatePath := filepath.Join(credentialDir, privateKeyFilename)
	certificatePath := filepath.Join(credentialDir, certificateFilename)
	if err := writeExclusive(privatePath, privateKeyPEM.Bytes(), 0o600); err != nil {
		return Result{}, fmt.Errorf("save client private key: %w", err)
	}
	certBytes := []byte(strings.TrimRight(certificate, "\r\n") + "\n")
	if err := writeExclusive(certificatePath, certBytes, 0o600); err != nil {
		if removeErr := os.Remove(privatePath); removeErr != nil {
			return Result{}, fmt.Errorf("save certificate: %v (also failed to remove private key after partial save: %w)", err, removeErr)
		}
		return Result{}, fmt.Errorf("save certificate: %w", err)
	}

	destination := options.User + "@" + options.Host
	command := "ssh -i " + shellQuote(privatePath) +
		" -o " + shellQuote("CertificateFile="+certificatePath) +
		" " + shellQuote(destination)
	return Result{
		PrivateKeyPath:  privatePath,
		CertificatePath: certificatePath,
		SSHCommand:      command,
	}, nil
}

func validateOptions(options *Options) error {
	if strings.TrimSpace(options.User) == "" {
		return errors.New("--user is required")
	}
	if strings.TrimSpace(options.Host) == "" {
		return errors.New("--host is required")
	}
	if strings.HasPrefix(options.Host, "-") || strings.ContainsAny(options.Host, " \t\r\n") {
		return errors.New("--host must be a hostname or IP address")
	}
	if strings.ContainsAny(options.User, " \t\r\n@") || strings.HasPrefix(options.User, "-") {
		return errors.New("--user must be a target account name")
	}
	if options.Duration == "" {
		return errors.New("--duration is required")
	}
	if options.Identity == "" {
		currentUser, err := user.Current()
		if err != nil {
			return fmt.Errorf("determine local identity (use --identity): %w", err)
		}
		options.Identity = currentUser.Username
	}
	if strings.TrimSpace(options.Identity) == "" {
		return errors.New("--identity must not be empty")
	}
	if options.ServerURL == "" {
		options.ServerURL = "http://127.0.0.1:8080"
	}
	parsedURL, err := url.Parse(options.ServerURL)
	if err != nil || (parsedURL.Scheme != "http" && parsedURL.Scheme != "https") || parsedURL.Host == "" {
		return errors.New("--server must be an absolute http or https URL")
	}
	if options.HomeDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return fmt.Errorf("determine home directory: %w", err)
		}
		options.HomeDir = home
	}
	if options.HTTPClient == nil {
		options.HTTPClient = &http.Client{Timeout: 15 * time.Second}
	}
	return nil
}

func requestCertificate(ctx context.Context, options Options, payload requestPayload) (string, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("encode access request: %w", err)
	}
	endpoint := strings.TrimRight(options.ServerURL, "/") + "/api/v1/request-access"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("create access request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	response, err := options.HTTPClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("request access certificate: %w", err)
	}
	defer response.Body.Close()

	responseBody, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return "", fmt.Errorf("read access response: %w", err)
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return "", fmt.Errorf("access request failed with HTTP %d: %s", response.StatusCode, strings.TrimSpace(string(responseBody)))
	}
	var result responsePayload
	if err := json.Unmarshal(responseBody, &result); err != nil {
		return "", fmt.Errorf("decode access response: %w", err)
	}
	if strings.TrimSpace(result.Certificate) == "" {
		return "", errors.New("server response did not contain a certificate")
	}
	return result.Certificate, nil
}

func writeExclusive(path string, contents []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	writeErr := func() error {
		if _, err := file.Write(contents); err != nil {
			return err
		}
		return file.Sync()
	}()
	closeErr := file.Close()
	if writeErr != nil {
		_ = os.Remove(path)
		return writeErr
	}
	if closeErr != nil {
		_ = os.Remove(path)
		return closeErr
	}
	return nil
}

func contains(values []string, value string) bool {
	for _, item := range values {
		if item == value {
			return true
		}
	}
	return false
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}
