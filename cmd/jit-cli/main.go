package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/code-with-amitk/proto-ephemeral-ssh/internal/client"
	"github.com/code-with-amitk/proto-ephemeral-ssh/internal/version"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" {
		printUsage(stdout)
		return 0
	}
	if args[0] == "--version" || args[0] == "-v" {
		fmt.Fprintf(stdout, "jit-cli %s\n", version.String())
		return 0
	}
	if args[0] != "access" {
		fmt.Fprintf(stderr, "unknown command: %s\n", args[0])
		printUsage(stderr)
		return 2
	}

	flags := flag.NewFlagSet("access", flag.ContinueOnError)
	flags.SetOutput(stderr)
	flags.Usage = func() {
		fmt.Fprintln(stderr, "Usage: jit-cli access --user <account> --host <hostname-or-ip> --duration <duration> [options]")
		fmt.Fprintln(stderr)
		fmt.Fprintln(stderr, "Options:")
		flags.PrintDefaults()
	}
	targetUser := flags.String("user", "", "account on the target SSH server")
	host := flags.String("host", "", "target SSH server hostname or IP address")
	duration := flags.String("duration", "", "requested lifetime as a whole number of minutes (for example 15m)")
	identity := flags.String("identity", "", "identity recorded in the certificate (defaults to the local username)")
	serverURL := flags.String("server", defaultServerURL(), "jitd base URL")
	if err := flags.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintf(stderr, "unexpected arguments: %s\n", strings.Join(flags.Args(), " "))
		flags.Usage()
		return 2
	}

	result, err := client.Access(context.Background(), client.Options{
		Identity:  *identity,
		User:      *targetUser,
		Host:      *host,
		Duration:  *duration,
		ServerURL: *serverURL,
	})
	if err != nil {
		fmt.Fprintf(stderr, "jit-cli access: %v\n", err)
		return 1
	}
	fmt.Fprintln(stdout, result.SSHCommand)
	return 0
}

func defaultServerURL() string {
	if value := strings.TrimSpace(os.Getenv("JIT_SERVER_URL")); value != "" {
		return value
	}
	return "http://127.0.0.1:8080"
}

func printUsage(w io.Writer) {
	fmt.Fprintln(w, "Usage: jit-cli <command> [options]")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Commands:")
	fmt.Fprintln(w, "  access    request a short-lived SSH certificate and print an SSH command")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Use 'jit-cli access --help' for access command options.")
	fmt.Fprintf(w, "Version: %s\n", version.String())
}
