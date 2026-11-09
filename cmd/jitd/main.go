package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"

	"golang.org/x/crypto/ssh"

	"github.com/code-with-amitk/proto-ephemeral-ssh/internal/ca"
	"github.com/code-with-amitk/proto-ephemeral-ssh/internal/server"
	"github.com/code-with-amitk/proto-ephemeral-ssh/internal/version"
)

func usage() {
	fmt.Fprintf(flag.CommandLine.Output(), "Usage: jitd [options]\n\n")
	fmt.Fprintf(flag.CommandLine.Output(), "Starts the JIT SSH certificate-signing daemon.\n\n")
	fmt.Fprintf(flag.CommandLine.Output(), "Options:\n")
	flag.PrintDefaults()
}

func main() {
	for _, arg := range os.Args[1:] {
		switch arg {
		case "-h", "--help", "-help":
			usage()
			return
		case "-v", "--version", "-version":
			fmt.Printf("jitd %s\n", version.String())
			return
		}
	}

	flag.Usage = usage
	flag.CommandLine.SetOutput(os.Stdout)
	flag.Bool("version", false, "print version and exit")
	printCAPublicKey := flag.Bool("print-ca-public-key", false, "print the CA public key and exit")
	flag.Parse()

	if flag.Lookup("version").Value.String() == "true" {
		fmt.Printf("jitd %s\n", version.String())
		return
	}

	keyPath := ca.DefaultKeyPath()
	issuer, err := ca.New(keyPath)
	if err != nil {
		log.Fatalf("initialize CA: %v", err)
	}
	if *printCAPublicKey {
		fmt.Println(string(ssh.MarshalAuthorizedKey(issuer.PublicKey())))
		return
	}

	fmt.Printf("jitd %s\n", version.String())
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65535 {
		log.Fatalf("invalid PORT %q: must be an integer between 1 and 65535", port)
	}
	address := ":" + strconv.Itoa(portNumber)
	fmt.Printf("Serving SSH certificate requests on %s using CA key %s\n", address, issuer.KeyPath())
	if err := http.ListenAndServe(address, server.New(issuer)); err != nil {
		log.Fatalf("serve daemon: %v", err)
	}
}
