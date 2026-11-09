GO ?= go

.PHONY: test build vet all

test:
	$(GO) test ./...

build:
	$(GO) build ./cmd/jitd ./cmd/jit-cli

vet:
	$(GO) vet ./...

all: test vet build
