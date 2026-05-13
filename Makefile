.DEFAULT_GOAL := build

GO ?= go
GOLANGCI_LINT ?= golangci-lint
DOCKER ?= docker

BIN := bin/bb-credential-broker
PKG := ./...

# Image coordinates used by the docker-* targets. The defaults match
# what the release workflow publishes; override for local
# experimentation.
IMAGE_REGISTRY ?= bb-credential-broker
IMAGE_TAG ?= dev
IMAGE := $(IMAGE_REGISTRY):$(IMAGE_TAG)

.PHONY: build
build:
	$(GO) build -trimpath -ldflags='-s -w' -o $(BIN) ./cmd/bb-credential-broker

.PHONY: test
test:
	$(GO) test -race -count=1 $(PKG)

.PHONY: vet
vet:
	$(GO) vet $(PKG)

.PHONY: lint
lint:
	$(GOLANGCI_LINT) run $(PKG)

.PHONY: tidy
tidy:
	$(GO) mod tidy

.PHONY: docker-build
docker-build:
	$(DOCKER) build -t $(IMAGE) .

# docker-run mounts the example configuration into the standard
# location used by the broker's container image. Override
# CONFIG_PATH to point at a different file.
CONFIG_PATH ?= $(CURDIR)/examples/config.jsonnet
.PHONY: docker-run
docker-run: docker-build
	$(DOCKER) run --rm \
		-p 8080:8080 -p 9980:9980 \
		-v $(CONFIG_PATH):/config/config.jsonnet:ro \
		$(IMAGE) /config/config.jsonnet

.PHONY: clean
clean:
	rm -rf bin/

.PHONY: all
all: tidy vet test lint build
