.DEFAULT_GOAL := build

GO ?= go
GOLANGCI_LINT ?= golangci-lint
DOCKER ?= docker

BIN := bin/bb-credential-broker
EGRESS_BIN := bin/egress-authd
PKG := ./...

# Image coordinates used by the docker-* targets. The defaults match
# what the release workflow publishes; override for local
# experimentation.
IMAGE_REGISTRY ?= bb-credential-broker
IMAGE_TAG ?= dev
IMAGE := $(IMAGE_REGISTRY):$(IMAGE_TAG)

EGRESS_IMAGE_REGISTRY ?= egress-authd
EGRESS_IMAGE_TAG ?= dev
EGRESS_IMAGE := $(EGRESS_IMAGE_REGISTRY):$(EGRESS_IMAGE_TAG)

.PHONY: build
build: build-broker build-egress-authd

.PHONY: build-broker
build-broker:
	$(GO) build -trimpath -ldflags='-s -w' -o $(BIN) ./cmd/bb-credential-broker

.PHONY: build-egress-authd
build-egress-authd:
	$(GO) build -trimpath -ldflags='-s -w' -o $(EGRESS_BIN) ./cmd/egress-authd

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
docker-build: docker-build-broker docker-build-egress-authd

.PHONY: docker-build-broker
docker-build-broker:
	$(DOCKER) build -t $(IMAGE) .

.PHONY: docker-build-egress-authd
docker-build-egress-authd:
	$(DOCKER) build -f Dockerfile.egress-authd -t $(EGRESS_IMAGE) .

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
