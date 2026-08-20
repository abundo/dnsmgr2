# Build directory
BUILD_DIR := bin

# Install directory
INSTALL_DIR := /usr/bin

VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
GO_BUILD_FLAGS := -ldflags="-s -w -X main.version=$(VERSION)"

.PHONY: build dnsmgr2 install snapshot

build: dnsmgr2

dnsmgr2:
	@mkdir -p $(BUILD_DIR)
	@CGO_ENABLED=0 go build $(GO_BUILD_FLAGS) -o $(BUILD_DIR)/dnsmgr2 ./cmd/dnsmgr2

install: build
	sudo install -m 755 $(BUILD_DIR)/dnsmgr2 $(INSTALL_DIR)

snapshot:
	goreleaser release --snapshot --clean --skip=publish
