.PHONY: generate build clean proto lint test

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod

# Build parameters
BINARY_NAME=cli
BINARY_PATH=./
BUILD_DIR=./bin

# Proto parameters
PROTO_DIR=../api/dm-manager
PROTO_FILE=$(PROTO_DIR)/dm-manager.proto

# Generate protobuf code

# Build the CLI
build:
	echo "Building $(BINARY_NAME)..."
	mkdir -p $(BUILD_DIR)
	$(GOBUILD) -o $(BUILD_DIR)/$(BINARY_NAME) $(BINARY_PATH)

# Build for multiple platforms
build-all: proto
	echo "Building for multiple platforms..."
	mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=amd64 $(GOBUILD) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 $(BINARY_PATH)
	GOOS=linux GOARCH=arm64 $(GOBUILD) -o $(BUILD_DIR)/$(BINARY_NAME)-linux-arm64 $(BINARY_PATH)
	GOOS=darwin GOARCH=amd64 $(GOBUILD) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 $(BINARY_PATH)
	GOOS=darwin GOARCH=arm64 $(GOBUILD) -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 $(BINARY_PATH)
	GOOS=windows GOARCH=amd64 $(GOBUILD) -o $(BUILD_DIR)/$(BINARY_NAME)-windows-amd64.exe $(BINARY_PATH)

# Clean build artifacts
clean:
	@echo "Cleaning..."
	$(GOCLEAN)
	rm -rf $(BUILD_DIR)
	rm -f $(PROTO_DIR)/*.pb.go


# Tidy modules
tidy:
	$(GOMOD) tidy

# Install dependencies
deps:
	$(GOGET) -u github.com/spf13/cobra@latest
	$(GOGET) -u google.golang.org/grpc@latest
	$(GOGET) -u google.golang.org/protobuf@latest

# Install protoc plugins
install-proto-tools:
	$(GOGET) -u google.golang.org/protobuf/cmd/protoc-gen-go@latest
	$(GOGET) -u google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest

# Run CLI with examples
run-examples:
	@echo "Running example commands..."
	./$(BUILD_DIR)/$(BINARY_NAME) --help
	./$(BUILD_DIR)/$(BINARY_NAME) report-amt-status --help
	./$(BUILD_DIR)/$(BINARY_NAME) retrieve-activation-details --help
	./$(BUILD_DIR)/$(BINARY_NAME) report-activation-results --help

# Install CLI globally
install: build
	cp $(BUILD_DIR)/$(BINARY_NAME) /usr/local/bin/

# Default target
all: clean tidy build test