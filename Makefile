BINARY_NAME      := threatintel
BUILD_DIR        := ./bin
CONFIG           ?= ./config/local/config.yaml
GOLANGCI_VERSION := v2.11.4

.PHONY: all build run-local clean install-lint fmt lint test-unit test-coverage generate check-generate

all: lint test-unit build

build:
	go build -o $(BUILD_DIR)/$(BINARY_NAME) ./cmd/threatintel

# make run-local CONFIG=./path/to/config.yaml — запуск с другим конфигом
run-local:
	go run ./cmd/threatintel -config=$(CONFIG)

clean:
	rm -rf $(BUILD_DIR) coverage

install-lint:
	@if command -v golangci-lint >/dev/null 2>&1 && golangci-lint --version 2>&1 | grep -q "$(subst v,,$(GOLANGCI_VERSION))"; then \
		echo "golangci-lint $(GOLANGCI_VERSION) already installed"; \
	else \
		echo "Installing golangci-lint $(GOLANGCI_VERSION)..."; \
		go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_VERSION); \
	fi

fmt: install-lint
	golangci-lint fmt ./...
	golangci-lint run --fix

lint: install-lint
	golangci-lint run

test-unit:
	go test -race -count=1 ./...

test-coverage:
	@mkdir -p coverage
	go test -race -count=1 -coverprofile=coverage/unit.out ./...
	go tool cover -func=coverage/unit.out | tail -1
	go tool cover -html=coverage/unit.out -o coverage/unit.html
	@echo "HTML report: coverage/unit.html"

generate:
	go generate ./...

check-generate:
	make generate
	git diff --exit-code internal/api