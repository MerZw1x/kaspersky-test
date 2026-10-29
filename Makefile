BINARY_NAME      := threatintel
BUILD_DIR        := ./bin
CONFIG           ?= ./config/local/config.yaml
GOLANGCI_VERSION := v2.11.4
GOLANGCI_LINT    := $(BUILD_DIR)/tools/golangci-lint

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
	@if [ -x "$(GOLANGCI_LINT)" ] && "$(GOLANGCI_LINT)" --version 2>&1 | grep -q "$(subst v,,$(GOLANGCI_VERSION))"; then \
		echo "golangci-lint $(GOLANGCI_VERSION) already installed"; \
	else \
		echo "Installing golangci-lint $(GOLANGCI_VERSION)..."; \
		GOBIN="$(abspath $(BUILD_DIR)/tools)" go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_VERSION); \
	fi

fmt: install-lint
	$(GOLANGCI_LINT) fmt ./...
	$(GOLANGCI_LINT) run --fix

lint: install-lint
	$(GOLANGCI_LINT) run

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
	@tmp=$$(mktemp); trap 'rm -f "$$tmp"' EXIT; \
	go -C tools/oapi-codegen tool oapi-codegen -config ../../api/oapi-codegen.yaml -o "$$tmp" ../../api/openapi.yaml && \
	cmp internal/api/api.gen.go "$$tmp" || { echo "Generated code is out of date: run make generate"; exit 1; }

.PHONY: test-integration
test-integration:
	go test -race -count=1 -tags=integration -timeout=3m ./internal/repository/postgres/...

.PHONY: up down logs
up:
	docker compose up --build --wait --wait-timeout 120

down:
	docker compose down

logs:
	docker compose logs -f app

.PHONY: certs up-tls
certs:
	@mkdir -p certs
	@test ! -e certs/server.key && test ! -e certs/server.crt || { echo "Certificates already exist in certs/"; exit 1; }
	openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 7 \
		-subj '/CN=localhost' -addext 'subjectAltName=DNS:localhost,IP:127.0.0.1' \
		-keyout certs/server.key -out certs/server.crt
	@chmod 644 certs/server.key certs/server.crt

up-tls:
	docker compose -f docker-compose.yaml -f docker-compose.tls.yaml up --build --wait --wait-timeout 120

.PHONY: lint-openapi verify
lint-openapi:
	npx -y @redocly/cli@1.34.5 lint api/openapi.yaml

verify: all check-generate test-integration lint-openapi
