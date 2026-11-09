# Makefile for regauth / reguser

BINDIR             ?= bin
PREFIX             ?= /usr/local
DESTDIR            ?=
INSTALL_DIR        ?= $(DESTDIR)$(PREFIX)/bin
COMPLETION_DIR     ?= $(DESTDIR)/etc/bash_completion.d

GO                 ?= go
GOFLAGS            ?=
LDFLAGS            ?= -s -w

VERSION            := $(shell cat internal/tools/VERSION 2>/dev/null | tr -d '[:space:]')
# Ожидаемая версия Go из go.mod (строка "go 1.25.0" -> 1.25.0)
GO_EXPECTED        := $(shell awk '$$1=="go"{print $$2; exit}' go.mod 2>/dev/null)

.PHONY: all check build static test install install-completion uninstall clean help

all: build

## check: проверить наличие Go, сравнить установленную и ожидаемую версии, вывести версию проекта
check:
	@command -v $(GO) >/dev/null 2>&1 || { echo "error: go not found in PATH"; exit 1; }
	@GO_INSTALLED=$$($(GO) env GOVERSION | sed 's/^go//'); \
	GO_INSTALLED=$${GO_INSTALLED%%-*}; \
	GO_EXPECTED="$(GO_EXPECTED)"; \
	if [ -z "$$GO_EXPECTED" ]; then \
	    echo "go:      $$($(GO) version) (expected: unknown, go.mod missing 'go' directive)"; \
	else \
	    echo "go:      go$$GO_INSTALLED (expected: go$$GO_EXPECTED)"; \
	    if ! printf '%s\n%s\n' "$$GO_EXPECTED" "$$GO_INSTALLED" | sort -V -C; then \
	        echo "error: installed Go $$GO_INSTALLED is older than required $$GO_EXPECTED (go.mod)"; \
	        exit 1; \
	    fi; \
	fi
	@echo "version: $(VERSION)"

## build: собрать оба бинарника (динамически) в $(BINDIR)
build: check
	$(GO) mod tidy
	@mkdir -p $(BINDIR)
	$(GO) build $(GOFLAGS) -trimpath -ldflags "$(LDFLAGS)" -o $(BINDIR)/regauth ./cmd/regauth
	$(GO) build $(GOFLAGS) -trimpath -ldflags "$(LDFLAGS)" -o $(BINDIR)/reguser ./cmd/reguser
	@echo "built: $(BINDIR)/regauth $(BINDIR)/reguser (v$(VERSION))"

## static: пересобрать те же бинарники статически (CGO_ENABLED=0)
static: check
	$(GO) mod tidy
	@mkdir -p $(BINDIR)
	CGO_ENABLED=0 $(GO) build $(GOFLAGS) -trimpath -ldflags "$(LDFLAGS)" -o $(BINDIR)/regauth ./cmd/regauth
	CGO_ENABLED=0 $(GO) build $(GOFLAGS) -trimpath -ldflags "$(LDFLAGS)" -o $(BINDIR)/reguser ./cmd/reguser
	@echo "built: $(BINDIR)/regauth $(BINDIR)/reguser (static, v$(VERSION))"

## test: запустить юнит-тесты (с -race и -v)
test: check
	$(GO) mod tidy
	$(GO) test -race -v ./...

## install: установить бинарники в $(INSTALL_DIR) (по умолчанию /usr/local/bin)
install: build
	@mkdir -p $(INSTALL_DIR)
	install -m 0755 $(BINDIR)/regauth $(INSTALL_DIR)/regauth
	install -m 0755 $(BINDIR)/reguser $(INSTALL_DIR)/reguser
	@echo "installed to $(INSTALL_DIR)"

## install-completion: установить bash-completion в $(COMPLETION_DIR) (по умолчанию /etc/bash_completion.d)
install-completion:
	@mkdir -p $(COMPLETION_DIR)
	install -m 0644 completions/regauth.bash $(COMPLETION_DIR)/regauth
	install -m 0644 completions/reguser.bash $(COMPLETION_DIR)/reguser
	@echo "completions installed to $(COMPLETION_DIR)"

## uninstall: удалить установленные бинарники и completion-файлы
uninstall:
	rm -f $(INSTALL_DIR)/regauth
	rm -f $(INSTALL_DIR)/reguser
	rm -f $(COMPLETION_DIR)/regauth
	rm -f $(COMPLETION_DIR)/reguser
	@echo "removed binaries from $(INSTALL_DIR) and completions from $(COMPLETION_DIR)"

## clean: удалить артефакты сборки и сгенерированные файлы
clean:
	rm -rf $(BINDIR)
	rm -f config.yaml accounts.yaml keystore.yaml
	rm -f public-v2.key public-v3.key
	rm -f .tmp-*
	@echo "cleaned"

## help: показать список целей
help:
	@echo "Usage: make <target>"
	@echo ""
	@echo "Targets:"
	@echo "  check              Check Go toolchain, compare installed vs required, print version"
	@echo "  build              Build dynamic binaries into $(BINDIR)/"
	@echo "  static             Build static binaries (CGO_ENABLED=0) into $(BINDIR)/"
	@echo "  test               Run unit tests with -race and -v"
	@echo "  install            Install binaries to $(INSTALL_DIR) (default: /usr/local/bin)"
	@echo "  install-completion Install bash completions to $(COMPLETION_DIR) (default: /etc/bash_completion.d)"
	@echo "  uninstall          Remove installed binaries and completions"
	@echo "  clean              Remove build artifacts and generated files"
	@echo "  help               Show this help"
	@echo ""
	@echo "Variables:"
	@echo "  PREFIX=$(PREFIX)   DESTDIR=$(DESTDIR)"
	@echo "  BINDIR=$(BINDIR)"
	@echo "  INSTALL_DIR=$(INSTALL_DIR)"
	@echo "  COMPLETION_DIR=$(COMPLETION_DIR)"
	@echo "  GO=$(GO)           GOFLAGS=$(GOFLAGS)   LDFLAGS=$(LDFLAGS)"
