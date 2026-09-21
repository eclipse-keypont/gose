# SPDX-FileCopyrightText: 2026 Thales Group and the gose Contributors
# SPDX-License-Identifier: MIT

.PHONY: all build vet test lint lint-fix govulncheck coverage notices clean version release

SRCS := $(wildcard *.go) $(wildcard jose/*.go)

all: clean build vet lint govulncheck coverage

# ── Tool preconditions ───────────────────────────────────────────────────────
# $(call require,<binary>,<how to install it>) — fail early with an install hint.
#
# Probes by running the tool, not `command -v`: a goenv shim stays on PATH even
# when the tool is not installed for the active Go version, so `command -v` says
# yes and the build dies later. Exit 127 (missing binary or dead shim) is the
# only status treated as missing; tools without --version exit 1 or 2 and pass.
#
# A hint must not contain a comma — make would read it as another $(call) argument.
define require
@$(1) --version >/dev/null 2>&1; \
if [ $$? -eq 127 ]; then \
    echo "$(1) not found. Install it with:"; \
    echo "  $(2)"; \
    exit 1; \
fi
endef

# ── Build ────────────────────────────────────────────────────────────────────
build:
	go build ./...

# ── Vet ──────────────────────────────────────────────────────────────────────
vet:
	go vet ./...

# ── Tests ────────────────────────────────────────────────────────────────────
test:
	go test -gcflags=-l -short -race ./...

coverage: coverage.out

coverage.out: $(SRCS)
	go test -gcflags=-l -coverprofile coverage.out ./...

# ── Lint ─────────────────────────────────────────────────────────────────────
# Runs golangci-lint (v2) against .golangci.yml — the same checks as the CI
# Lint workflow, so you can catch issues before pushing.
#
# Install the linter (v2, matching CI's `version: latest`):
#   go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest
# Ensure $(go env GOPATH)/bin is on your PATH, then `golangci-lint version`.
GOLANGCI_LINT ?= golangci-lint
GOLANGCI_LINT_INSTALL_HINT := go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest

lint:
	$(call require,$(GOLANGCI_LINT),$(GOLANGCI_LINT_INSTALL_HINT))
	$(GOLANGCI_LINT) run ./...

# Auto-fix the mechanically-fixable findings (formatting, some conversions):
lint-fix:
	$(call require,$(GOLANGCI_LINT),$(GOLANGCI_LINT_INSTALL_HINT))
	$(GOLANGCI_LINT) run --fix ./...

# ── Vulnerability scan ───────────────────────────────────────────────────────
# Runs govulncheck (reachability-aware, cross-checked against the Go vuln DB) —
# the same check as the CI govulncheck workflow (.github/workflows/govulncheck.yml).
#
# Install govulncheck:
#   go install golang.org/x/vuln/cmd/govulncheck@latest
GOVULNCHECK ?= govulncheck

govulncheck:
	$(call require,$(GOVULNCHECK),go install golang.org/x/vuln/cmd/govulncheck@latest)
	$(GOVULNCHECK) -show verbose ./...

## Licenses
# Generated via a temp file: redirecting straight into NOTICES.md truncates it
# to zero bytes whenever go-licenses fails, destroying the committed file before
# anyone sees the error. Write, then move only on success.
GO_LICENSES ?= go-licenses

notices:
	$(call require,$(GO_LICENSES),go install github.com/google/go-licenses@latest)
	@{ $(GO_LICENSES) report ./... --ignore github.com/eclipse-keypont/gose,github.com/eclipse-keypont/crypto11/v2,github.com/eclipse-keypont/pkcs11-go --template go-licenses.tpl > NOTICES.md.tmp && \
	   mv NOTICES.md.tmp NOTICES.md; } || { rm -f NOTICES.md.tmp; exit 1; }
	@echo "NOTICES.md generated"

# ── Clean ────────────────────────────────────────────────────────────────────
clean:
	go clean
	rm -f coverage.out

# ── Release ───────────────────────────────────────────────────────────────────
# Versioning is git-tag only — there is no in-repo version file/const to bump
# (unlike pkcs11-go, which derives its tag from cryptoki/version.go).
#
#   * Run: make release VERSION=0.14.0   (tags v0.14.0, signed, and pushes)
#   * Or:  make version                   (prints the most recent tag)
#
# The tag is created with `git tag -s` (GPG/SSH-signed, per your git signing
# config) so consumers can `git verify-tag v$VERSION`. `go get` consumers still
# rely on go.sum + sum.golang.org, not on any release assets.
version:
	@git describe --tags --abbrev=0 2>/dev/null || echo "no tags yet"

release:
	@if [ -z "$(VERSION)" ]; then \
	    echo ""; \
	    echo "Error: VERSION is not set."; \
	    echo ""; \
	    echo "Example:"; \
	    echo "  make release VERSION=0.14.0"; \
	    echo ""; \
	    exit 1; \
	fi
	git tag -s "v$(VERSION)" -m "Release v$(VERSION)"
	git push --tags
	@echo "Released v$(VERSION)"
