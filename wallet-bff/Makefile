# SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
#
# SPDX-License-Identifier: EUPL-1.2

SHELL := /bin/bash

.PHONY: help check testcontainer all-tests coverage-setup coverage full-coverage

## Display available targets
help:
	@echo "Available targets:"
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/^## //' | while IFS= read -r desc; do \
		read -r target < <(grep -A1 "^## $${desc}$$" $(MAKEFILE_LIST) | tail -1); \
		printf "  \033[36m%-20s\033[0m %s\n" "$${target%%:*}" "$$desc"; \
	done

## format, build, test and run clippy
check:
	@set -e; \
	run() { \
		name="$$1"; shift; \
		tmp="$$(mktemp)"; \
		if "$$@" >"$$tmp" 2>&1; then \
			printf "\033[32m✓ %s\033[0m\n" "$$name"; \
		else \
			cat "$$tmp"; \
			rm -f "$$tmp"; \
			exit 1; \
		fi; \
		rm -f "$$tmp"; \
	}; \
	run fmt cargo fmt; \
	run test cargo test -q; \
	run clippy cargo clippy -q --all-targets -- -D warnings;

## Run all testContainer tests
testcontainer:
	cargo test -- --ignored --test-threads=1

## Run all tests (unit + integration + testContainer) in one go
all-tests:
	cargo test -- --include-ignored --test-threads=1

# Install cargo-llvm-cov and llvm-tools if not already present
coverage-setup:
	@cargo llvm-cov --version >/dev/null 2>&1 || cargo install cargo-llvm-cov
	@rustup component add llvm-tools-preview --toolchain stable 2>/dev/null || true

## Run unit tests only with llvm coverage report (Installs llvm-cov if needed)
coverage: coverage-setup
	cargo llvm-cov

## Run full test suite (including ignored integration tests) with llvm coverage report (Installs llvm-cov needed)
full-coverage: coverage-setup
	cargo llvm-cov --all-targets -- --include-ignored

