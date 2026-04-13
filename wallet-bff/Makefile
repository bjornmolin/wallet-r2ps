# SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
#
# SPDX-License-Identifier: EUPL-1.2

SHELL := /bin/bash

.PHONY: check

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
