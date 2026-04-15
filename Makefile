# SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
#
# SPDX-License-Identifier: EUPL-1.2

SHELL := /bin/bash

.PHONY: copy-tokens verify-tokens fix-permissions help verify-docker build-verify copyright

# Target 1: Copy the tokens
copy-tokens:
	@echo "Copying tokens from container..."
	docker compose cp hsm-worker:/myuser/softhsm/tokens softhsm-tokens
	@echo "Copy complete."

# Target 2: Verify the copy worked
verify-tokens:
	@echo "Verifying host directory contents:"
	ls -la softhsm-tokens/

# Target 3: Fix permissions (using UID 1000 as an example)
# Run this if you get "Permission Denied" errors on the host
fix-permissions:
	@echo "Fixing permissions..."
	sudo chown -R $(shell id -u):$(shell id -g) softhsm-tokens
	@echo "Permissions fixed."

copyright:
	git ls-files -z -- '*.rs' '*.toml' '*.sh' '*.yaml' '*.yml' '*.py' 'Makefile' '*Makefile' '*Dockerfile' '*Containerfile' 'justfile' | \
		xargs -0 reuse annotate \
			--license EUPL-1.2 \
			--copyright "Digg - Agency for Digital Government" \
			--year "$$(date +%Y)" \
			--skip-unrecognised \
			--skip-existing
	reuse lint

# Run `just verify` inside a container (no local tooling required)
build-verify:
	docker build -t hsm-verify -f ci/Dockerfile .

verify-docker: build-verify
	docker run --rm -v "$(CURDIR):/src" hsm-verify

# Standard Docker Compose helpers
up:
	docker compose up -d

build:
	docker compose build

down:
	docker compose down

logs:
	docker compose logs -f hsm-worker

# Display this help message
help:
	@echo "Available targets:"
	@grep -E '^[a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'
