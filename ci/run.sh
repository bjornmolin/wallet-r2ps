#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Digg - Agency for Digital Government
#
# SPDX-License-Identifier: EUPL-1.2

# Clone the mounted source into a pristine worktree and run just verify.
# /src may be owned by a different uid on Linux hosts, so mark it safe first.

set -euo pipefail

git config --global --add safe.directory /src
branch=$(git -C /src rev-parse --abbrev-ref HEAD)
git clone --local --no-hardlinks --branch "$branch" /src /verify
git -C /verify remote set-head origin main
cd /verify && just verify
