#!/bin/bash
set -e

# Check if token is already initialized
if ! softhsm2-util --show-slots | grep -q "wallet-keys"; then
  echo "Initializing SoftHSM token..."
  softhsm2-util --init-token --slot 0 --label "wallet-keys" \
    --so-pin "${SO_PIN}" --pin "${USER_PIN}"
else
  echo "SoftHSM token already initialized, skipping..."
fi

# Execute the main command
exec "$@"
