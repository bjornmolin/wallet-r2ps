#!/bin/bash
set -e

# Check if token is already initialized
if ! softhsm2-util --show-slots | grep -q "${PKCS11_SLOT_TOKEN_LABEL}"; then
  echo "Initializing SoftHSM token..."
  softhsm2-util --init-token --slot 0 --label "${PKCS11_SLOT_TOKEN_LABEL}" \
    --so-pin "${PKCS11_SO_PIN}" --pin "${PKCS11_USER_PIN}"
else
  echo "SoftHSM token already initialized, skipping..."
fi

# Execute the main command
exec "$@"
