#!/usr/bin/env bash
# EmberVault Remote Proxy Deploy Shortcut
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
export DEPLOY_ROLE="2"
exec bash "$SCRIPT_DIR/embervault_sync_and_deploy.sh" "$@"
