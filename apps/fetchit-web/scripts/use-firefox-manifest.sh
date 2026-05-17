#!/usr/bin/env bash
# Swap manifest.json for the Firefox-targeted variant.
#
# Why: Chrome MV3 forbids `background.scripts`; Firefox MV3 (151 and below)
# rejects `background.service_worker` by default. The two can't share one
# manifest. We ship the Chrome form as manifest.json (the common case) and
# manifest.firefox.json as the Firefox variant. This script swaps them in
# place so Firefox's about:debugging can load the extension.
#
# Reversible — re-run with `restore` (or `git checkout manifest.json`) to
# go back to the Chrome form.
set -euo pipefail

cd "$(dirname "$0")/.."

case "${1:-firefox}" in
  firefox)
    cp manifest.firefox.json manifest.json
    echo "manifest.json is now the Firefox variant. Reload via about:debugging."
    ;;
  chrome|chromium|restore)
    git checkout manifest.json
    echo "manifest.json restored to the Chrome variant. Reload via chrome://extensions."
    ;;
  *)
    echo "usage: $0 [firefox|chrome|restore]" >&2
    exit 1
    ;;
esac
