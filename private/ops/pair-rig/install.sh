#!/bin/bash
# install.sh — install the pair-rig systemd --user units.
#
# Idempotent: copies units into ~/.config/systemd/user/, reloads,
# enables, and starts. Re-run after editing units to pick up changes.
#
# Pre-reqs:
#   - x0xd already runs once standalone so the data dir + api-token
#     exist at ~/.local/share/x0x-claude-here/
#   - fetchit-chat-peer compiled at
#     ~/Desktop/etchit-fetchit/fetchit/target/debug/fetchit-chat-peer
#   - claude-chat-peer-start installed at ~/.local/bin/
#   - passphrase file at ~/.local/share/fetchit-claude-peer/passphrase
#
# Usage:
#   bash private/ops/pair-rig/install.sh
#   bash private/ops/pair-rig/install.sh --uninstall

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
UNIT_DIR="${HOME}/.config/systemd/user"
BIN_DIR="${HOME}/.local/bin"
UNITS=(x0xd-claude-here.service fetchit-chat-peer-claude.service)
# Wrappers installed under ~/.local/bin/. claude-chat-peer-start is
# the ExecStart target of the chat-peer unit; claude-tx-send is the
# operator's outbound entry point that appends to the chat-peer's
# `--outbox-file`. Both are versioned here so a fresh box can be
# stood up from a single clone + install.sh run.
WRAPPERS=(claude-chat-peer-start claude-tx-send)

uninstall() {
  for u in "${UNITS[@]}"; do
    systemctl --user stop "$u" 2>/dev/null || true
    systemctl --user disable "$u" 2>/dev/null || true
    rm -f -- "$UNIT_DIR/$u"
  done
  for w in "${WRAPPERS[@]}"; do
    rm -f -- "$BIN_DIR/$w"
  done
  systemctl --user daemon-reload
  echo "uninstalled."
}

install() {
  mkdir -p -- "$UNIT_DIR" "$BIN_DIR"
  for w in "${WRAPPERS[@]}"; do
    install -m 0755 -- "$HERE/$w" "$BIN_DIR/$w"
  done
  for u in "${UNITS[@]}"; do
    install -m 0644 -- "$HERE/$u" "$UNIT_DIR/$u"
  done
  systemctl --user daemon-reload
  for u in "${UNITS[@]}"; do
    # `reenable` (vs `enable`) recreates symlinks each time so a
    # WantedBy addition in the unit file (e.g. the chat-peer unit's
    # WantedBy=x0xd-claude-here.service that closes the
    # BindsTo-cascade-stop-but-not-start gap) materializes correctly.
    systemctl --user reenable "$u"
    systemctl --user restart "$u"
  done
  sleep 2
  for u in "${UNITS[@]}"; do
    systemctl --user is-active --quiet "$u" \
      && echo "  $u: active" \
      || echo "  $u: INACTIVE — check journalctl --user -u $u"
  done
}

case "${1:-install}" in
  install)   install ;;
  --uninstall|uninstall) uninstall ;;
  *) echo "usage: $0 [install|--uninstall]" >&2; exit 2 ;;
esac
