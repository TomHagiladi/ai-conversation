#!/usr/bin/env bash
# Install Secret Guard into ~/.claude/
# Idempotent: safe to re-run.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLAUDE_DIR="${CLAUDE_DIR:-$HOME/.claude}"
HOOK_DIR="$CLAUDE_DIR/hooks"
SETTINGS="$CLAUDE_DIR/settings.json"

mkdir -p "$HOOK_DIR"

cp "$SCRIPT_DIR/secret-guard.py" "$HOOK_DIR/secret-guard.py"
chmod +x "$HOOK_DIR/secret-guard.py"
echo "✓ Installed $HOOK_DIR/secret-guard.py"

if [[ ! -f "$SETTINGS" ]]; then
  cp "$SCRIPT_DIR/settings.snippet.json" "$SETTINGS"
  echo "✓ Created $SETTINGS"
  echo
  echo "Done. Restart any open Claude Code session to load the hooks."
  exit 0
fi

if ! command -v jq >/dev/null 2>&1; then
  echo
  echo "⚠ jq not found. Cannot auto-merge into existing $SETTINGS."
  echo "  Manually merge the contents of settings.snippet.json into your settings.json,"
  echo "  or install jq and re-run this script."
  exit 1
fi

BACKUP="$SETTINGS.bak.$(date +%Y%m%d-%H%M%S)"
cp "$SETTINGS" "$BACKUP"
echo "✓ Backed up existing settings to $BACKUP"

TMP="$(mktemp)"
jq -s '.[0] as $cur | .[1] as $new
  | $cur
  | .hooks = ((.hooks // {}) as $h
      | $h
      | .UserPromptSubmit = (($h.UserPromptSubmit // []) + ($new.hooks.UserPromptSubmit // []))
      | .PreToolUse       = (($h.PreToolUse       // []) + ($new.hooks.PreToolUse       // []))
    )' "$SETTINGS" "$SCRIPT_DIR/settings.snippet.json" > "$TMP"

mv "$TMP" "$SETTINGS"
echo "✓ Merged hooks into $SETTINGS"
echo
echo "Done. Restart any open Claude Code session to load the hooks."
echo
echo "Optional LLM layer (slower but smarter):"
echo "  export SECRET_GUARD_LLM=1"
echo "  export ANTHROPIC_API_KEY=sk-ant-..."
echo "  pip install --user anthropic"
