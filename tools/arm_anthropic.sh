#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SECRETS_DIR="$ROOT_DIR/.secrets"
KEY_FILE="$SECRETS_DIR/anthropic_api_key"

mkdir -p "$SECRETS_DIR"
chmod 700 "$SECRETS_DIR"

if [[ -t 0 && -t 1 ]]; then
  printf 'Anthropic API key: ' >&2
  stty -echo
  IFS= read -r api_key
  stty echo
  printf '\n' >&2
else
  IFS= read -r api_key
fi

api_key="${api_key#"${api_key%%[![:space:]]*}"}"
api_key="${api_key%"${api_key##*[![:space:]]}"}"

if [[ -z "$api_key" ]]; then
  echo "no key provided" >&2
  exit 1
fi

printf '%s\n' "$api_key" > "$KEY_FILE"
chmod 600 "$KEY_FILE"

echo "armed: $KEY_FILE"
