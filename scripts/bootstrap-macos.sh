#!/usr/bin/env sh
set -eu

PROJECT_ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." >/dev/null && pwd -P)"
cd "$PROJECT_ROOT"

if grep -qiE "(microsoft|wsl)" /proc/version 2>/dev/null; then
  printf 'bootstrap-macos.sh is for macOS only.\n' >&2
  printf 'Current environment looks like WSL/Linux. Use scripts/check-env-wsl.sh instead.\n' >&2
  exit 1
fi

mkdir -p inputs runs .cache tools

if [ ! -d .venv ]; then
  python3 -m venv .venv
fi

# shellcheck disable=SC1091
. .venv/bin/activate

python3 -m pip install -r requirements.txt

if [ -f .mcp.json ]; then
  backup=".mcp.json.bak.$(date +%Y%m%d%H%M%S)"
  cp .mcp.json "$backup"
  printf 'Backed up existing .mcp.json to %s\n' "$backup"
fi

ghidra_mcp="$PROJECT_ROOT/tools/run-ghidra-mcp.sh"
if [ ! -x "$ghidra_mcp" ]; then
  printf 'Warning: %s is missing or not executable.\n' "$ghidra_mcp" >&2
  printf 'Writing .mcp.json anyway, but Ghidra MCP will not work until the local tool is installed.\n' >&2
fi

cat > .mcp.json <<EOF
{
  "mcpServers": {
    "ghidra": {
      "command": "$ghidra_mcp",
      "args": []
    }
  }
}
EOF

printf '\nBootstrap complete.\n'
printf 'Next command:\n'
printf '  . scripts/env.sh\n'
printf '  scripts/check-env.sh\n'
