#!/usr/bin/env sh
set -eu

PROJECT_ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
cd "$PROJECT_ROOT"

mkdir -p inputs runs .cache tools

if [ ! -d .venv ]; then
  python3 -m venv .venv
fi

# shellcheck disable=SC1091
. .venv/bin/activate

python3 -m pip install -r requirements.txt

cat > .mcp.json <<EOF
{
  "mcpServers": {
    "ghidra": {
      "command": "$PROJECT_ROOT/tools/run-ghidra-mcp.sh",
      "args": []
    }
  }
}
EOF

printf '\nBootstrap complete.\n'
printf 'Next command:\n'
printf '  . scripts/env.sh\n'
printf '  scripts/check-env.sh\n'
