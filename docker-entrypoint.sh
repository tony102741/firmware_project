#!/bin/sh
set -e

# Install payload-dumper-go into the expected project path if not already present.
# The binary lives at /opt/tools/ so it survives any volume mount on /workspace.
DUMPER_DST="/workspace/tools/payload-dumper-go/payload-dumper-go"
DUMPER_SRC="/opt/tools/payload-dumper-go"

if [ ! -f "$DUMPER_DST" ]; then
    mkdir -p "$(dirname "$DUMPER_DST")"
    cp "$DUMPER_SRC" "$DUMPER_DST"
    chmod +x "$DUMPER_DST"
fi

exec "$@"
