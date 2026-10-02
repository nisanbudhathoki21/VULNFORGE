#!/usr/bin/env bash
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

if [ "$#" -gt 0 ]; then
    exec python3 -m vulnforge "$@"
fi

exec python3 -m vulnforge dashboard
