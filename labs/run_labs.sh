#!/usr/bin/env bash

set -u

ROOT="$(cd "$(dirname "$0")" && pwd)"

echo
echo "======================================================"
echo "                 VULNFORGE LABS"
echo "======================================================"
echo
echo "  CRITICAL"
echo "    ShopCart  http://127.0.0.1:9001"
echo
echo "  HIGH"
echo "    QuickCart http://127.0.0.1:9002"
echo
echo "  MEDIUM"
echo "    MegaMart  http://127.0.0.1:9003"
echo
echo "======================================================"
echo

if ! python -c "import flask" >/dev/null 2>&1; then
    echo "[ERROR] Flask is not installed."
    echo
    echo "Run:"
    echo "  python -m pip install 'Flask>=3,<4'"
    exit 1
fi

pids=()

python "$ROOT/critical/authorization/shopcart/app.py" &
pids+=("$!")

python "$ROOT/high/injection/quickcart/app.py" &
pids+=("$!")

python "$ROOT/medium/business_logic/megamart/app.py" &
pids+=("$!")

sleep 1

echo
echo "[+] Services started."
echo
echo "Browser:"
echo "  CRITICAL -> http://127.0.0.1:9001"
echo "  HIGH     -> http://127.0.0.1:9002"
echo "  MEDIUM   -> http://127.0.0.1:9003"
echo

cleanup() {
    echo
    echo "[*] Stopping labs..."

    for pid in "${pids[@]}"; do
        kill "$pid" 2>/dev/null || true
    done
}

trap cleanup EXIT INT TERM

wait
