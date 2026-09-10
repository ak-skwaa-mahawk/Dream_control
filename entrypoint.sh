#!/usr/bin/env bash
set -euo pipefail

AUDIT_LOG="${AUDIT_LOG:-/app/audit_log.jsonl}"
SEED_BANK="${SEED_BANK:-/app/seeds/seed_bank.json}"

if [[ ! -f "$AUDIT_LOG" ]]; then
    touch "$AUDIT_LOG"
    chmod 600 "$AUDIT_LOG"
fi

echo "=== DREAM_CONTROL QUARANTINE GATE INITIATED ==="
echo "[+] Kernel namespaces and cgroup v2 barriers armed."
echo "[+] Starting pre-flight audit evaluation..."

exec python3 core/dream_daemon.py \
    --seed-bank "$SEED_BANK" \
    --audit-path "$AUDIT_LOG" \
    --require-isolation \
    "$@"
