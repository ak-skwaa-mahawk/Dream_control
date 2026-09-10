#!/usr/bin/env bash
set -euo pipefail

case "${1:-daemon}" in
  test)
    exec python3 -W error::ResourceWarning -m unittest discover -s tests -v
    ;;
  daemon)
    shift || true
    exec python3 -u core/dream_daemon.py \
      --workspace "/var/dream/workspace" \
      --seed-bank "/var/dream/seeds/seed_bank.json" \
      --harness-tree "/app/harnesses" \
      "$@"
    ;;
  *)
    exec "$@"
    ;;
esac
