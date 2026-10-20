#!/usr/bin/env bash
set -euo pipefail

ELF="src/boot/sovr_kernel.elf"

echo "=== Verifying Freestanding Kernel ELF Architecture ==="

if [ ! -f "$ELF" ]; then
    echo "[-] Error: $ELF not found."
    exit 1
fi

ENTRY_ADDR=$(llvm-readelf -h "$ELF" | awk '/Entry point address:/ {print $4}')
echo "[1] Entry Point Address: $ENTRY_ADDR"

INTERP_COUNT=$(llvm-readelf -l "$ELF" | grep -c "INTERP" || true)
echo "[2] Dynamic Interp Header Count: $INTERP_COUNT"
if [ "$INTERP_COUNT" -ne 0 ]; then
    echo "[-] Failure: ELF has dynamic interpreter headers."
    exit 1
fi

DATAPORT_ADDR=$(llvm-readelf -s "$ELF" | awk '$8 == "_sovr_shared_dataport" {print "0x"$2}')
echo "[3] Shared Dataport Address: $DATAPORT_ADDR"

if [ -n "$DATAPORT_ADDR" ]; then
    ALIGN_CHECK=$(( DATAPORT_ADDR % 4096 ))
    if [ "$ALIGN_CHECK" -eq 0 ]; then
        echo "[+] Dataport is strictly 4096-byte hardware page aligned."
    else
        echo "[-] Failure: Dataport is misaligned: offset $ALIGN_CHECK"
        exit 1
    fi
fi

echo "[+] SUCCESS: Freestanding sovereign kernel binary verified."
