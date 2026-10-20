#!/usr/bin/env bash
set -euo pipefail

ADDR="0xB09D703E8DC8f4E8BB0Ec5D6FB40D96c23FEBf6e"
RPC="${SEPOLIA_RPC_URL:-https://rpc.sepolia.org}"
INTERVAL=15

echo "[*] Monitoring faucet funding for relayer: $ADDR"
echo "[*] Polling endpoint: $RPC (every ${INTERVAL}s)"

while true; do
    RESP=$(curl -s -X POST "$RPC" \
        -H "Content-Type: application/json" \
        -d "{
            \"id\": 1,
            \"jsonrpc\": \"2.0\",
            \"method\": \"eth_getBalance\",
            \"params\": [\"$ADDR\", \"latest\"]
        }")

    BAL_HEX=$(echo "$RESP" | grep -o '"result":"[^"]*"' | cut -d'"' -f4 || echo "0x0")

    if [ "$BAL_HEX" != "0x0" ] && [ -n "$BAL_HEX" ]; then
        echo -e "\n\033[32m[+] Faucet funds detected! Raw balance: $BAL_HEX\033[0m"
        echo "[*] Starting ZkRelayerDaemon in live dispatch mode..."
        /data/data/com.termux/files/home/sovereign-appliance/service_control.sh restart
        /data/data/com.termux/files/home/sovereign-appliance/service_control.sh status
        break
    else
        echo -ne "[-] Current balance: 0.0 ETH. Retrying in ${INTERVAL}s...\r"
    fi

    sleep "$INTERVAL"
done
