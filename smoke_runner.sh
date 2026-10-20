#!/bin/sh
mount -t devtmpfs devtmpfs /dev
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t tmpfs tmpfs /tmp
mkdir -p /dev/pts
mount -t devpts devpts /dev/pts

export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

echo "=========================================="
echo " Running Automated Smoke Test Suite"
echo "=========================================="

cd /appliance
./test_handshake_harness.py
STATUS=$?

if [ -x /appliance/gate_dataport_reader ]; then
    echo "[4/4] Verifying Dataport Vector via In-Guest CAmkES Reader..."
    /appliance/gate_dataport_reader /appliance/workspace/harness_approval.bin /appliance/workspace/notary_keys
    if [ $? -ne 0 ]; then
        STATUS=1
    fi
fi

if [ $STATUS -eq 0 ]; then
    echo "=== SMOKE_TEST_PASS ==="
else
    echo "=== SMOKE_TEST_FAIL ==="
fi

poweroff -f
