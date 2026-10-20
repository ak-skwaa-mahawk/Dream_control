#!/bin/sh
mount -t devtmpfs devtmpfs /dev 2>/dev/null || true
mount -t proc proc /proc 2>/dev/null || true
mount -t sysfs sysfs /sys 2>/dev/null || true
mount -t tmpfs tmpfs /tmp 2>/dev/null || true
mkdir -p /dev/pts
mount -t devpts devpts /dev/pts 2>/dev/null || true

export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# Check if automated smoke test requested via kernel parameters
if grep -q "smoke" /proc/cmdline 2>/dev/null; then
    echo "=========================================="
    echo " Sovereign Appliance Automated Smoke Test"
    echo "=========================================="
    cd /appliance
    ./test_handshake_harness.py
    STATUS=$?
    if [ $STATUS -eq 0 ]; then
        if [ -x /appliance/gate_dataport_reader ]; then
        echo "[4/4] Verifying Dataport Vector via In-Guest CAmkES Reader..."
        /appliance/gate_dataport_reader /appliance/workspace/harness_approval.bin /appliance/workspace/notary_keys
        if [ $? -ne 0 ]; then
            echo "[-] In-guest CAmkES verification failed"
            STATUS=1
        fi
    fi
    echo "=== SMOKE_TEST_PASS ===" 
    else
        echo "=== SMOKE_TEST_FAIL ==="
    fi
    poweroff -f
fi

echo "=========================================="
echo " Sovereign seL4 Appliance Shell Ready"
echo "=========================================="
exec /bin/sh
