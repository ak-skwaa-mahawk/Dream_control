#!/usr/bin/env bash
set -euo pipefail

ROOTFS_DIR="$(pwd)/rootfs_tree"
OUTPUT_TAR="sovr-rootfs-aarch64.tar.gz"
OUTPUT_CPIO="sovr-initramfs-aarch64.cpio.gz"
DOWNLOAD_URL="https://dl-cdn.alpinelinux.org/alpine/latest-stable/releases/aarch64/alpine-minirootfs-3.24.0-aarch64.tar.gz"

mkdir -p "${ROOTFS_DIR}"

if [ ! -d "${ROOTFS_DIR}/bin" ]; then
    if [ -f "sovr-rootfs-aarch64.tar.gz" ]; then
        echo "=== [1/5] Using verified local baseline cache ==="
        tar -xzf sovr-rootfs-aarch64.tar.gz -C "${ROOTFS_DIR}"
    else
        echo "=== [1/5] Fetching verified baseline (~3.8 MB) ==="
        curl -f -L --connect-timeout 10 --retry 3 "${DOWNLOAD_URL}" -o miniroot.tar.gz
        tar -xzf miniroot.tar.gz -C "${ROOTFS_DIR}"
        rm -f miniroot.tar.gz
    fi
fi

echo "=== [3/5] Configuring DNS & Installing declarative package set ==="
mkdir -p "${ROOTFS_DIR}/etc" "${ROOTFS_DIR}/tmp"
echo "nameserver 1.1.1.1" > "${ROOTFS_DIR}/etc/resolv.conf"

cp packages.list "${ROOTFS_DIR}/tmp/"
cp configure-system.sh "${ROOTFS_DIR}/tmp/"

mkdir -p "${ROOTFS_DIR}/appliance"
cp admission_gate.toml ingress_firewall.py firecrawl_ingress.py notarizer_signer.py test_handshake_harness.py smoke_runner.sh gate_dataport_reader "${ROOTFS_DIR}/appliance/"
mkdir -p "${ROOTFS_DIR}/appliance/include" "${ROOTFS_DIR}/appliance/boot"
cp include/sovr_phoneme_engine.h "${ROOTFS_DIR}/appliance/include/"
cp src/boot/sovr_kernel.elf "${ROOTFS_DIR}/appliance/boot/"
cp guest_sovr_agent.py guest_uio_transport.py ZkRelayerDaemon.ts "${ROOTFS_DIR}/appliance/"
chmod +x "${ROOTFS_DIR}"/appliance/*.py

# Align default config search path for guest
sed -i 's|/data/data/com.termux/files/usr/bin|/usr/bin|g' "${ROOTFS_DIR}/appliance/admission_gate.toml"

if [ -d "$HOME/admission-gate" ]; then
    mkdir -p "${ROOTFS_DIR}/tmp/admission-gate-src"
    cp -r "$HOME/admission-gate/"* "${ROOTFS_DIR}/tmp/admission-gate-src/"
fi

unset LD_PRELOAD

proot \
  -0 \
  -r "${ROOTFS_DIR}" \
  -w / \
  --link2symlink \
  -b /dev \
  -b /proc \
  -b /sys \
  /bin/sh -c '
    export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
    apk update
    apk add --no-cache $(cat /tmp/packages.list) py3-pip
    /bin/sh /tmp/configure-system.sh
    if [ -d /tmp/admission-gate-src ]; then
        pip install --no-cache-dir --break-system-packages /tmp/admission-gate-src
        rm -rf /tmp/admission-gate-src
    fi
    rm -f /tmp/packages.list /tmp/configure-system.sh
'

# Create root /init entrypoint
cp root_init.sh "${ROOTFS_DIR}/init"
chmod +x "${ROOTFS_DIR}/init"

echo "=== [4/5] Packing deterministic rootfs image ==="
tar -czf "${OUTPUT_TAR}" -C "${ROOTFS_DIR}" .
sha256sum "${OUTPUT_TAR}" > "${OUTPUT_TAR}.sha256"

echo "=== [5/5] Generating bootable initramfs cpio.gz ==="
(cd "${ROOTFS_DIR}" && find . | cpio -o -H newc | gzip -9 > "../${OUTPUT_CPIO}")
sha256sum "${OUTPUT_CPIO}" > "${OUTPUT_CPIO}.sha256"

rm -rf "${ROOTFS_DIR}"

echo ""
echo "=========================================================="
echo "[+] Appliance rootfs and initramfs generated successfully:"
echo "    Rootfs Tar:    $(pwd)/${OUTPUT_TAR}"
echo "    Initramfs:     $(pwd)/${OUTPUT_CPIO}"
echo "=========================================================="
