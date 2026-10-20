#!/bin/sh
exec qemu-system-aarch64 \
  -M virt \
  -cpu max \
  -m 512M \
  -smp 2 \
  -nographic \
  -kernel ./vmlinuz-virt \
  -initrd ./sovr-initramfs-aarch64.cpio.gz \
  -append "console=ttyAMA0 quiet"
