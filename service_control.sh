#!/usr/bin/env bash
set -euo pipefail

PID_FILE="/data/data/com.termux/files/home/sovereign-appliance/relayer.pid"
PIPE_PATH="/data/data/com.termux/files/home/sovereign-appliance/state_queue.pipe"
LOG_FILE="/data/data/com.termux/files/home/sovereign-appliance/relayer.log"

start() {
    if [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
        echo "[!] ZkRelayerDaemon is already running (PID $(cat "$PID_FILE"))."
        return 0
    fi

    [ -p "$PIPE_PATH" ] || { rm -f "$PIPE_PATH"; mkfifo "$PIPE_PATH"; }

    echo "[*] Launching ZkRelayerDaemon..."
    nohup npx tsx /data/data/com.termux/files/home/sovereign-appliance/ZkRelayerDaemon.ts > "$LOG_FILE" 2>&1 &
    DAEMON_PID=$!
    echo "$DAEMON_PID" > "$PID_FILE"
    echo "[+] Daemon started with PID $DAEMON_PID (logging to $LOG_FILE)."
}

stop() {
    if [ -f "$PID_FILE" ]; then
        PID="$(cat "$PID_FILE")"
        echo "[*] Stopping ZkRelayerDaemon (PID $PID)..."
        kill -9 "$PID" 2>/dev/null || true
        rm -f "$PID_FILE"
    fi
    pkill -9 -f "ZkRelayerDaemon" 2>/dev/null || true
    echo "[+] Stopped."
}

status() {
    if [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
        echo "[+] ZkRelayerDaemon active (PID $(cat "$PID_FILE"))."
    else
        echo "[-] ZkRelayerDaemon inactive."
    fi
}

case "${1:-}" in
    start)  start ;;
    stop)   stop ;;
    restart) stop; sleep 1; start ;;
    status) status ;;
    *) echo "Usage: $0 {start|stop|restart|status}" ; exit 1 ;;
esac
