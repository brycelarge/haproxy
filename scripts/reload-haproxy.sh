#!/bin/sh

SOCKET="/var/lib/haproxy/admin.sock"
PID_FILE="/var/run/haproxy/haproxy.pid"
TIMEOUT=30

# Function to run socket commands as HAProxy user
run_as_haproxy() {
    s6-setuidgid haproxy "$@"
}

# Function to check HAProxy status
check_haproxy() {
    run_as_haproxy echo "show info" | run_as_haproxy socat stdio "unix-connect:$SOCKET" > /dev/null 2>&1
    return $?
}

# Check prerequisites
if [ ! -S "$SOCKET" ]; then
    echo "[Haproxy] Error: HAProxy admin socket not found at $SOCKET" | ts '%Y-%m-%d %H:%M:%S'
    exit 1
fi

if [ ! -f "$PID_FILE" ]; then
    echo "[Haproxy] Error: HAProxy PID file not found at $PID_FILE" | ts '%Y-%m-%d %H:%M:%S'
    exit 1
fi

# Store old PID
OLD_PID=$(cat "$PID_FILE")
if [ -z "$OLD_PID" ]; then
    echo "[Haproxy] Error: PID file is empty" | ts '%Y-%m-%d %H:%M:%S'
    exit 1
fi

if ! kill -0 "$OLD_PID" 2>/dev/null; then
    echo "[Haproxy] Error: HAProxy process (PID: $OLD_PID) is not running" | ts '%Y-%m-%d %H:%M:%S'
    exit 1
fi

# Perform soft reload
echo "[Haproxy] Initiating soft reload..." | ts '%Y-%m-%d %H:%M:%S'
if ! run_as_haproxy echo "reload" | run_as_haproxy socat stdio "unix-connect:$SOCKET"; then
    EXIT_CODE=$?
    echo "[Haproxy] Error: Failed to trigger reload (exit code: $EXIT_CODE)" | ts '%Y-%m-%d %H:%M:%S'
    exit 1
fi

# Wait for new PID file and verify process
count=0
while [ $count -lt $TIMEOUT ]; do
    if [ -f "$PID_FILE" ]; then
        NEW_PID=$(cat "$PID_FILE")
        if [ "$NEW_PID" != "$OLD_PID" ] && kill -0 "$NEW_PID" 2>/dev/null; then
            if check_haproxy; then
                echo "[Haproxy] Successfully reloaded (Old PID: $OLD_PID, New PID: $NEW_PID)" | ts '%Y-%m-%d %H:%M:%S'
                exit 0
            fi
        fi
    fi
    count=$((count + 1))
    sleep 1
done

echo "[Haproxy] Error: Reload timed out after $TIMEOUT seconds" | ts '%Y-%m-%d %H:%M:%S'
exit 1