#!/bin/sh

SOCKET="/var/lib/haproxy/admin.sock"
PID_FILE="/var/run/haproxy/haproxy.pid"
TIMEOUT=30

source /scripts/debug.sh

# Ensure script has proper permissions
if [ "$(stat -c %a $0)" != "775" ]; then
    chmod 775 "$0"
fi

# Ensure socket has proper permissions
if [ -S "$SOCKET" ]; then
    chmod 660 "$SOCKET"
    chown haproxy:haproxy "$SOCKET"
fi

# Function to check HAProxy status
check_haproxy() {
    if [ "$HA_DEBUG_ENABLED" = "1" ]; then
        echo "show info" | socat stdio "unix-connect:$SOCKET"
    else
        echo "show info" | socat stdio "unix-connect:$SOCKET" >/dev/null 2>&1
    fi
    return $?
}

# Check prerequisites
if [ ! -S "$SOCKET" ]; then
    echo "[Haproxy] Error: HAProxy admin socket not found at $SOCKET" | ts '%Y-%m-%d %H:%M:%S'
    exit 1
fi

# Validate the configuration first
debug_log "Validating configuration..."
if ! haproxy -c -f /config/haproxy.cfg >/dev/null 2>&1; then
    echo "[Haproxy] Error: Configuration validation failed" | ts '%Y-%m-%d %H:%M:%S'
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

# Start new HAProxy process and pass the old PID for graceful shutdown
if ! haproxy -f /config/haproxy.cfg -p "$PID_FILE" -sf "$OLD_PID" >/dev/null 2>&1; then
    EXIT_CODE=$?
    echo "[Haproxy] Error: Failed to trigger reload (exit code: $EXIT_CODE)" | ts '%Y-%m-%d %H:%M:%S'
    exit 1
fi

# Wait for new PID file and verify process
count=0
while [ $count -lt $TIMEOUT ]; do
    if [ -f "$PID_FILE" ]; then
        NEW_PID=$(cat "$PID_FILE")
        debug_log "Current PID file content: $NEW_PID"
        if [ "$NEW_PID" != "$OLD_PID" ] && kill -0 "$NEW_PID" 2>/dev/null; then
            debug_log "New process detected with PID $NEW_PID"
            if check_haproxy; then
                echo "[Haproxy] Successfully reloaded (Old PID: $OLD_PID → New PID: $NEW_PID)" | ts '%Y-%m-%d %H:%M:%S'
                exit 0
            else
                debug_log "check_haproxy failed for new process"
            fi
        else
            debug_log "Either PID hasn't changed or new process not running"
        fi
    else
        debug_log "PID file not found"
    fi
    count=$((count + 1))
    sleep 1
done

echo "[Haproxy] Error: Reload timed out after $TIMEOUT seconds" | ts '%Y-%m-%d %H:%M:%S'
exit 1