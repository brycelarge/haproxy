#!/usr/bin/with-contenv bash

# Lock file path in memory
LOCK_FILE="/tmp/acme.lock"
source /scripts/debug.sh

# Function to acquire lock
acquire_lock() {
    local pid

    # Check if lock file exists
    if [ -f "$LOCK_FILE" ]; then
        pid=$(cat "$LOCK_FILE")
        
        # Check if process is still running
        if kill -0 "$pid" 2>/dev/null; then
            debug_log "Another ACME process is running (PID: $pid)" | ts '%Y-%m-%d %H:%M:%S'
            return 1
        else
            debug_log " Removing stale lock file" | ts '%Y-%m-%d %H:%M:%S'
            rm -f "$LOCK_FILE"
        fi
    fi

    # Create lock file with current PID
    echo $$ > "$LOCK_FILE"
    
    # Verify we got the lock
    if [ "$(cat "$LOCK_FILE")" != "$$" ]; then
        debug_log " Failed to acquire lock" | ts '%Y-%m-%d %H:%M:%S'
        return 1
    fi

    debug_log " Lock acquired" | ts '%Y-%m-%d %H:%M:%S'
    return 0
}

# Function to release lock
release_lock() {
    if [ -f "$LOCK_FILE" ] && [ "$(cat "$LOCK_FILE")" = "$$" ]; then
        rm -f "$LOCK_FILE"
        debug_log " Lock released" | ts '%Y-%m-%d %H:%M:%S'
        return 0
    fi
    return 1
}

# Function to ensure lock is released even if script fails
cleanup() {
    release_lock
    exit "${1:-0}"
}

# Updated wrapper function for ACME operations
with_lock() {
    local func_name="$1"
    shift  # Remove first argument, leaving remaining args for the function

    if ! acquire_lock; then
        return 1
    fi

    # Set up trap to release lock on script exit
    trap cleanup EXIT

    # Execute the requested function with its arguments
    "$func_name" "$@"
    local result=$?

    release_lock
    return $result
}

