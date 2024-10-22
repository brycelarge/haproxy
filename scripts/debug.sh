#!/usr/bin/with-contenv bash

# Function to output debug messages if debugging is enabled
debug_log() {
    # Get debug setting
    debug_enabled=$(echo "${DEBUG:-false}" | tr 'A-Z' 'a-z')

    # Check if debug is enabled (true)
    if [ "$debug_enabled" = "true" ]; then
        echo "[Debug] $1" | ts '%Y-%m-%d %H:%M:%S'
    fi
}

# If script is run directly, process the argument
if [ "$0" = "/scripts/debug.sh" ]; then
    debug_log "$1"
fi
