#!/usr/bin/with-contenv bash
# shellcheck shell=bash

# Define debug state based on environment variable
case "${HA_DEBUG}" in
    1|yes|true|TRUE|Yes|YES)
        HA_DEBUG_ENABLED=1
        ;;
    *)
        HA_DEBUG_ENABLED=0
        ;;
esac

# Debug logging function using the state variable
debug_log() {
    if [ "${HA_DEBUG_ENABLED}" = "1" ]; then
        echo "[Debug] $1"
    fi
}
