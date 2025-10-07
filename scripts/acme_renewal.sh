#!/usr/bin/with-contenv bash
# shellcheck shell=bash

source /scripts/acme_functions.sh
source /scripts/debug.sh

LOG_FILE="/var/log/acme-renewals.log"

echo "[acme-renewal] Entering periodic certificate renewal loop" | ts '%Y-%m-%d %H:%M:%S'

while true; do
    # Sleep for 12 hours between checks (43200 seconds)
    # This provides twice-daily checks which matches your original schedule
    debug_log "[acme-renewal] Sleeping for 12 hours before next check" | ts '%Y-%m-%d %H:%M:%S'
    sleep 43200

    echo "[acme-renewal] Running periodic certificate renewal check" | ts '%Y-%m-%d %H:%M:%S' >> "$LOG_FILE" 2>&1

    # Process certificates for renewal, redirecting all output to log file
    if check_for_missing_domain_certs "no" >> "$LOG_FILE" 2>&1; then
        echo "[acme-renewal] Periodic certificate check completed successfully" | ts '%Y-%m-%d %H:%M:%S' >> "$LOG_FILE" 2>&1
    else
        echo "[acme-renewal] Periodic certificate check failed" | ts '%Y-%m-%d %H:%M:%S' >> "$LOG_FILE" 2>&1
    fi
done
