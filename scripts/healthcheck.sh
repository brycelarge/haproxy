#!/bin/sh

TIMEOUT=5
HTTP_PORT=80
HTTPS_PORT=443
STATS_SOCKET="/var/lib/haproxy/admin.sock"
MAX_RETRIES=3

check_port() {
    local port=$1
    local protocol=$2
    local retries=0

    while [ $retries -lt $MAX_RETRIES ]; do
        if nc -z -w$TIMEOUT localhost "$port"; then
            return 0
        fi
        retries=$((retries + 1))
        [ $retries -lt $MAX_RETRIES ] && sleep 1
    done
    echo "Port $port ($protocol) is not responding after $MAX_RETRIES attempts"
    return 1
}

check_stats_socket() {
    if [ ! -S "$STATS_SOCKET" ]; then
        echo "Stats socket $STATS_SOCKET does not exist"
        return 1
    fi

    if ! echo "show info" | socat "$STATS_SOCKET" stdio > /dev/null 2>&1; then
        echo "Cannot communicate with HAProxy through stats socket"
        return 1
    fi
    return 0
}

check_certificates() {
    local warning_days=30
    local certs_dir="/etc/haproxy/certs"
    local has_warning=0

    if [ ! -d "$certs_dir" ]; then
        echo "Certificates directory does not exist"
        return 1
    fi

    for cert in "$certs_dir"/*.pem; do
        [ -f "$cert" ] || continue

        expiry=$(openssl x509 -enddate -noout -in "$cert" | cut -d= -f2)
        expiry_epoch=$(date -D "%b %d %T %Y %Z" -d "$expiry" +%s 2>/dev/null || date -j -f "%b %d %T %Y %Z" "$expiry" +%s 2>/dev/null)
        warning_epoch=$(date -d "+${warning_days} days" +%s 2>/dev/null || date -j -v "+${warning_days}d" +%s 2>/dev/null)

        if [ "$expiry_epoch" -lt "$(date +%s)" ]; then
            echo "Certificate $cert has expired"
            return 1
        elif [ "$expiry_epoch" -lt "$warning_epoch" ]; then
            echo "Warning: Certificate $cert will expire in less than $warning_days days"
            has_warning=1
        fi
    done

    return $has_warning
}

check_process() {
    local pid
    pid=$(pgrep haproxy) || { echo "HAProxy is not running"; return 1; }

    # Check if process is zombie
    if ps -p "$pid" -o state= | grep -q Z; then
        echo "HAProxy process is zombie"
        return 1
    fi

    # Check memory usage (warn if over 90% of available memory)
    local mem_percent
    mem_percent=$(ps -p "$pid" -o %mem= | tr -d ' ')
    if [ "${mem_percent%.*}" -gt 90 ]; then
        echo "Warning: HAProxy memory usage is high (${mem_percent}%)"
        return 2
    fi

    return 0
}

main() {
    local status=0

    # Check HAProxy process
    if ! check_process; then
        status=1
    fi

    # Check ports
    if ! check_port "$HTTP_PORT" "HTTP"; then
        status=1
    fi

    if ! check_port "$HTTPS_PORT" "HTTPS"; then
        status=1
    fi

    # Check stats socket
    if ! check_stats_socket; then
        status=1
    fi

    # Check certificates (warning doesn't fail the health check)
    cert_status=0
    check_certificates || cert_status=$?
    [ "$cert_status" -eq 1 ] && status=1

    if [ $status -eq 0 ]; then
        echo "HAProxy is healthy"
    else
        echo "HAProxy health check failed"
    fi

    return $status
}

main