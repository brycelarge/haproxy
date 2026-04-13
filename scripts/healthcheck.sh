#!/bin/sh

TIMEOUT=3
HTTP_PORT=80
HTTPS_PORT=443
STATS_SOCKET="/var/lib/haproxy/admin.sock"
MAX_RETRIES=1

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

    # Check if we can communicate with HAProxy and it's actually responding
    if ! timeout 3 sh -c "echo 'show info' | socat '$STATS_SOCKET' stdio" | grep -q "Name: HAProxy" 2>/dev/null; then
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

        # Use openssl to check certificate validity (works on all systems)
        if ! openssl x509 -checkend 0 -noout -in "$cert" >/dev/null 2>&1; then
            echo "Certificate $cert has expired"
            return 1
        fi

        # Check if cert expires within warning_days (in seconds)
        warning_seconds=$((warning_days * 86400))
        if ! openssl x509 -checkend "$warning_seconds" -noout -in "$cert" >/dev/null 2>&1; then
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