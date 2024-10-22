#!/bin/sh
set -e

# Check if HAProxy is running
if ! pgrep haproxy > /dev/null; then
    echo "HAProxy is not running"
    exit 1
fi

# Check if HAProxy is listening on port 80 (or your configured port)
if ! nc -z localhost 80; then
    echo "HAProxy is not listening on port 80"
    exit 1
fi

echo "HAProxy is healthy"
exit 0