#!/bin/bash

# Create required directories if they don't exist
mkdir -p ./config /var/log/haproxy

# Stop and remove existing container if it exists
docker stop haproxy 2>/dev/null
docker rm haproxy 2>/dev/null

# Run HAProxy container
docker run -d \
    --name haproxy \
    --restart unless-stopped \
    --security-opt no-new-privileges:true \
    --cap-add NET_BIND_SERVICE \
    -p 80:80 \
    -p 443:443 \
    -p 443:443/udp \
    -v "$(pwd)/config:/config" \
    -v "/var/log/haproxy:/var/log/haproxy" \
    -e HAPROXY_THREADS=4 \
    -e HAPROXY_BIND_IP=0.0.0.0 \
    -e CONFIG_AUTO_GENERATE=false \
    -e MIXED_SSL_MODE=true \
    -e HA_DEBUG=false \
    -e H3_29_SUPPORT=true \
    -e QUIC_MAX_AGE=86400 \
    -e ACME_EMAIL=your-email@example.com \
    brycelarge/haproxy:latest

# Show container logs
echo "Container started. Showing logs..."
docker logs -f haproxy
