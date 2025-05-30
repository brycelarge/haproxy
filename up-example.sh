#!/bin/bash

# Define variables
NAME="haproxy"
DIR="$(pwd)"

# Create required directories if they don't exist
mkdir -p $DIR/data $DIR/data/logs $DIR/data/deployed-certs

# Stop and remove existing container if it exists
docker stop $NAME 2>/dev/null
docker rm $NAME 2>/dev/null

# Run HAProxy container
docker run -d \
    --name=$NAME \
    --restart unless-stopped \
    --security-opt no-new-privileges:true \
    -p 80:80 \
    -p 443:443 \
    --network=host \
    -v $DIR/data:/config \
    -v $DIR/data/logs:/var/log/haproxy \
    -v $DIR/data/deployed-certs:/etc/haproxy/certs \
    -e "MIXED_SSL_MODE=true" \
    -e "HA_DEBUG=false" \
    -e "HAPROXY_THREADS=16" \
    -e "CONFIG_AUTO_GENERATE=true" \
    -e "ACME_CHALLENGE_TYPE=http" \
    -e "ACME_EMAIL=your-email@example.com" \
    docker.io/brycelarge/haproxy:latest

# Show container logs
echo "Container started. Showing logs..."
docker logs -f $NAME
