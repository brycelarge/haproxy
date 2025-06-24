# HAProxy Docker Image

A high-performance HAProxy Docker image with QUIC support, automated SSL/TLS certificate management, and flexible configuration options.

> [!NOTE]
> Credits to the haproxy team and any one whos contributed to it.

## Table of Contents

1. [Features](#features)
2. [Quick Start](#quick-start)
3. [YAML Configuration Examples](#yaml-configuration-examples)
4. [Configuration](#configuration)
    - [YAML Structure](#yaml-structure)
    - [YAML to Config Conversion](#yaml-to-config-conversion)
    - [Full YAML Example](#full-yaml-example)
5. [Environment Variables](#environment-variables)
6. [Volumes](#volumes)
7. [Ports](#ports)
8. [Security Configuration](#security-configuration)
    - [Required Secrets](#required-secrets)
    - [Optional Settings](#optional-settings)
9. [ACME Configuration](#acme-configuration)
    - [DNS Challenge Setup](#dns-challenge-setup)
    - [HTTP Challenge Setup](#http-challenge-setup)
    - [Domain Configuration](#domain-configuration)
10. [Architecture](#architecture)
    - [Service Structure](#service-structure)
    - [ACME HTTP-01 Challenge Implementation](#acme-http-01-challenge-implementation)
11. [HAProxy 3.2 Features](#haproxy-32-features)
    - [HTTP/2 and QUIC Improvements](#http2-and-quic-improvements)
    - [Performance Optimizations](#performance-optimizations)
    - [Implementation Details](#implementation-details)
12. [Advanced Usage](#advanced-usage)
    - [Custom Certificates](#custom-certificates)
    - [Healthcheck Configuration](#healthcheck-configuration)
    - [Firewall Port Forwarding (MIXED_SSL_MODE)](#firewall-port-forwarding-mixed_ssl_mode)
13. [Building the Image](#building-the-image)
14. [Troubleshooting](#troubleshooting)

## Features

### HAProxy 3.2 Features
- QUIC/HTTP3 protocol support
- Enhanced performance with optimized buffer handling
- HTTP/2 idle connection checking with `idle-ping`
- Connection reuse for health checks with `check-reuse-pool`
- Improved TLS performance with optimized SSL session cache
- TCP inspection improvements for complex TLS connections

### Certificate Management
- Automatic SSL/TLS certificate management via acme.sh
- Support for both Cloudflare DNS and HTTP ACME challenges
- Custom stick table implementation for HTTP-01 challenge validation
- Real-time certificate updates without HAProxy restart
- Automatic certificate renewal

### Configuration System
- YAML-based configuration with automatic conversion
- Dynamic backend configuration with multiple host support
- Comprehensive health check system with per-host configuration
- IP-restricted frontends for protected services

### Container Features
- Alpine Linux base for minimal footprint
- s6-overlay for reliable process management
- Structured service dependencies for proper startup sequence

## Quick Start

### Using Docker Run

```bash
docker run -d \
  --name haproxy \
  -p 80:80 \
  -p 443:443 \
  --network=host \
  -v /path/to/data:/config \
  -v /path/to/data/logs:/var/log/haproxy \
  -v /path/to/data/deployed-certs:/etc/haproxy/certs \
  -e "MIXED_SSL_MODE=true" \
  -e "HA_DEBUG=false" \
  -e "HAPROXY_THREADS=16" \
  -e "CONFIG_AUTO_GENERATE=true" \
  -e "ACME_CHALLENGE_TYPE=http" \
  -e "ACME_EMAIL=your-email@example.com" \
  docker.io/brycelarge/haproxy:latest
```

### Using Docker Compose

```yaml
version: '3.8'
services:
  haproxy:
    image: docker.io/brycelarge/haproxy:latest
    container_name: haproxy
    restart: unless-stopped
    network_mode: host  # Optional: Use host networking if needed
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./data:/config
      - ./data/logs:/var/log/haproxy
      - ./data/deployed-certs:/etc/haproxy/certs
    environment:
      - MIXED_SSL_MODE=true
      - HA_DEBUG=false
      - HAPROXY_THREADS=16
      - CONFIG_AUTO_GENERATE=true
      - ACME_CHALLENGE_TYPE=http
      - ACME_EMAIL=your-email@example.com
```

## YAML Configuration Examples

The configuration uses a YAML structure to define HAProxy settings. Here's a real-world example:

```yaml
# Basic Settings
global:  # Global HAProxy settings

defaults:
  - option http-keep-alive
  - timeout client 30s
  - timeout connect 5s
  - timeout server 90s

# Frontend Configurations
frontend:
  http:
    config:
      - bind *:80 user haproxy group haproxy
      - default_backend web-backend

  https:
    config:
      - bind *:443 user haproxy group haproxy
      - default_backend secure-backend
    domains:
      - backend: frontend-offloading
        patterns:
          - .example.com
          - .company.com

  # IP-restricted frontend example
  https-offloading-ip-protection:
    config:
      - default_backend restricted-backend
      - acl network_allowed src 192.168.1.0/24
      - acl from_allowed_ip req.hdr(X-Forwarded-For) -m ip 192.168.1.0/24
      - http-request deny unless from_allowed_ip or network_allowed
    domains:
      - backend: frontend-offloading-ip-protection
        patterns:
          - restricted.example.com
          - admin.example.com

  https-offloading:
    config:
      - default_backend web-backend

# Domain to Backend Mappings
The `domain_mappings` array serves two crucial purposes:
1. It defines the routing rules for HAProxy
2. It determines which SSL certificates to obtain via acme.sh

When the container starts, it reads this array to:
- Generate the necessary HAProxy configuration for each domain
- Automatically request and renew Let's Encrypt certificates for all listed domains
- Set up the proper SSL termination rules

domain_mappings:
  # IP-protected service
  - domains:
    - restricted.example.com
    frontend: https-offloading-ip-protection
    backend: restricted-service

  # Standard web service
  - domains:
    - www.example.com
    frontend: https-offloading
    backend: web-service

# Backend Definitions
backends:
  # TCP frontend for SSL passthrough
  - name: frontend-offloading
    mode: tcp
    timeout_connect: 5000
    timeout_server: 5000
    server_address: socket
    check:
      interval: 5000
      fall: 2
      rise: 3

  # IP-protected frontend
  - name: frontend-offloading-ip-protection
    mode: tcp
    timeout_connect: 5000
    timeout_server: 5000
    server_address: socket

  # Standard HTTP backend
  - name: web-service
    mode: http
    timeout_connect: 5000
    timeout_server: 5000
    server_address: 192.168.1.10:80

  # HTTPS backend with SSL
  - name: secure-service
    mode: http
    timeout_connect: 5000
    timeout_server: 5000
    server_address: 192.168.1.11:443
    ssl: true
    ssl_verify: false

### Configuration Sections Explained

1. **Basic Settings**
   - `global`: HAProxy global settings
   - `defaults`: Default timeouts and options

2. **Frontend Types**
   - `http`: Standard HTTP frontend (port 80)
   - `https`: Standard HTTPS frontend (port 443)
   - `https-offloading-ip-protection`: IP-restricted frontend
   - `https-offloading`: SSL termination frontend

3. **Domain Rules (`https_frontend_rules`)**
   - Define domain patterns for SSL handling
   - Support for wildcard domains (`.example.com`)
   - Different match types (`ssl_fc_sni_end`, `ssl_fc_sni`)

4. **Domain Mappings**
   - Map specific domains to backends
   - Support for both standard and IP-protected frontends

5. **Backend Types**
   - TCP mode for SSL passthrough
   - HTTP mode for standard web services
   - Support for SSL backends
   - Custom timeouts and health checks

### Common Use Cases

1. **Standard Web Service**
```yaml
domain_mappings:
  - domain: www.example.com
    frontend: https-offloading
    backend: web-service

backends:
  - name: web-service
    mode: http
    enable_h2: true  # Enable HTTP/2 with idle connection checks
    hosts:
      - "192.168.1.10:80"
```

2. **IP-Restricted Service**
```yaml
domain_mappings:
  - domain: admin.example.com
    frontend: https-offloading-ip-protection
    backend: admin-service

backends:
  - name: admin-service
    mode: http
    check:
      type: http
      uri: /health
      interval: 2000
      fall: 3
      rise: 2
    hosts:
      - "192.168.1.20:8080"
```

3. **SSL Backend**
```yaml
backends:
  - name: web-service
    mode: http
    enable_h2: true  # Automatically adds idle-ping 30s
    hosts:
      - "192.168.1.10:80"
```

4. **HTTP/2 Backend with Per-Host Configuration**
```yaml
backends:
  - name: advanced-service
    mode: http
    enable_h2: true  # Default for all hosts that don't specify it
    options:
      - "httpchk GET /health"
      - "allbackups"
    http_check:
      - "expect status 200"
    hosts:
      - host: "192.168.1.10:8090"  # Inherits enable_h2 from backend
        check:
          type: tcp
          interval: 1000
          fall: 2
          rise: 1
          slowstart: "10s"
      - host: "192.168.1.10:8081"
        enable_h2: false  # Override backend setting - HTTP/2 disabled for this host
        check:
          type: http
          uri: "/health"
      - "192.168.1.10:80 backup"  # Simple string format inherits backend enable_h2
```

5. **Mixed HTTP/2 Configuration**
```yaml
backends:
  - name: mixed-backend
    mode: http
    enable_h2: false  # HTTP/2 disabled by default
    hosts:
      - host: "192.168.1.10:8090"  # No HTTP/2 (inherits from backend)
      - host: "192.168.1.10:8081"
        enable_h2: true  # Explicitly enables HTTP/2 for this host only
      - "192.168.1.10:80"  # No HTTP/2 (inherits from backend)
```

5. **Multiple Hosts with Backup**
```yaml
backends:
  - name: secure-service
    mode: http
    ssl: true
    ssl_verify: false
    options:
      - "allbackups"  # Optional: if all servers marked as backup should be used together
    hosts:
      - "192.168.1.30:443"  # Primary server
      - "192.168.1.31:443 backup"  # Simple backup syntax
      - host: "192.168.1.32:443"  # Object syntax with backup
        backup: true
      - host: "192.168.1.33:443"  # Object syntax with weight
        backup: true
        weight: 10  # Higher weight gets more traffic when active
```

## Configuration

### YAML Structure

The YAML configuration file is used to define the HAProxy configuration. The file is divided into several sections:

* `global`: Global settings for HAProxy
* `defaults`: Default settings for HAProxy
* `frontend`: Frontend configuration for HAProxy
* `backend`: Backend configuration for HAProxy

### Full YAML Example

A comprehensive example configuration file is included in the repository as `haproxy.yaml.example`. This file demonstrates all the major features and can be used as a starting point for your own configuration:

```bash
cp haproxy.yaml.example /config/haproxy.yaml
# Then edit to match your environment
```

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| ACME_EMAIL | Yes | - | Email for Let's Encrypt registration |
| ACME_CHALLENGE_TYPE | No | dns_cf | Challenge type (dns_cf/http) |
| HA_DEBUG | No | false | Enable debug logging |
| TZ | No | UTC | Container timezone |

### Cloudflare API Authentication Methods

You can use either the newer API Token method or the legacy API Key method:

1. **API Token Method (Recommended)**:
   - Requires: `CF_Token`, `CF_Account_ID`, `CF_Zone_ID`
   - More secure with granular permissions
   - Can be easily revoked if compromised

2. **Legacy API Key Method**:
   - Requires: `CF_Email`, `CF_Key`
   - Full account access
   - Less secure but simpler setup

## Volumes

| Path | Purpose |
|------|---------|
| your_dir:/config | Configuration files, certificates, and YAML configuration |
| your_log_dir:/var/log/haproxy | HAProxy access and error logs |

## Ports

| Port | Protocol | Description |
|------|----------|-------------|
| 80 | TCP | HTTP traffic and ACME challenges |
| 443 | TCP | HTTPS traffic |
| 443 | UDP | QUIC protocol (HTTP/3) |

## Security Configuration

### Optional Settings

```yaml
security_options:
  - no-new-privileges:true
  - seccomp=unconfined
```

## ACME Configuration

This container includes automatic HTTPS certificate management using ACME protocol (Let's Encrypt). Two challenge types are supported:

### HTTP Challenge Setup (Recommended)

1. **Configure Environment**:
   ```bash
   -e ACME_CHALLENGE_TYPE=http \
   -e ACME_EMAIL=your-email@example.com
   ```

2. **Ensure Port 80 is Accessible**:
   ```bash
   -p 80:80
   ```

3. **How it Works**:
   - The container automatically configures HAProxy to handle ACME HTTP-01 challenges
   - Certificates are automatically renewed before expiration
   - No additional configuration needed beyond specifying domains in your YAML file

### DNS Challenge Setup (Alternative)

For scenarios where port 80 cannot be exposed, DNS challenge is available. Cloudflare DNS is supported:

1. **Create Cloudflare API Token**:
   - Go to Cloudflare Dashboard → Profile → API Tokens
   - Create token with `Zone:DNS:Edit` permissions
   - Note down the token, Account ID, and Zone ID

2. **Configure Environment**:
   ```bash
   -e ACME_CHALLENGE_TYPE=dns_cf \
   -e ACME_EMAIL=your-email@example.com
   ```

3. **Create acme.sh.env File**:
   - The file will be generated on first boot at `/config/acme/acme.sh.env`
   - Shutdown the container and add your Cloudflare credentials:

```
export CF_Token=your_token
export CF_Account_ID=your_cf_account_id
export CF_Zone_ID=your_cf_zone_id

# Alternative Cloudflare settings (if not using token)
# export CF_Key=your_cf_key
# export CF_Email=your_cf_email
```

### Domain Configuration

To specify domains for ACME certificate management, you need to define them in your YAML configuration:

```yaml
# /config/haproxy.yaml
domain_mappings:
  - domain: app1.example.com
    frontend: https-offloading
    backend: app1-backend

  - domain: app2.example.com
    frontend: https-offloading
    backend: app2-backend
```

```bash
# Environment variables in docker-compose.yml or docker run
environment:
  - ACME_EMAIL=your-email@example.com
  - ACME_CHALLENGE_TYPE=dns_cf
  - CF_Token=your_cloudflare_token
  - CF_Account_ID=your_cloudflare_account_id
  - CF_Zone_ID=your_cloudflare_zone_id
  - DOMAIN_LIST=app1.example.com,app2.example.com  # List of domains for certificate management
```

#### Example with HTTP Challenge
```yaml
# /config/haproxy.yaml
frontend:
  http:
    - bind "${HAPROXY_BIND_IP}:80"
    - mode http
    - acl is_acme path_beg /.well-known/acme-challenge/
    - use_backend acme_backend if is_acme
    - redirect scheme https if !is_acme

  https:
    - bind "${HAPROXY_BIND_IP}:443" ssl crt /config/certs/ alpn h2,http/1.1
    - mode http
    - acl host_app1 hdr(host) -i app1.example.com
    - use_backend app1_backend if host_app1

backend:
  acme_backend:
    - mode http
    - server acme_srv 127.0.0.1:8080
```

```bash
# Environment variables in docker-compose.yml or docker run
environment:
  - ACME_EMAIL=your-email@example.com
  - ACME_CHALLENGE_TYPE=http
  - DOMAIN_LIST=app1.example.com  # List of domains for certificate management
```

The container will automatically:
1. Request certificates for all domains listed in `DOMAIN_LIST`
2. Store certificates in `/config/certs/`
3. Automatically renew certificates before expiry
4. Reload HAProxy configuration when certificates are renewed

> [!NOTE]
> - Domains must be publicly accessible for ACME verification
> - For Cloudflare DNS challenge, ensure your API token has the correct zone permissions
> - For HTTP challenge, port 80 must be accessible from the internet

## Architecture

### Service Structure

This image uses s6-overlay to manage service dependencies and startup sequence:

1. **acme-setup**: Initializes the ACME environment
   - Downloads DH parameters for TLS
   - Installs acme.sh if not present
   - Registers with Let's Encrypt if needed
   - Configures cron jobs for renewals

2. **haproxy-config**: Generates HAProxy configuration
   - Converts YAML to HAProxy config when `CONFIG_AUTO_GENERATE=true`
   - Uses `/scripts/generate_haproxy_config.sh` for conversion

3. **rsyslog**: Sets up logging
   - Creates log socket at `/var/lib/haproxy/dev/log`
   - Configures log rotation

4. **haproxy**: Main HAProxy service
   - Depends on haproxy-config and rsyslog
   - Runs with proper capabilities for binding to privileged ports

5. **acme**: Certificate management
   - Runs after HAProxy is fully operational
   - Checks for missing certificates
   - Issues/renews certificates as needed
   - Updates HAProxy without restart

### ACME HTTP-01 Challenge Implementation

The container uses a custom stick table implementation for HTTP-01 challenges:

1. Domains are added to a stick table with `http_req_cnt` counter
2. ACLs check if the domain exists in the stick table
3. When a challenge arrives, HAProxy validates it against the stick table
4. This allows for dynamic certificate issuance without pre-configuration

## HAProxy 3.2 Features

This image leverages several HAProxy 3.2 performance and security enhancements:

### HTTP/2 and QUIC Improvements

- **HTTP/2 Idle Connection Checking**: The `idle-ping 30s` parameter automatically checks and closes unresponsive HTTP/2 connections
- **QUIC Protocol Support**: Native HTTP/3 support with optimized UDP handling
- **Connection Reuse for Health Checks**: The `check-reuse-pool` parameter reduces connection overhead by reusing idle connections

### Performance Optimizations

- **Enhanced TLS Performance**: Optimized SSL session caching with `tune.ssl.cachesize 100000` and `tune.ssl.lifetime 300`
- **TCP Inspection Improvements**: Increased inspection delay with `tcp-request inspect-delay 10s` for better TLS handling
- **Buffer Tuning**: Optimized buffer sizes with `tune.bufsize` and `tune.maxrewrite`

### Implementation Details

HTTP/2 can be configured with maximum flexibility:

1. **Backend Level**: Set `enable_h2: true|false` at the backend level as a default for all hosts
2. **Host Level**: Individual hosts can override the backend setting with their own `enable_h2: true|false`
3. **Mixed Configuration**: You can have some hosts with HTTP/2 and others without in the same backend

This works in both directions:
- Enable HTTP/2 at backend level, disable for specific hosts
- Disable HTTP/2 at backend level, enable for specific hosts

When HTTP/2 is enabled for a host, the script adds:
```
alpn h2 check-reuse-pool idle-ping 30s
```

This combines HTTP/2 protocol negotiation with idle connection checking and health check connection reuse. The flexible per-host configuration allows you to fine-tune HTTP/2 usage based on each server's capabilities.

## Advanced Usage

### SSL Certificate Management

The container automatically manages SSL certificates using acme.sh and Let's Encrypt. The process works as follows:

1. On container startup, the system reads the `domain_mappings` array
2. For each domain in the array:
   - Checks if a valid certificate exists
   - If not, requests a new certificate from Let's Encrypt
   - If yes, checks if renewal is needed
3. Certificates are stored in `/config/certs/`
4. Automatic renewal is handled by a cron job

Example domain mapping that will get an SSL certificate:
```yaml
domain_mappings:
  - domain: secure.example.com    # Certificate will be requested for this domain
    frontend: https-offloading
    backend: secure-backend
```

The container needs:
- Port 80 exposed for ACME HTTP challenges
- A valid email address set via `ACME_EMAIL` environment variable
- The domains to be properly pointed to your server

### MIXED_SSL_MODE and HTTP/3 Support

When running in MIXED_SSL_MODE, HAProxy uses a split configuration to handle both traditional HTTPS and QUIC/HTTP3 traffic. This is necessary because:

1. The main HTTPS frontend (`frontend https`) operates in TCP mode to handle SSL passthrough, which is required for certain features and optimizations
2. QUIC/HTTP3 requires a separate frontend in HTTP mode with SSL termination
3. Both protocols need to be accessible on the standard HTTPS port (443) from the client's perspective

Our container automatically handles all the necessary internal port forwarding to make this work seamlessly. You only need to:

1. Enable MIXED_SSL_MODE by setting the environment variable:
   ```
   -e "MIXED_SSL_MODE=true"
   ```

2. Expose port 443 for both TCP and UDP traffic:
   ```
   -p 443:443
   ```

No additional firewall configuration is required. The container will automatically set up the necessary internal routing to ensure that both HTTPS and HTTP/3 traffic work correctly on port 443.

### Custom Certificates

Place custom certificates in `/config/acme/certs/`:
```bash
/config/acme/certs/
├── example.com.pem
├── example.com.key
└── example.com.chain
```

### Healthcheck Configuration

Default healthcheck configuration:
```dockerfile
HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
    CMD /usr/local/bin/healthcheck.sh
```

## Troubleshooting

### Common Issues

1. **Certificate Issues**:
   ```bash
   # Check ACME logs
   docker exec haproxy cat /var/log/acme-renewals.log
   ```

2. **HAProxy Startup Failures**:
   ```bash
   # Check HAProxy logs
   docker exec haproxy cat /var/log/haproxy/haproxy.log
   ```

3. **Configuration Errors**:
   ```bash
   # Validate configuration
   docker exec haproxy haproxy -c -f /config/haproxy.cfg
   ```

### Debug Mode

Enable debug logging:
```bash
-e HA_DEBUG=true

```
