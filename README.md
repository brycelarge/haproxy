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
10. [Advanced Usage](#advanced-usage)
    - [Custom Certificates](#custom-certificates)
    - [Healthcheck Configuration](#healthcheck-configuration)
    - [Firewall Port Forwarding (MIXED_SSL_MODE)](#firewall-port-forwarding-mixed_ssl_mode)
11. [Building the Image](#building-the-image)
12. [Troubleshooting](#troubleshooting)

## Features

- HAProxy 2.4+ with QUIC protocol support
- Automatic SSL/TLS certificate management via acme.sh
- Support for both Cloudflare DNS and HTTP ACME challenges
- YAML-based configuration system
- Dynamic backend configuration
- Comprehensive healthcheck system
- Alpine Linux base for minimal footprint
- s6-overlay for reliable process management
- Real-time SSL certificate updates without restart
- Support for multiple domains and certificates
- Automatic certificate renewal

## Quick Start

### Using Docker Run

```bash
docker run -d \
  --name haproxy \
  -p 80:80 \
  -p 443:443 \
  -v /path/to/config:/config \
  -e CF_Token=your-cloudflare-api-token \
  -e CF_Account_ID=your-cloudflare-account-id \
  -e CF_Zone_ID=your-cloudflare-zone-id \
  -e ACME_EMAIL=your-email@example.com \
  brycelarge/haproxy:latest
```

### Using Docker Compose

```yaml
version: '3.8'
services:
  haproxy:
    image: brycelarge/haproxy:latest
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./config:/config
    environment:
      - CF_Token=${CF_Token}
      - CF_Account_ID=${CF_Account_ID}
      - CF_Zone_ID=${CF_Zone_ID}
      - ACME_EMAIL=${ACME_EMAIL}
      - ACME_CHALLENGE_TYPE=dns_cf
      - HA_DEBUG=false
    restart: unless-stopped
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
    - bind *:80 user haproxy group haproxy
    - default_backend web-backend

  https:
    - bind *:443 user haproxy group haproxy
    - default_backend secure-backend

  # IP-restricted frontend example
  https-offloading-ip-protection:
    - default_backend restricted-backend
    - acl network_allowed src 192.168.1.0/24
    - acl from_allowed_ip req.hdr(X-Forwarded-For) -m ip 192.168.1.0/24
    - http-request deny unless from_allowed_ip or network_allowed

  https-offloading:
    - default_backend web-backend

# Domain Rules
https_frontend_rules:
  # Standard domains
  - backend: frontend-offloading
    match_type: ssl_fc_sni_end
    domains:
      - .example.com
      - .company.com
  
  # IP-protected domains
  - backend: frontend-offloading-ip-protection
    match_type: ssl_fc_sni
    domains:
      - restricted.example.com
      - admin.example.com

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
  - domain: restricted.example.com
    frontend: https-offloading-ip-protection
    backend: restricted-service

  # Standard web service
  - domain: www.example.com
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
```

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
    server_address: 192.168.1.10:80
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
    server_address: 192.168.1.20:8080
```

3. **SSL Backend**
```yaml
backends:
  - name: secure-service
    mode: http
    server_address: 192.168.1.30:443
    ssl: true
    ssl_verify: false
```

## Configuration

### YAML Structure

The YAML configuration file is used to define the HAProxy configuration. The file is divided into several sections:

* `global`: Global settings for HAProxy
* `defaults`: Default settings for HAProxy
* `frontend`: Frontend configuration for HAProxy
* `backend`: Backend configuration for HAProxy

### Full YAML Example

```yaml
# /config/haproxy.yaml
global:
  - tune.ssl.default-dh-param 2048
  - tune.quic.socket-owner haproxy
  - ssl-default-bind-ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256
  - ssl-default-bind-options no-sslv3 no-tlsv10 no-tlsv11 no-tls-tickets

defaults:
  - timeout connect 5s
  - timeout client 50s
  - timeout server 50s
  - option forwardfor
  - option http-server-close

frontend:
  http:
    - bind "${HAPROXY_BIND_IP}:80"
    - mode http
    - option httplog
    - option forwardfor
    - acl is_acme path_beg /.well-known/acme-challenge/
    - use_backend acme_backend if is_acme
    - redirect scheme https if !is_acme

  https:
    - bind "${HAPROXY_BIND_IP}:443" ssl crt /config/certs/ alpn h2,http/1.1
    - bind "quic4@:443" ssl crt /config/certs/ alpn h3
    - mode http
    - http-response set-header alt-svc "h3=\":443\"; ma=86400"
    - option httplog
    - option forwardfor
    - http-request set-header X-Forwarded-Proto https

backend:
  app1_backend:
    - mode http
    - timeout_connect: 5s
    - timeout_server: 30s
    enable_h2: true
    ssl: true
    ssl_verify: true
    hosts:
      - name: web1
        address: "192.168.1.10:8443"
        check: true
        ssl: true
      - name: web2
        address: "192.168.1.11:8443"
        check: true
        ssl: true

  acme_backend:
    - mode http
    - timeout_connect: 5s
    - timeout_server: 30s
    hosts:
      - name: acme
        address: "127.0.0.1:8080"
        check: false
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
| 443/8443 | UDP | QUIC protocol (HTTP/3) - Port 8443 is used when MIXED_SSL_MODE=true |

## Security Configuration

### Optional Settings

```yaml
security_options:
  - no-new-privileges:true
  - seccomp=unconfined
```

## ACME Configuration

### DNS Challenge Setup

1. **Create Cloudflare API Token**:
   - Go to Cloudflare Dashboard → Profile → API Tokens
   - Create token with `Zone:DNS:Edit` permissions
   - Note down the token, Account ID, and Zone ID


2. **Configure Environment**:
   - Take the information from steps taken above and add it to your config/acme/acme.sh.env file.

#### config/acme/acme.sh.env file will be generated on the first boot when acme is installed, then shutdown the container and add the above to the file in the format shown below.

```
export CF_Token=your_token
export CF_Account_ID=your_cf_account_id
export export CF_Zone_ID=your_cf_zone_id

# Alternative Cloudflare settings
export CF_Key=your_cf_key
export CF_Email=your_cf_email
```

### HTTP Challenge Setup

1. **Configure Environment**:
   ```bash
   -e ACME_CHALLENGE_TYPE=http \
   -e ACME_EMAIL=your-email@example.com
   ```

2. **Ensure Port 80 is Accessible**:
   ```bash
   -p 80:80
   ```

### Domain Configuration

To specify domains for ACME certificate management, you need to:

1. Define your domains in the YAML configuration
2. Set up the appropriate ACME challenge method

#### Example with Cloudflare DNS Challenge
```yaml
# /config/haproxy.yaml
frontend:
  https:
    - bind "${HAPROXY_BIND_IP}:443" ssl crt /config/certs/ alpn h2,http/1.1
    - bind "quic4@:443" ssl crt /config/certs/ alpn h3
    - mode http
    - acl host_app1 hdr(host) -i app1.example.com
    - acl host_app2 hdr(host) -i app2.example.com
    - use_backend app1_backend if host_app1
    - use_backend app2_backend if host_app2
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

### Firewall Port Forwarding (MIXED_SSL_MODE)

When running in MIXED_SSL_MODE, HAProxy uses a split configuration to handle both traditional HTTPS and QUIC traffic. This is necessary because:

1. The main HTTPS frontend (`frontend https`) operates in TCP mode to handle SSL passthrough, which is required for certain features and optimizations
2. QUIC/HTTP3 requires a separate frontend in HTTP mode with SSL termination
3. Both protocols need to be accessible on the standard HTTPS port (443) from the client's perspective

Due to this architecture:
- The TCP frontend binds directly to port 443 for SSL passthrough
- The QUIC frontend must bind to a different port (8443) to avoid conflict
- External clients must still connect to port 443 for both protocols

To achieve this, your firewall needs to direct traffic differently based on protocol while maintaining the appearance of a single port externally. Here's how to set it up:

#### pfSense Configuration

1. Navigate to `Firewall > NAT > Port Forward`
2. Add two rules:

**Rule 1 - TCP Traffic:**
- Protocol: TCP
- Source: any
- Destination Port Range: 443
- Redirect Target IP: [Your HAProxy Host IP]
- Redirect Target Port: 443
- Description: HAProxy HTTPS

**Rule 2 - UDP/QUIC Traffic:**
- Protocol: UDP
- Source: any
- Destination Port Range: 443
- Redirect Target IP: [Your HAProxy Host IP]
- Redirect Target Port: 8443
- Description: HAProxy QUIC

#### Other Firewalls

For other firewalls/routers, you need to configure:
1. Forward TCP port 443 → [HAProxy Host]:443
2. Forward UDP port 443 → [HAProxy Host]:8443

This setup ensures that:
- Regular HTTPS traffic (TCP/443) goes directly to HAProxy on port 443
- QUIC/HTTP3 traffic (UDP/443) is redirected to HAProxy's QUIC port 8443

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
