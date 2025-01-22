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
  yourusername/haproxy:latest
```

### Using Docker Compose

```yaml
version: '3.8'
services:
  haproxy:
    image: yourusername/haproxy:latest
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

### Basic Configuration Structure
```yaml
# /config/haproxy.yaml
global:
  - ssl-default-bind-ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384
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
    - redirect scheme https code 301 if !{ ssl_fc }

backend:
  example_backend:
    - mode http
    - balance roundrobin
    - option httpchk GET /health
    - server server1 10.0.0.1:8080 check
    - server server2 10.0.0.2:8080 check
```

### Advanced Configuration with SSL and QUIC
```yaml
# /config/haproxy.yaml
global:
  - ssl-default-bind-ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256
  - ssl-default-bind-options no-sslv3 no-tlsv10 no-tlsv11 no-tls-tickets
  - tune.ssl.default-dh-param 2048
  - tune.quic.socket-owner haproxy

frontend:
  http:
    - bind "${HAPROXY_BIND_IP}:80"
    - mode http
    - redirect scheme https code 301 if !{ ssl_fc }

  https:
    - bind "${HAPROXY_BIND_IP}:443" ssl crt /config/certs/ alpn h2,http/1.1
    - bind "quic4@:443" ssl crt /config/certs/ alpn h3
    - mode http
    - http-request set-header X-Forwarded-Proto https
    - acl host_example hdr(host) -i example.com
    - use_backend example_backend if host_example

backend:
  example_backend:
    - mode http
    - balance roundrobin
    - option httpchk
    - http-check send meth GET uri /health
    - server web1 192.168.1.10:8080 check ssl verify none
    - server web2 192.168.1.11:8080 check ssl verify none
```

### Configuration with Multiple Domains and SSL Offloading
```yaml
# /config/haproxy.yaml
global:
  - ssl-default-bind-ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256
  - tune.ssl.default-dh-param 2048

frontend:
  https:
    - bind "${HAPROXY_BIND_IP}:443" ssl crt /config/certs/ alpn h2,http/1.1
    - mode http
    - option httplog
    - acl host_app1 hdr(host) -i app1.example.com
    - acl host_app2 hdr(host) -i app2.example.com
    - use_backend app1_backend if host_app1
    - use_backend app2_backend if host_app2

backend:
  app1_backend:
    - mode http
    - balance roundrobin
    - option httpchk
    - server app1_1 10.0.0.10:8080 check
    - server app1_2 10.0.0.11:8080 check

  app2_backend:
    - mode http
    - balance roundrobin
    - option httpchk
    - server app2_1 10.0.0.20:8080 check
    - server app2_2 10.0.0.21:8080 check
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
  - ssl-default-bind-ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384
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
    - redirect scheme https code 301 if !{ ssl_fc }

backend:
  example_backend:
    - mode http
    - balance roundrobin
    - option httpchk GET /health
    - server server1 10.0.0.1:8080 check
    - server server2 10.0.0.2:8080 check
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

## Advanced Usage

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
