# HAProxy Docker Image

A high-performance HAProxy Docker image with QUIC support, automated SSL/TLS certificate management, and flexible configuration options.

> [!NOTE]  
> Credits to the haproxy team and any one whos contributed to it.

> [!WARNING]  
> If you plan to use this docker then please take note that I have a day job and two little kids at home so free time for these projects are rare, so any support needed could take some time. There are other dockers out there so concider the support issue if you plan to use this package.
> I am also open to any pull request to contribute to the project when time is available to test and review.

## Table of Contents

1. [Features](#features)
2. [Quick Start](#quick-start)
3. [Configuration](#configuration)
    - [YAML Structure](#yaml-structure)
    - [Full YAML Example](#full-yaml-example)
4. [Environment Variables](#environment-variables)
5. [Volumes](#volumes)
6. [Ports](#ports)
7. [Security Configuration](#security-configuration)
    - [Required Secrets](#required-secrets)
    - [Optional Settings](#optional-settings)
8. [ACME Configuration](#acme-configuration)
    - [DNS Challenge Setup](#dns-challenge-setup)
    - [HTTP Challenge Setup](#http-challenge-setup)
9. [Advanced Usage](#advanced-usage)
    - [Custom Certificates](#custom-certificates)
    - [Healthcheck Configuration](#healthcheck-configuration)
10. [Building the Image](#building-the-image)
11. [Troubleshooting](#troubleshooting)

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
      - CONFIG_AUTO_GENERATE_DEBUG=false
    restart: unless-stopped
```

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| ACME_EMAIL | Yes | - | Email for Let's Encrypt registration |
| ACME_CHALLENGE_TYPE | No | dns_cf | Challenge type (dns_cf/http) |
| DEBUG | No | false | Enable debug logging |
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
-e DEBUG=true
```
