# brycelarge/haproxy

A self-contained Docker image that acts as a **TLS-terminating reverse proxy** for self-hosted infrastructure. It wraps HAProxy 3.4 (built with QUIC/HTTP3 support via quictls) with YAML-driven config generation and fully automated Let's Encrypt certificate management.

> [!NOTE]
> Credits to the HAProxy team and all contributors.

## Table of Contents

1. [How It Works](#how-it-works)
2. [Quick Start](#quick-start)
3. [SSL Modes](#ssl-modes)
    - [Standard Mode](#standard-mode)
    - [Mixed SSL Mode](#mixed-ssl-mode)
    - [IP Protection Mode](#ip-protection-mode)
4. [YAML Configuration Reference](#yaml-configuration-reference)
    - [global](#global)
    - [defaults](#defaults)
    - [frontend](#frontend)
    - [domain_mappings](#domain_mappings)
    - [backends](#backends)
5. [Environment Variables](#environment-variables)
6. [Certificate Management](#certificate-management)
    - [HTTP Challenge](#http-challenge)
    - [DNS Challenge (Cloudflare)](#dns-challenge-cloudflare)
7. [Architecture](#architecture)
8. [Troubleshooting](#troubleshooting)

## How It Works

On container startup the following happens in order:

1. **acme-setup** — installs acme.sh, downloads DH params, registers with Let's Encrypt
2. **haproxy-config** — reads `/config/haproxy.yaml`, runs `generate_haproxy_config.sh` to produce `/config/haproxy.cfg`
3. **rsyslog** — creates the log socket HAProxy writes to
4. **haproxy** — starts with the generated config
5. **acme** — issues/renews certificates for every domain in `domain_mappings`, hot-reloads HAProxy when certs change (no restart)

The `http` frontend (port 80) is fully managed — it handles ACME HTTP-01 challenges via a stick table and redirects everything else to HTTPS. You do not configure it in YAML.

---

## Quick Start

```yaml
# docker-compose.yml
services:
  haproxy:
    image: docker.io/brycelarge/haproxy:latest
    restart: unless-stopped
    network_mode: host
    volumes:
      - ./config:/config
      - ./config/logs:/var/log/haproxy
      - ./config/certs:/etc/haproxy/certs
    environment:
      - ACME_EMAIL=you@example.com
      - ACME_CHALLENGE_TYPE=http
      - CONFIG_AUTO_GENERATE=true
```

Create `/config/haproxy.yaml` (see [YAML Configuration Reference](#yaml-configuration-reference)) and start the container. Certificates are issued automatically on first boot.

---

## SSL Modes

### Standard Mode

`MIXED_SSL_MODE=false` (default) — HAProxy binds directly to `:443` and terminates TLS there. HTTP/3 QUIC also binds to UDP `:443`.

```
client → :443 TCP/UDP → https-offloading frontend → backend
```

### Mixed SSL Mode

`MIXED_SSL_MODE=true` — A TCP passthrough frontend binds to `:443`, inspects SNI, and forwards to an internal unix socket where TLS is terminated. Preserves the original client IP via PROXY protocol (`send-proxy-v2-ssl-cn`). HTTP/3 QUIC binds to UDP `:8443` internally.

```
client → :443 TCP → frontend https (tcp, SNI routing)
                       → unix socket → https-offloading (TLS termination) → backend
```

### IP Protection Mode

`FRONTEND_IP_PROTECTION=true` — Adds a second SSL offloading frontend (`https-offloading-ip-protection`) on a separate unix socket. Use it to restrict certain domains to specific source IPs. Add restriction rules via `frontend.https-offloading-ip-protection.raw` and map domains to it in `domain_mappings`.

---

## YAML Configuration Reference

Place your config at `/config/haproxy.yaml`. Use `haproxy.yaml.example` as a starting point:

```bash
cp haproxy.yaml.example /config/haproxy.yaml
```

### `global`

Raw HAProxy `global` directives appended to the generated global section.

```yaml
global:
  - maxconn 10000
  - tune.bufsize 32768
  - tune.ssl.cachesize 100000
```

### `defaults`

Raw HAProxy `defaults` directives.

```yaml
defaults:
  - option http-keep-alive
  - timeout client 30s
  - timeout connect 5s
  - timeout server 240s
  - timeout tunnel 43200s
```

### `frontend`

Optional raw directives injected into the generated frontend sections. The frontends themselves are fully generated — you only inject additional lines via `raw`.

| Key | Injected into |
|-----|--------------|
| `frontend.https-offloading.raw[]` | `frontend https-offloading` |
| `frontend.https-offloading-ip-protection.raw[]` | `frontend https-offloading-ip-protection` |
| `frontend.https.raw[]` | `frontend https` (MIXED_SSL_MODE only) |

```yaml
frontend:
  https-offloading:
    raw:
      - acl is_websocket hdr(Upgrade) -i WebSocket
      - http-request set-header Connection upgrade if is_websocket
      - http-request set-header Upgrade websocket if is_websocket

  https-offloading-ip-protection:
    raw:
      - acl allowed_src src 10.0.0.0/8
      - http-request deny unless allowed_src
    domains:
      - backend: frontend-offloading-ip-protection
        patterns:
          - admin.example.com
```

### `domain_mappings`

Maps domains to frontends and backends. **This is also the source of truth for which certificates acme.sh will issue** — every domain listed here gets a Let's Encrypt certificate automatically.

```yaml
domain_mappings:
  - domains:
    - example.com
    - www.example.com
    frontend: https-offloading
    backend: my-app

  - domains:
    - admin.example.com
    frontend: https-offloading-ip-protection
    backend: admin-app
```

### `backends`

Defines upstream servers.

**Backend fields:**

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `name` | string | required | Referenced by `domain_mappings` |
| `mode` | string | `http` | `http` or `tcp` |
| `ssl` | bool | `false` | Connect to upstream over SSL |
| `ssl_verify` | bool | `false` | Verify upstream SSL cert |
| `enable_h2` | bool | `false` | Enable HTTP/2 (`alpn h2 check-reuse-pool idle-ping 30s`) |
| `use_send_proxy` | bool | `false` | Send PROXY protocol to upstream |
| `cache` | bool | `false` | Enable response cache for images |
| `options` | list | — | Raw `option` directives |
| `http_check` | list | — | Raw `http-check` directives |
| `raw` | list | — | Raw HAProxy directives injected into the backend block |
| `hosts` | list | required | Upstream addresses |

**Host formats — simple string:**
```yaml
hosts:
  - "10.0.0.10:8080"
  - "10.0.0.11:8080 backup"
```

**Host formats — object with per-host health check:**
```yaml
hosts:
  - host: "10.0.0.10:8080"
    enable_h2: true
    check:
      type: http        # http | ssl | tcp
      uri: /health
      interval: 2000
      fall: 3
      rise: 2
      slowstart: "10s"
```

**Full backend example:**
```yaml
backends:
  - name: api
    mode: http
    enable_h2: true
    options:
      - "httpchk GET /health"
      - "allbackups"
    http_check:
      - "expect status 200"
    raw:
      - "http-request set-header Host api.example.com"
    hosts:
      - host: "10.0.0.10:8080"
        check:
          type: tcp
          interval: 1000
          fall: 2
          rise: 1
          slowstart: "10s"
      - "10.0.0.11:8080 backup"
```

---

## Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `ACME_EMAIL` | Yes | — | Email for Let's Encrypt registration |
| `ACME_CHALLENGE_TYPE` | No | `dns_cf` | `http` or `dns_cf` |
| `CONFIG_AUTO_GENERATE` | No | `false` | Regenerate config from YAML on startup |
| `MIXED_SSL_MODE` | No | `false` | Enable TCP passthrough + unix socket SSL offloading |
| `FRONTEND_IP_PROTECTION` | No | `false` | Enable IP-restricted SSL offloading frontend |
| `HAPROXY_BIND_IP` | No | `0.0.0.0` | IP address HAProxy binds to |
| `HAPROXY_THREADS` | No | — | Number of HAProxy threads |
| `H3_29_SUPPORT` | No | `false` | Include `h3-29` in `alt-svc` header |
| `QUIC_MAX_AGE` | No | `86400` | `alt-svc` max-age for HTTP/3 |
| `HA_DEBUG` | No | `false` | Enable debug logging in config generation |
| `TZ` | No | `EST` | Container timezone |

---

## Certificate Management

Certificates are stored in `/etc/haproxy/certs/` and managed by acme.sh. HAProxy is hot-reloaded when certificates change — no downtime.

Every domain listed in `domain_mappings` gets a certificate automatically. No extra configuration needed.

### HTTP Challenge

Port 80 must be reachable from the internet. HAProxy handles the ACME HTTP-01 challenge internally via a stick table — no separate backend or pre-hook needed.

```bash
ACME_CHALLENGE_TYPE=http
ACME_EMAIL=you@example.com
```

### DNS Challenge (Cloudflare)

Use when port 80 cannot be exposed. On first boot, `/config/acme/acme.sh.env` is created. Shut down the container, add your credentials, then restart:

```bash
# /config/acme/acme.sh.env
export CF_Token=your_token
export CF_Account_ID=your_account_id
export CF_Zone_ID=your_zone_id
```

```bash
ACME_CHALLENGE_TYPE=dns_cf
ACME_EMAIL=you@example.com
```

> [!NOTE]
> Cloudflare API token needs `Zone:DNS:Edit` permission.

---

## Architecture

### Volumes and Ports

| Volume | Purpose |
|--------|---------|
| `/config` | YAML config, generated `haproxy.cfg`, ACME state |
| `/var/log/haproxy` | HAProxy access and error logs |
| `/etc/haproxy/certs` | Deployed TLS certificates (symlinked from acme.sh output) |

| Port | Protocol | Purpose |
|------|----------|---------|
| 80 | TCP | HTTP + ACME HTTP-01 challenges |
| 443 | TCP | HTTPS |
| 443 | UDP | HTTP/3 QUIC |

### s6-overlay Service Order

```
acme-setup → haproxy-config → rsyslog → haproxy → acme
```

- **acme-setup** — installs acme.sh, downloads DH params, registers with Let's Encrypt
- **haproxy-config** — generates `haproxy.cfg` from `haproxy.yaml`
- **rsyslog** — creates `/var/lib/haproxy/dev/log` socket
- **haproxy** — starts the proxy
- **acme** — issues/renews certs, hot-reloads HAProxy via `haproxy -sf`

### Config Generation

`generate_haproxy_config.sh` reads `haproxy.yaml` and:

1. Renders static sections (`global`, `defaults`, `cache`, frontends) from template files in `/scripts/templates/` using `envsubst`
2. Injects `global[]` and `defaults[]` YAML entries via `sed` placeholders
3. Injects `frontend.*.raw[]` entries via `sed` placeholders
4. Generates `backend` blocks dynamically from `backends[]` and `domain_mappings[]`

---

## Troubleshooting

**Config parse error on startup:**
```bash
docker exec haproxy haproxy -c -f /config/haproxy.cfg
```

**Certificate not issuing:**
```bash
docker exec haproxy cat /var/log/acme-renewals.log
```

**HAProxy not starting:**
```bash
docker exec haproxy cat /var/log/haproxy/haproxy.log
```

**Enable debug logging for config generation:**
```bash
HA_DEBUG=true
```
