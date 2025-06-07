#!/usr/bin/with-contenv bash
# shellcheck shell=bash

YAML_FILE="/config/haproxy.yaml"
HAPROXY_CFG="/config/haproxy.cfg"
ACME_THUMBPRINT_PATH="/config/acme/ca/thumbprint"
LOCK_FILE="/tmp/haproxy-generate.lock"

source /scripts/debug.sh

# Create config file if it doesn't exist
if [ ! -f "$HAPROXY_CFG" ]; then
    echo "[haproxy] file does not exist" | ts '%Y-%m-%d %H:%M:%S'
    touch "$HAPROXY_CFG"
fi

# Always clear the file contents before generating new config
echo "[haproxy] clearing existing config..." | ts '%Y-%m-%d %H:%M:%S'
debug_log "file size before clear: $(wc -c < "$HAPROXY_CFG")" | ts '%Y-%m-%d %H:%M:%S'
cat /dev/null > "$HAPROXY_CFG"
debug_log "file size after clear: $(wc -c < "$HAPROXY_CFG")" | ts '%Y-%m-%d %H:%M:%S'

# Ensure only one instance runs at a time
if [ -f "$LOCK_FILE" ]; then
    pid=$(cat "$LOCK_FILE")
    if kill -0 "$pid" 2>/dev/null; then
        echo "[haproxy] Another config generation process is running (PID: $pid)" | ts '%Y-%m-%d %H:%M:%S'
        exit 1
    else
        echo "[haproxy] Removing stale lock file" | ts '%Y-%m-%d %H:%M:%S'
        rm -f "$LOCK_FILE"
    fi
fi

# Create lock file with current PID
echo $$ > "$LOCK_FILE"

# Verify we got the lock
if [ "$(cat "$LOCK_FILE")" != "$$" ]; then
    echo "[haproxy] Failed to acquire lock" | ts '%Y-%m-%d %H:%M:%S'
    exit 1
fi

# Cleanup lock file on exit
trap 'rm -f "$LOCK_FILE"' EXIT

while [ ! -f "$ACME_THUMBPRINT_PATH" ]; do
    echo "[haproxy] Waiting for $ACME_THUMBPRINT_PATH to be created before creating configuration..." | ts '%Y-%m-%d %H:%M:%S'
    sleep 3
done

# Read the thumbprint from the file
if [ -f /config/acme/ca/thumbprint ]; then
    ACCOUNT_THUMBPRINT=$(cat /config/acme/ca/thumbprint)
else
    echo "Error: ACME account thumbprint not found"
    exit 1
fi

: "${HAPROXY_THREADS:=4}"
: "${QUIC_MAX_AGE:=86400}"
: "${H3_29_SUPPORT:=false}"
: "${MIXED_SSL_MODE:=false}"

if [ -z "${HAPROXY_BIND_IP}" ]; then
    HAPROXY_BIND_IP="0.0.0.0"
fi

echo "[haproxy] Generating configuration..." | ts '%Y-%m-%d %H:%M:%S'

# Set the correct port for HTTP/3 alt-svc header based on MIXED_SSL_MODE
if [ "$MIXED_SSL_MODE" = "true" ]; then
    QUIC_PORT="8443"
else
    QUIC_PORT="443"
fi

# Always use port 443 for the ALT_SVC header since we handle port forwarding internally
if [ "$H3_29_SUPPORT" = "true" ]; then
    ALT_SVC="h3=\":${QUIC_PORT}\"; ma=${QUIC_MAX_AGE}, h3-29=\":${QUIC_PORT}\"; ma=3600"
else
    ALT_SVC="h3=\":${QUIC_PORT}\"; ma=${QUIC_MAX_AGE}"
fi

if [ ! -f "/var/run/haproxy/haproxy.pid" ]; then
    PIDFILE="
    pidfile /var/run/haproxy/haproxy.pid"
else
    PIDFILE=""
fi

cat <<EOF >> "$HAPROXY_CFG"
global
    daemon
    hard-stop-after 15m

    # Performance Optimizations
    nbthread ${HAPROXY_THREADS}
    cpu-map auto:1/1-${HAPROXY_THREADS} 0-$((HAPROXY_THREADS-1))

    # acme thumbprnt
    setenv ACCOUNT_THUMBPRINT '${ACCOUNT_THUMBPRINT}'

    # Default socket configurations
    # used for newer reload mechanism. See https://www.haproxy.com/blog/hitless-reloads-with-haproxy-howto/
    stats socket /var/lib/haproxy/admin.sock level admin mode 660 expose-fd listeners
    stats timeout 30s
    ${PIDFILE}

    # [GLOBALS PLACEHOLDER]

    # rsyslogd has created a socket to listen on at /var/lib/haproxy/dev/log
    # haproxy is chrooted to /var/lib/haproxy/ and can only write therein
    log /var/lib/haproxy/dev/log local0

    # generated 2022-05-03, Mozilla Guideline v5.6, HAProxy 2.5, OpenSSL 1.1.1n, intermediate configuration
    # https://ssl-config.mozilla.org/#server=haproxy&version=2.5&config=intermediate&openssl=1.1.1n&guideline=5.6
    # intermediate configuration
    ssl-default-bind-ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384
    ssl-default-bind-ciphersuites TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256
    ssl-default-bind-options prefer-client-ciphers no-sslv3 no-tlsv10 no-tlsv11 no-tls-tickets
    ssl-default-server-ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384
    ssl-default-server-ciphersuites TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256
    ssl-default-server-options no-sslv3 no-tlsv10 no-tlsv11 no-tls-tickets

    ssl-dh-param-file /config/acme/tls1-params/ffdhe2048
    tune.ssl.default-dh-param 2048

EOF

# Generate HAProxy defaults configuration
cat <<EOF >> "$HAPROXY_CFG"
defaults
    log global
    mode http
    option dontlognull

    # Placed by yaml defaults
    # [DEFAULTS PLACEHOLDER]

    # Our format here will produce 2021-01-01 08:00:01.565 +0200
    log-format "[%[date,ltime(%Y-%m-%d %H:%M:%S)].%ms %[date,ltime(%z)]] %[var(txn.real_ip)] %ci:%cp %ft %b/%s %TR/%Tw/%Tc/%Tr/%Ta %ST %B %CC %CS %tsc %ac/%fc/%bc/%sc/%rc %sq/%bq %hr %hs %{+Q}r %[ssl_fc_sni]"
    error-log-format "[%[date,ltime(%Y-%m-%d %H:%M:%S)].%ms %[date,ltime(%z)]] %[var(txn.real_ip)] %ci:%cp %ft %ac/%fc %[fc_err_str]/%[ssl_fc_err,hex]/%[ssl_c_err]/%[ssl_c_ca_err]/%[ssl_fc_is_resumed] %[ssl_fc_sni]/%sslv/%sslc"

    # Basic compression settings
    compression algo gzip deflate

    # File types to compress
    compression type text/html
    compression type text/plain
    compression type text/css
    compression type text/xml
    compression type text/javascript
    compression type text/calendar
    compression type text/markdown
    compression type text/vcard
    compression type text/vtt
    compression type text/x-component
    compression type text/x-cross-domain-policy
    compression type application/javascript
    compression type application/x-javascript
    compression type application/json
    compression type application/ld+json
    compression type application/manifest+json
    compression type application/schema+json
    compression type application/vnd.api+json
    compression type application/vnd.geo+json
    compression type application/xml
    compression type application/xhtml+xml
    compression type application/rss+xml
    compression type application/atom+xml
    compression type application/soap+xml
    compression type application/x-httpd-php
    compression type font/collection
    compression type font/opentype
    compression type font/otf
    compression type font/ttf
    compression type application/x-font-ttf
    compression type application/x-font-opentype
    compression type application/x-font-truetype
    compression type application/vnd.ms-fontobject
    compression type application/font-sfnt
    compression type application/font-woff
    compression type application/font-woff2
    compression type image/svg+xml
    compression type image/x-icon
    compression type application/pdf
    compression type application/x-yaml
    compression type application/yaml
    compression type application/rtf

EOF

# Generate HAProxy caching configuration
cat <<EOF >> "$HAPROXY_CFG"
cache my-cache
    total-max-size 1024                 # 1GB total cache
    max-object-size 524288              # 512KB max object size
    max-age 3600                        # 1 hour
    process-vary on

EOF

MIXED_MODE_404_RESPONSE=""
if [ "${MIXED_SSL_MODE}" != "true" ]; then
    MIXED_MODE_404_RESPONSE="
    # Respond 404 if not valid domain and not in mixed mode
    http-request return status 404 if is_acme_challenge !valid_acme_domain !valid_acme_sub_domain"
fi

cat <<EOF >> "$HAPROXY_CFG"
frontend http
    bind            ${HAPROXY_BIND_IP}:80
    mode            http
    log             global
    option          httplog

    # Define a simple stick table to track domains
    stick-table type string len 100 size 100k expire 300s store http_req_cnt,gpc0

    # Define ACL for ACME challenges
    acl is_acme_challenge path_beg /.well-known/acme-challenge/

    # Only return responses for domains that were tracked in the stick table
    # This is checked in a separate script that adds the domains when acme.sh runs
    acl valid_acme_domain req.hdr(host),field(2,.),table_http_req_cnt(http) gt 0
    acl valid_acme_sub_domain req.hdr(host),table_http_req_cnt(http) gt 0

    # Fallback to the old method if needed
    http-request return status 200 content-type text/plain lf-string "%[path,field(-1,/)].${ACCOUNT_THUMBPRINT}\n" if is_acme_challenge valid_acme_sub_domain
    http-request return status 200 content-type text/plain lf-string "%[path,field(-1,/)].${ACCOUNT_THUMBPRINT}\n" if is_acme_challenge valid_acme_domain
    ${MIXED_MODE_404_RESPONSE}

    # Proxy headers
    http-request set-header X-Forwarded-Proto http if !is_acme_challenge

    # Only redirect non-ACME traffic to HTTPS
    http-request redirect scheme https if !is_acme_challenge

    # Placed by yaml frontend http:
    # [HTTP-FRONTEND PLACEHOLDER]

EOF

if [ "$MIXED_SSL_MODE" = "true" ]; then
    cat <<EOF >> "$HAPROXY_CFG"
frontend https
    bind        ${HAPROXY_BIND_IP}:443
    mode        tcp
    log         global
    option      tcplog
    option      dontlognull

    # Enhanced TCP logging format
    log-format "%ci:%cp [%t] %ft %b/%s %Tw/%Tc/%Tt %B %ts %ac/%fc/%bc/%sc/%rc %sq/%bq %sslc %sslv %{+Q}[ssl_fc_sni] %{+Q}[ssl_fc_protocol] %[ssl_fc_cipher]"

    # Strict TLS inspection with timeout
    tcp-request inspect-delay 10s
    tcp-request content accept if { req.ssl_hello_type 1 }

    # Placed by yaml https_frontend_rules
    # [HTTPS-FRONTEND USE_BACKEND PLACEHOLDER]

    # Placed by yaml domain_mappings
    # [HTTPS-FRONTEND EXTRA PLACEHOLDER]

EOF
fi

if [ "FRONTEND_IP_PROTECTION" = "true" ]; then
    cat <<EOF >> "$HAPROXY_CFG"
frontend https-offloading-ip-protection
    bind            unix@/var/lib/haproxy/frontend-offloading-ip-protection.sock accept-proxy ssl crt /etc/haproxy/certs/ strict-sni alpn h2
    mode            http
    log             global
    option          http-keep-alive
    option          forwardfor
    option          httplog

    http-request    set-var(txn.txnhost) hdr(host)

    # Placed by yaml frontend https-offloading-ip-protection:
    # [HTTPS-FRONTEND-OFFLOADING-IP-PROTECTION PLACEHOLDER]

    # Proxy headers
    http-request set-header X-Forwarded-Proto https if { ssl_fc } !{ req.hdr(X-Forwarded-Proto) -m found }

    # Remove server information headers
    http-response del-header ^Server:.*$
    http-response del-header ^X-Powered.*$

    # Security headers
    http-response set-header X-Frame-Options sameorigin
    http-response set-header Strict-Transport-Security "max-age=63072000"
    http-response set-header X-XSS-Protection "1; mode=block"
    http-response set-header X-Content-Type-Options nosniff
    http-response set-header Referrer-Policy no-referrer-when-downgrade

    http-response set-header alt-svc "${ALT_SVC}"

    # Compression controls
    acl compressed_file path_end .gz .br .zip .png .jpg .jpeg .gif .webp .webm
    acl has_content_encoding hdr(Content-Encoding) -m found
    acl accept_encoding hdr(Accept-Encoding) -m found

    # Compression monitoring headers
    http-response set-header X-Compressed true if { res.comp }
    http-response del-header X-Compressed if !{ res.comp }
    http-response set-header Vary Accept-Encoding

    compression offload

    # Placed by yaml domain_mappings
    # [HTTPS-FRONTEND-OFFLOADING-IP-PROTECTION USE_BACKEND PLACEHOLDER]

EOF
fi

PRIMARY_BIND=""
if [ $MIXED_SSL_MODE != "true" ]; then
    PRIMARY_BIND="${HAPROXY_BIND_IP}:8443 alpn h3"
fi

cat <<EOF >> "$HAPROXY_CFG"
frontend https-offloading
    bind            unix@/var/lib/haproxy/frontend-offloading.sock accept-proxy ssl crt /etc/haproxy/certs/ strict-sni alpn h2
    bind            quic4@${HAPROXY_BIND_IP}:$([ "$MIXED_SSL_MODE" = "true" ] && echo "8443" || echo "443") ssl crt /etc/haproxy/certs/ alpn h3 thread 1-${HAPROXY_THREADS}
    $PRIMARY_BIND
    mode            http
    log             global
    option          http-keep-alive
    option          forwardfor
    option          httplog

    # Add proxy protocol handling
    declare capture request len 40
    http-request capture req.hdr(X-Forwarded-For) id 0

    http-request    set-var(txn.txnhost) hdr(host)

    # Proxy headers
    http-request set-header X-Forwarded-Proto https if { ssl_fc } !{ req.hdr(X-Forwarded-Proto) -m found }

    # Remove server information headers
    http-response del-header ^Server:.*$
    http-response del-header ^X-Powered.*$

    # Security headers
    http-response set-header X-Frame-Options sameorigin
    http-response set-header Strict-Transport-Security "max-age=63072000"
    http-response set-header X-XSS-Protection "1; mode=block"
    http-response set-header X-Content-Type-Options nosniff
    http-response set-header Referrer-Policy no-referrer-when-downgrade

    http-response set-header alt-svc "${ALT_SVC}"

    # Compression controls
    acl compressed_file path_end .gz .br .zip .png .jpg .jpeg .gif .webp .webm
    acl has_content_encoding hdr(Content-Encoding) -m found
    acl accept_encoding hdr(Accept-Encoding) -m found

    # Compression monitoring headers
    http-response set-header X-Compressed true if { res.comp }
    http-response del-header X-Compressed if !{ res.comp }
    http-response set-header Vary Accept-Encoding

    compression offload

    # Placed by yaml domain_mappings
    # [HTTPS-FRONTEND-OFFLOADING USE_BACKEND PLACEHOLDER]
    # Placed by yaml frontend https-offloading:
    # [HTTPS-FRONTEND-OFFLOADING PLACEHOLDER]

EOF

if [ "$MIXED_SSL_MODE" = "true" ]; then
    cat <<EOF >> "$HAPROXY_CFG"
backend frontend-offloading
    mode tcp
    id 10
    log global
    retries 3
    server frontend-offloading-srv unix@/var/lib/haproxy/frontend-offloading.sock send-proxy-v2-ssl-cn

EOF
fi

cat <<EOF >> "$HAPROXY_CFG"
backend frontend-offloading-ip-protection
    mode tcp
    id 11
    log global
    retries 3
    server frontend-offloading-ip-protection-srv unix@/var/lib/haproxy/frontend-offloading-ip-protection.sock send-proxy-v2-ssl-cn

EOF

# Convert YAML to JSON and check for errors
if ! JSON_CONFIG=$(yq eval -o=json "$YAML_FILE"); then
    echo "[haproxy] Error: Failed to convert YAML configuration to JSON" | ts '%Y-%m-%d %H:%M:%S'
    exit 1
fi

# Function to replace placeholders with YAML data
replace_placeholder() {
    local placeholder="$1"
    local yaml_path="$2"
    local indent="$3"

    # Check if the YAML path exists and is not empty
    if yq eval "$yaml_path" "$YAML_FILE" | grep -q -v '^$'; then
        local content
        content=$(yq eval "$yaml_path" "$YAML_FILE" | sed "s/^/${indent}/")
        sed -i "/${placeholder}/r /dev/stdin" "$HAPROXY_CFG" << EOF
$content
EOF
        sed -i "/${placeholder}/d" "$HAPROXY_CFG"
    else
        local msg="Warning: YAML path '"$yaml_path"' is empty or doesn't exist. Placeholder '"$placeholder"' will remain unchanged."
        debug_log "$msg"
    fi
}

# Replace placeholders with YAML data
replace_placeholder "# \[GLOBALS PLACEHOLDER\]" '.global[]' '    '
replace_placeholder "# \[DEFAULTS PLACEHOLDER\]" '.defaults[]' '    '
replace_placeholder "# \[HTTP-FRONTEND PLACEHOLDER\]" '.frontend.http[]' '    '
replace_placeholder "# \[HTTPS-FRONTEND-OFFLOADING PLACEHOLDER\]" '.frontend.https-offloading[]' '    '
replace_placeholder "# \[HTTPS-FRONTEND-OFFLOADING-IP-PROTECTION PLACEHOLDER\]" '.frontend.https-offloading-ip-protection[]' '    '

if [ "$MIXED_SSL_MODE" = "true" ]; then
    replace_placeholder "# \[HTTPS-FRONTEND EXTRA PLACEHOLDER\]" '.frontend.https[]' '    '
else
    # Generate individual ACLs for frontend-offloading-ip-protection
    while read -r domain; do
        config="${config}    acl            https-offloading-ip-protection req.ssl_sni -i ${domain}
"
    done < <(echo "$JSON_CONFIG" | jq -r '.https_frontend_rules[] | select(.backend == "frontend-offloading-ip-protection") | .domains[]')
fi

# Function to generate HTTPS frontend configuration
generate_https_frontend_config() {
    local config=""

    debug_log "Generating ACLs and use_backend rules for HTTPS frontend"

    # Generate individual ACLs for frontend-offloading-ip-protection
    while read -r domain; do
        config="${config}    acl            https-offloading-ip-protection req.ssl_sni -i ${domain}
"
    done < <(echo "$JSON_CONFIG" | jq -r '.https_frontend_rules[] | select(.backend == "frontend-offloading-ip-protection") | .domains[]')

    # Generate individual ACLs for frontend-offloading
    while read -r domain; do
        config="${config}    acl            https-offloading req.ssl_sni -m end -i ${domain}
"
    done < <(echo "$JSON_CONFIG" | jq -r '.https_frontend_rules[] | select(.backend == "frontend-offloading" and .backend != "frontend-offloading-ip-protection") | .domains[]')

    # Add use_backend rules
    config="${config}
    use_backend frontend-offloading-ip-protection if https-offloading-ip-protection
    use_backend frontend-offloading if https-offloading"

    if [ -n "$config" ]; then
        debug_log "Inserting generated config into HAPROXY_CFG"
        sed -i "/# \[HTTPS-FRONTEND USE_BACKEND PLACEHOLDER\]/r /dev/stdin" "$HAPROXY_CFG" << EOF
$config
EOF
        sed -i '/# \[HTTPS-FRONTEND USE_BACKEND PLACEHOLDER\]/d' "$HAPROXY_CFG"
    fi
}

# Helper function to generate regex pattern for domain
get_domain_regex() {
    ESCAPED_DOMAIN=$(echo "$1" | sed 's/\./\\./g')

    if [ "$2" = "true" ]; then
        # For base domain only wild card certificates
        echo "^${ESCAPED_DOMAIN}(:([0-9]){1,5})?\$"
    else
        # For subdomains - support multiple levels of subdomains
        echo "^([^\.]+\.)*${ESCAPED_DOMAIN}(:([0-9]){1,5})?\$"
    fi
}

# Helper function to extract domain from match condition
get_match_domain() {
    local match_condition="$1"
    echo "$match_condition" | sed 's/.*-i \([^ ]*\)$/\1/'
}

# Function to generate HTTPS offloading frontend configuration
generate_https_offloading_frontend_config() {
    local acl_config=""
    local backend_config=""
    local seen_certs=""

    debug_log "Generating configuration for https-offloading"

    # First pass: Generate all unique certificate ACLs
    while read -r domain backend; do
        if [ -n "$domain" ] && [ "$domain" != "null" ] && [ "$backend" != "null" ]; then
            # Get base domain
            base_domain=$(echo "$domain" | sed 's/.*\.\([^.]*\.[^.]*\.[^.]*\)$/\1/')
            cert_acl_name="aclcrt_${base_domain}_https_offloading"

            # Only add cert ACL if we haven't seen it before
            if ! echo "$seen_certs" | grep -F "$cert_acl_name" > /dev/null; then
                seen_certs="${seen_certs}${cert_acl_name}
"
                # Add certificate matching ACLs for both subdomain and base domain
                acl_config="${acl_config}    acl ${cert_acl_name} var(txn.txnhost) -m reg -i $(get_domain_regex "$base_domain" "false")
"
                acl_config="${acl_config}    acl ${cert_acl_name} var(txn.txnhost) -m reg -i $(get_domain_regex "$base_domain" "true")
"
            fi

            # Create domain-specific ACL using the original domain
            domain_clean=${domain//[.-]/_}
            acl_config="${acl_config}    acl acl_${domain_clean} var(txn.txnhost) -m str -i ${domain}
"

            # Store backend rule using both ACLs
            backend_config="${backend_config}    use_backend ${backend} if acl_${domain_clean} ${cert_acl_name}
"
        fi
    done < <(echo "$JSON_CONFIG" | jq -r '.domain_mappings[] | select(.frontend == "https-offloading" and .frontend != "https-offloading-ip-protection") | .domains[] + " " + .backend')

    # Combine configs with proper line breaks
    local config="${acl_config}
${backend_config}"

    if [ -n "$config" ]; then
        debug_log "Inserting generated config into HAPROXY_CFG"
        sed -i "/# \[HTTPS-FRONTEND-OFFLOADING USE_BACKEND PLACEHOLDER\]/r /dev/stdin" "$HAPROXY_CFG" << EOF
$config
EOF
        sed -i '/# \[HTTPS-FRONTEND-OFFLOADING USE_BACKEND PLACEHOLDER\]/d' "$HAPROXY_CFG"
    fi
}

# Function to generate HTTPS offloading IP protection frontend configuration
generate_https_offloading_ip_protection_frontend_config() {
    local acl_config=""
    local backend_config=""
    local seen_certs=""
    local base_domain=""

    debug_log "Generating configuration for https-offloading-ip-protection frontend"

    # First determine the base domain from the first domain
    while read -r domain backend; do
        if [ -n "$domain" ] && [ "$domain" != "null" ] && [ "$backend" != "null" ]; then
            base_domain=$(echo "$domain" | sed 's/.*\.\([^.]*\.[^.]*\.[^.]*\)$/\1/')
            break
        fi
    done < <(echo "$JSON_CONFIG" | jq -r '.domain_mappings[] | select(.frontend == "https-offloading-ip-protection") | .domains[] + " " + .backend')

    if [ -z "$base_domain" ]; then
        debug_log "Error: Could not determine base domain for IP protection frontend"
        return 1
    fi

    debug_log "Using base domain: $base_domain for IP protection frontend"

    # Generate ACLs using the determined base domain
    while read -r domain backend; do
        if [ -n "$domain" ] && [ "$domain" != "null" ] && [ "$backend" != "null" ]; then
            base_domain=$(echo "$domain" | sed 's/.*\.\([^.]*\.[^.]*\.[^.]*\)$/\1/')
            cert_acl_name="aclcrt_${base_domain}_https_offloading_ip_protection"

            # Only add cert ACL if we haven't seen it before
            if ! echo "$seen_certs" | grep -F "$cert_acl_name" > /dev/null; then
                seen_certs="${seen_certs}${cert_acl_name}
"
                # Add certificate matching ACLs for both subdomain and base domain
                acl_config="${acl_config}    acl ${cert_acl_name} var(txn.txnhost) -m reg -i $(get_domain_regex "$base_domain" "false")
"
                acl_config="${acl_config}    acl ${cert_acl_name} var(txn.txnhost) -m reg -i $(get_domain_regex "$base_domain" "true")
"
            fi

            # Create domain ACL using the original domain
            acl_config="${acl_config}    acl ${domain} var(txn.txnhost) -m str -i ${domain}
"

            # Store backend rule using both ACLs
            backend_config="${backend_config}    use_backend ${backend} if ${domain} ${cert_acl_name}
"
        fi
    done < <(echo "$JSON_CONFIG" | jq -r '.domain_mappings[] | select(.frontend == "https-offloading-ip-protection") | .domains[] + " " + .backend')

    # Combine configs with proper line breaks
    local config="${acl_config}
${backend_config}"

    if [ -n "$config" ]; then
        debug_log "Inserting generated config into HAPROXY_CFG"
        sed -i "/# \[HTTPS-FRONTEND-OFFLOADING-IP-PROTECTION USE_BACKEND PLACEHOLDER\]/r /dev/stdin" "$HAPROXY_CFG" << EOF
$config
EOF
        sed -i '/# \[HTTPS-FRONTEND-OFFLOADING-IP-PROTECTION USE_BACKEND PLACEHOLDER\]/d' "$HAPROXY_CFG"
    fi
}

# Function to generate backend configurations
generate_backend_configs() {
    local backend_id=13
    local server_id=103

    debug_log "Generating backend configurations"
    echo "$JSON_CONFIG" | jq -c '.backends[]' | while read -r backend; do
        name=$(echo "$backend" | jq -r '.name')
        mode=$(echo "$backend" | jq -r '.mode // "http"')
        timeout_connect=$(echo "$backend" | jq -r '.timeout_connect')
        timeout_server=$(echo "$backend" | jq -r '.timeout_server')
        hosts=$(echo "$backend" | jq -r '.hosts[]')
        is_ssl=$(echo "$backend" | jq -r '.ssl // false')
        ssl_verify=$(echo "$backend" | jq -r '.ssl_verify // false')
        enable_h2=$(echo "$backend" | jq -r '.enable_h2 // false')
        use_send_proxy=$(echo "$backend" | jq -r '.use_send_proxy // false')

        debug_log "Processing backend: $name"

        # Skip this backend if essential information is missing
        if [ "$name" = "null" ] || [ -z "$name" ] ||
           [ "$mode" = "null" ] || [ -z "$mode" ]; then
            debug_log "Warning: Skipping backend with missing essential information. Name: $name, Mode: $mode" | ts '%Y-%m-%d %H:%M:%S'
            continue
        fi

        # Get hosts array
        if [ -z "$hosts" ] || [ "$hosts" = "null" ]; then
            debug_log "Warning: No hosts defined for backend $name" | ts '%Y-%m-%d %H:%M:%S'
            continue
        fi

        # Handle options and other directives
        options_config=""
        if echo "$backend" | jq -e '.options[]' > /dev/null 2>&1; then
            # Process each option, handling special cases for httpchk with headers
            options_config=$(echo "$backend" | jq -r '.options[]?' | while read -r option; do
                # Check if this is an httpchk option with headers that contain \r\n
                if [[ "$option" == *"httpchk"*"\r\n"* ]]; then
                    # Process the httpchk option to ensure headers are on the same line
                    # Replace \r\n with actual carriage return and newline in the HAProxy config
                    echo "    option $(echo "$option" | sed 's/\\r\\n/\r\n/g' | sed 's/\\ / /g')"
                else
                    echo "    option $option"
                fi
            done)
        fi

        # Handle http-check directives separately
        http_check_config=""
        if echo "$backend" | jq -e '.http_check[]' > /dev/null 2>&1; then
            # Add http-check directives without "option" prefix
            http_check_config=$(echo "$backend" | jq -r '.http_check[]? | "    http-check " + .')
        fi

        # Handle extra_config directives
        extra_config=""
        if echo "$backend" | jq -e '.extra_config[]' > /dev/null 2>&1; then
            # Add extra_config directives without any prefix
            extra_config=$(echo "$backend" | jq -r '.extra_config[]? | "    " + .')
        fi

        # Set default values for timeout if they are null or empty
        timeout_connect=${timeout_connect:-5000}
        timeout_server=${timeout_server:-50000}

        health_check=""
        retries="retries 3"

        cache=""
        if echo "$backend" | jq -e '.cache == true' > /dev/null; then
            cache="acl is_image path_end -i .jpg .jpeg .png .gif
    http-request cache-use my-cache if is_image
    http-response cache-store my-cache if { res.hdr(Content-Type) -m sub image/ }
"
        fi

        ssl_options=""
        if [ "$is_ssl" = "true" ]; then
            ssl_options="ssl"
            if [ "$ssl_verify" = "false" ]; then
                ssl_options="${ssl_options} verify none"
            fi
        fi

        # First determine the proxy option based on SSL and send-proxy settings
        send_proxy=""
        if [ "$use_send_proxy" = "true" ]; then
            if [ "$is_ssl" = "true" ]; then
                # When SSL is enabled, use ssl-cn version to preserve certificate info
                send_proxy="send-proxy-v2-ssl-cn"
            else
                # For non-SSL connections, use standard proxy protocol
                send_proxy="send-proxy-v2"
            fi
        fi

        # Generate server lines
        server_lines=""
        server_count=1
        while read -r host_entry; do
            if [ -n "$host_entry" ]; then
                # Check if the host entry is a simple string or a JSON object
                if [[ "$host_entry" == {* ]]; then
                    # Parse JSON object for host and check config
                    host=$(echo "$host_entry" | jq -r '.host')

                    # Check if there's a check configuration for this host
                    host_check=""
                    if echo "$host_entry" | jq -e '.check' > /dev/null 2>&1; then
                        check_type=$(echo "$host_entry" | jq -r '.check.type // "tcp"')
                        check_interval=$(echo "$host_entry" | jq -r '.check.interval // "2000"')
                        check_fall=$(echo "$host_entry" | jq -r '.check.fall // "3"')
                        check_rise=$(echo "$host_entry" | jq -r '.check.rise // "2"')
                        check_slowstart=$(echo "$host_entry" | jq -r '.check.slowstart // false')

                        host_check="check inter ${check_interval} fall ${check_fall} rise ${check_rise}"
                        if [ "$check_slowstart" != "false" ]; then
                            host_check="${host_check} slowstart ${check_slowstart}"
                        fi

                        # Add health check option based on check type if not already defined
                        if [ -z "$health_check" ]; then
                            case $check_type in
                                http)
                                    check_uri=$(echo "$host_entry" | jq -r '.check.uri // "/"')
                                    health_check="option httpchk GET ${check_uri}"
                                    ;;
                                ssl)
                                    check_verify=$(echo "$host_entry" | jq -r '.check.verify // "none"')
                                    health_check="option ssl-hello-chk"
                                    ;;
                                tcp)
                                    # TCP check doesn't need additional parameters
                                    ;;
                                *)
                                    debug_log "Warning: Unknown check type '${check_type}' for host in backend '${name}'. Using TCP check." | ts '%Y-%m-%d %H:%M:%S'
                                    ;;
                            esac
                        fi
                    fi
                else
                    # Simple string host - no check config
                    host="$host_entry"
                    host_check=""
                fi

                # Parse host to extract address and options (like 'backup')
                host_address=$(echo "$host" | awk '{print $1}' | tr -d '"')
                host_options=$(echo "$host" | cut -d' ' -f2- -s | tr -d '"')

                # Check for per-host enable_h2 setting
                host_enable_h2="false"
                if [ "$is_json" = "true" ]; then
                    # For JSON object hosts, check for enable_h2 in the host entry
                    host_enable_h2=$(echo "$host_entry" | jq -r '.enable_h2 // "false"')
                fi

                # If host explicitly sets enable_h2, use that value
                # Otherwise fall back to backend-level setting
                if [ "$host_enable_h2" = "false" ] && [ "$enable_h2" = "true" ]; then
                    host_enable_h2="true"
                elif [ "$host_enable_h2" = "true" ]; then
                    # Host explicitly enables H2 even if backend doesn't
                    host_enable_h2="true"
                fi

                h2_options=""
                if [ "$host_enable_h2" = "true" ]; then
                    h2_options=" alpn h2 check-reuse-pool idle-ping 30s"
                fi

                server_lines="${server_lines}    server ${name}-srv${server_count} ${host_address}${ssl_options:+ $ssl_options}${h2_options}${host_check:+ $host_check}${host_options:+ $host_options}${send_proxy:+ $send_proxy}
"
                server_count=$((server_count + 1))
            fi
        done < <(echo "$backend" | jq -c '.hosts[]')

        debug_log "Server lines for backend $name: $server_lines"

{
    cat <<EOF
backend $name
    mode ${mode:-http}
    id $backend_id
    log global
EOF
    [ -n "$retries" ] && echo "    ${retries}"
    [ -n "$health_check" ] && echo "    ${health_check}"
    [ -n "$options_config" ] && echo "${options_config}"
    [ -n "$http_check_config" ] && echo "${http_check_config}"
    [ -n "$extra_config" ] && echo "${extra_config}"
    [ "$enable_h2" = "true" ] && [ "$is_ssl" = "false" ] && echo "    # HTTP/2 Cleartext (h2c) settings"
    echo -n "${server_lines}"
    [ -n "$cache" ] && echo -n "    ${cache}"
    echo
} >> "$HAPROXY_CFG"

        backend_id=$((backend_id + 1))
        server_id=$((server_id + 1))
    done
}

if [ "$MIXED_SSL_MODE" = "true" ]; then
    generate_https_frontend_config;
    generate_https_offloading_frontend_config;
    generate_https_offloading_ip_protection_frontend_config;
fi

generate_backend_configs;

echo "[haproxy] Configuration generation complete." | ts '%Y-%m-%d %H:%M:%S'
