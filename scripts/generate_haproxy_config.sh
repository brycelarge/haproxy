#!/usr/bin/with-contenv bash
# shellcheck shell=bash

YAML_FILE=/config/haproxy.yaml
HAPROXY_CFG="/config/haproxy.cfg"
ACME_THUMBPRINT_PATH="/config/acme/ca/thumbprint"

while [ ! -f "$ACME_THUMBPRINT_PATH" ]; do
    echo "[haproxy] Waiting for $ACME_THUMBPRINT_PATH to be created before creating configuration..." | ts '%Y-%m-%d %H:%M:%S'
    sleep 3
done
THUMBPRINT=$(cat "${ACME_THUMBPRINT_PATH}")

: "${HAPROXY_THREADS:=4}"
: "${QUIC_MAX_AGE:=86400}"
: "${H3_29_SUPPORT:=true}"

[ -e "$HAPROXY_CFG" ] && rm "$HAPROXY_CFG"
touch "$HAPROXY_CFG"

if [ -z "${HAPROXY_BIND_IP}" ]; then
    HAPROXY_BIND_IP=$(ip addr show eth0 | grep "inet " | awk '{print $2}' | cut -d/ -f1)
    if [ -z "${HAPROXY_BIND_IP}" ]; then
        HAPROXY_BIND_IP="0.0.0.0"
    fi
fi

source /scripts/debug.sh

echo "[haproxy] Generating configuration..." | ts '%Y-%m-%d %H:%M:%S'

if [ "$H3_29_SUPPORT" = "true" ]; then
    ALT_SVC="h3=\":443\"; ma=${QUIC_MAX_AGE}, h3-29=\":443\"; ma=3600"
else
    ALT_SVC="h3=\":443\"; ma=${QUIC_MAX_AGE}"
fi

cat <<EOF >> "$HAPROXY_CFG"
global
    maxconn 4096
    daemon
    hard-stop-after 15m

    # Performance Optimizations
    nbthread ${HAPROXY_THREADS}
    cpu-map auto:1/1-${HAPROXY_THREADS} 0-$((HAPROXY_THREADS-1))

    # acme thumbprnt
    setenv ACCOUNT_THUMBPRINT '${THUMBPRINT}'

    # Default socket configurations
    # used for newer reload mechanism. See https://www.haproxy.com/blog/hitless-reloads-with-haproxy-howto/
    stats socket /var/lib/haproxy/admin.sock level admin mode 660 expose-fd listeners
    stats timeout 30s

    pidfile /var/run/haproxy/haproxy.pid

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
    error-log-format "[%[date,ltime(%Y-%m-%d %H:%M:%S)].%ms %[date,ltime(%z)]] %[var(txn.real_ip)] %ci:%cp %ft %ac/%fc %[fc_err_str]/%[ssl_fc_err,hex]/%[ssl_c_err]/%[ssl_c_ca_err]/%[ssl_fc_is_resumed] %{+Q}r %[ssl_fc_sni]/%sslv/%sslc"

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
    total-max-size 100     # MB
    max-object-size 100000 # bytes
    max-age 3600           # seconds
    process-vary on

EOF

cat <<EOF >> "$HAPROXY_CFG"
frontend http
    bind        ${HAPROXY_BIND_IP}:80
    mode        http
    log	        global

    # ACME challenge
    http-request return status 200 content-type text/plain lf-string "%[path,field(-1,/)].${THUMBPRINT}\n" if { path_beg '/.well-known/acme-challenge/' }

    # Placed by yaml frontend http:
    # [HTTP-FRONTEND PLACEHOLDER]

    # Proxy headers
    http-request set-header X-Forwarded-Proto https if { ssl_fc } # For Proto
    option forwardfor # X-forwarded-for
    http-request redirect scheme https

    http-response set-header alt-svc "${ALT_SVC}"

EOF

if [ "$MIXED_SSL_MODE" = "true" ]; then
    cat <<EOF >> "$HAPROXY_CFG"
frontend https
    bind        ${HAPROXY_BIND_IP}:443
    mode        tcp
    log         global
    option      dontlognull
    option      log-separate-errors

    # Strict TLS inspection with timeout
    tcp-request inspect-delay 10s
    tcp-request content accept if { req.ssl_hello_type 1 }

    # Placed by yaml https_frontend_rules
    # [HTTPS-FRONTEND USE_BACKEND PLACEHOLDER]

    # Placed by yaml domain_mappings
    # [HTTPS-FRONTEND EXTRA PLACEHOLDER]

EOF
fi

cat <<EOF >> "$HAPROXY_CFG"
frontend https-offloading-ip-protection
    bind            unix@/var/lib/haproxy/frontend-offloading-ip-protection.sock accept-proxy ssl crt /etc/haproxy/certs/ strict-sni alpn h2
    mode            http
    log             global
    option          http-keep-alive
    option          forwardfor

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

cat <<EOF >> "$HAPROXY_CFG"
frontend https-offloading
    bind            unix@/var/lib/haproxy/frontend-offloading.sock accept-proxy ssl crt /etc/haproxy/certs/ strict-sni alpn h2
    bind            quic4@${HAPROXY_BIND_IP}:$([ "$MIXED_SSL_MODE" = "true" ] && echo "8443" || echo "443") ssl crt /etc/haproxy/certs/ alpn h3 thread 1-${HAPROXY_THREADS}
    mode            http
    log             global
    option          http-keep-alive
    option          forwardfor

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
    config="${config}    use_backend frontend-offloading-ip-protection if https-offloading-ip-protection
    use_backend frontend-offloading if https-offloading
"
    
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
        # For subdomains
        echo "^([^\.]*)\.${ESCAPED_DOMAIN}(:([0-9]){1,5})?\$"
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
    done < <(echo "$JSON_CONFIG" | jq -r '.domain_mappings[] | select(.frontend == "https-offloading" and .frontend != "https-offloading-ip-protection") | "\(.domain) \(.backend)"')
    
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
    done < <(echo "$JSON_CONFIG" | jq -r '.domain_mappings[] | select(.frontend == "https-offloading-ip-protection") | "\(.domain) \(.backend)"')
    
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
    done < <(echo "$JSON_CONFIG" | jq -r '.domain_mappings[] | select(.frontend == "https-offloading-ip-protection") | "\(.domain) \(.backend)"')
    
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
        mode=$(echo "$backend" | jq -r '.mode')
        timeout_connect=$(echo "$backend" | jq -r '.timeout_connect')
        timeout_server=$(echo "$backend" | jq -r '.timeout_server')
        hosts=$(echo "$backend" | jq -r '.hosts[]')
        is_ssl=$(echo "$backend" | jq -r '.ssl // false')
        ssl_verify=$(echo "$backend" | jq -r '.ssl_verify // false')
        enable_h2=$(echo "$backend" | jq -r '.enable_h2 // false')
        
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

        # Set default values for timeout if they are null or empty
        timeout_connect=${timeout_connect:-5000}
        timeout_server=${timeout_server:-50000}
        
        health_check=""
        server_check=""
        retries="retries 3"

        cache=""
        if echo "$backend" | jq -e '.cache == true' > /dev/null; then
            cache="acl is_image path_end -i .jpg .jpeg .png .gif
    http-request cache-use my-cache if is_image
    http-response cache-store my-cache if { res.hdr(Content-Type) -m sub image/ }
"
        fi
        
        if echo "$backend" | jq -e '.check' > /dev/null; then
            if echo "$backend" | jq -e '.check.disable == true' > /dev/null; then
                health_check=""
                server_check=""
            else
                check_type=$(echo "$backend" | jq -r '.check.type // "tcp"')
                check_interval=$(echo "$backend" | jq -r '.check.interval // "2000"')
                check_fall=$(echo "$backend" | jq -r '.check.fall // "3"')
                check_rise=$(echo "$backend" | jq -r '.check.rise // "2"')

                server_check="check inter ${check_interval} fall ${check_fall} rise ${check_rise}"

                case $check_type in
                    http)
                        check_uri=$(echo "$backend" | jq -r '.check.uri // "/"')
                        health_check="${health_check} httpchk GET ${check_uri}"
                        ;;
                    ssl)
                        check_verify=$(echo "$backend" | jq -r '.check.verify // "none"')
                        health_check="${health_check} ssl verify ${check_verify}"
                        ;;
                    tcp)
                        # TCP check doesn't need additional parameters
                        ;;
                    *)
                        debug_log "Warning: Unknown check type '${check_type}' for backend '${name}'. Using TCP check." | ts '%Y-%m-%d %H:%M:%S'
                        ;;
                esac
            fi
        fi

        ssl_options=""
        if [ "$is_ssl" = "true" ]; then
            ssl_options="ssl"
            if [ "$ssl_verify" = "false" ]; then
                ssl_options="${ssl_options} verify none"
            fi
        fi

        # Generate server lines
        server_lines=""
        server_count=1
        while read -r host; do
            if [ -n "$host" ]; then
                h2_options=""
                if [ "$enable_h2" = "true" ]; then
                    h2_options=" proto h2"
                fi
                server_lines="${server_lines}    server ${name}-srv${server_count} ${host}${ssl_options:+ $ssl_options}${h2_options}${server_check:+ $server_check}
"
                server_count=$((server_count + 1))
            fi
        done < <(echo "$hosts")

        debug_log "Server lines for backend $name: $server_lines"

        cat <<EOF >> "$HAPROXY_CFG"
backend $name
    mode $mode
    id $backend_id
    log global
    ${retries}
    ${health_check}
${server_lines}
    ${cache}
EOF

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