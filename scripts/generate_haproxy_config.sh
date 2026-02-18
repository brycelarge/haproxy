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

# Function to clean up lock file
cleanup() {
    # Check if lock file exists and contains our PID before removing
    if [ -f "$LOCK_FILE" ] && [ "$(cat "$LOCK_FILE" 2>/dev/null)" = "$$" ]; then
        rm -f "$LOCK_FILE"
    fi
}

# Set trap to ensure cleanup on exit
trap cleanup EXIT INT TERM

# Create lock file with current PID
echo $$ > "$LOCK_FILE"

# Verify we got the lock
if [ "$(cat "$LOCK_FILE")" != "$$" ]; then
    echo "[haproxy] Failed to acquire lock" | ts '%Y-%m-%d %H:%M:%S'
    exit 1
fi


while [ ! -f "$ACME_THUMBPRINT_PATH" ]; do
    echo "[haproxy] Waiting for $ACME_THUMBPRINT_PATH to be created before creating configuration..." | ts '%Y-%m-%d %H:%M:%S'
    sleep 3
done

# Read the thumbprint from the file
ACCOUNT_THUMBPRINT=$(cat "$ACME_THUMBPRINT_PATH")

: "${QUIC_MAX_AGE:=86400}"
: "${H3_29_SUPPORT:=false}"
: "${MIXED_SSL_MODE:=false}"

if [ -z "${HAPROXY_BIND_IP}" ]; then
    HAPROXY_BIND_IP="0.0.0.0"
fi

echo "[haproxy] Generating configuration..." | ts '%Y-%m-%d %H:%M:%S'

# Set the correct port for HTTP/3 alt-svc header based on MIXED_SSL_MODE
QUIC_PORT="443"

# Always use port 443 for the ALT_SVC header since we handle port forwarding internally
if [ "$H3_29_SUPPORT" = "true" ]; then
    ALT_SVC="h3=\\\":${QUIC_PORT}\\\"; ma=${QUIC_MAX_AGE}, h3-29=\\\":${QUIC_PORT}\\\"; ma=3600"
else
    ALT_SVC="h3=\\\":${QUIC_PORT}\\\"; ma=${QUIC_MAX_AGE}"
fi

if [ ! -f "/var/run/haproxy/haproxy.pid" ]; then
    PIDFILE="
    pidfile /var/run/haproxy/haproxy.pid"
else
    PIDFILE=""
fi

# Generate HAProxy global configuration
envsubst '${ACCOUNT_THUMBPRINT} ${PIDFILE}' \
    < /scripts/templates/global.cfg.tmpl >> "$HAPROXY_CFG"

# Generate HAProxy defaults configuration
cat /scripts/templates/defaults.cfg.tmpl >> "$HAPROXY_CFG"

# Generate HAProxy caching configuration
cat /scripts/templates/cache.cfg.tmpl >> "$HAPROXY_CFG"

MIXED_MODE_404_RESPONSE=""
if [ "${MIXED_SSL_MODE}" != "true" ]; then
    MIXED_MODE_404_RESPONSE="
    # Respond 404 if not valid domain and not in mixed mode
    http-request return status 404 if is_acme_challenge !valid_acme_domain !valid_acme_sub_domain"
fi

# Generate HAProxy http frontend configuration
envsubst '${HAPROXY_BIND_IP} ${ACCOUNT_THUMBPRINT} ${MIXED_MODE_404_RESPONSE}' \
    < /scripts/templates/frontend-http.cfg.tmpl >> "$HAPROXY_CFG"

# Check if certificate directory exists and has files
HAS_CERTS=false
if [ -d "/etc/haproxy/certs" ] && [ "$(ls -A /etc/haproxy/certs 2>/dev/null)" ]; then
    HAS_CERTS=true
    echo "[haproxy] Certificate directory contains files, enabling SSL frontends" | ts '%Y-%m-%d %H:%M:%S'
else
    echo "[haproxy] Certificate directory is empty, skipping SSL frontends" | ts '%Y-%m-%d %H:%M:%S'
fi

# Generate TCP-mode HTTPS frontend for mixed SSL passthrough (MIXED_SSL_MODE=true only)
if [ "$MIXED_SSL_MODE" = "true" ] && [ "$HAS_CERTS" = "true" ]; then
    envsubst '${HAPROXY_BIND_IP}' \
        < /scripts/templates/frontend-https-mixed.cfg.tmpl >> "$HAPROXY_CFG"
fi

# Generate SSL offloading frontend with IP protection (FRONTEND_IP_PROTECTION=true only)
# Binds to a unix socket; the TCP frontend above proxies to it with send-proxy-v2-ssl-cn
if [ "$FRONTEND_IP_PROTECTION" = "true" ] && [ "$HAS_CERTS" = "true" ]; then
    envsubst '${ALT_SVC}' \
        < /scripts/templates/frontend-https-offloading-ip-protection.cfg.tmpl >> "$HAPROXY_CFG"
fi

PRIMARY_BIND="unix@/var/lib/haproxy/frontend-offloading.sock accept-proxy"
if [ "$MIXED_SSL_MODE" != "true" ]; then
    PRIMARY_BIND="${HAPROXY_BIND_IP}:443"
fi

# Generate main SSL offloading frontend (HTTP/2 + HTTP/3 QUIC)
# Binds directly to :443 in standard mode, or to a unix socket in MIXED_SSL_MODE
if [ "$HAS_CERTS" = "true" ]; then
    QUIC_BIND_PORT=$([ "$MIXED_SSL_MODE" = "true" ] && echo "8443" || echo "443")
    envsubst '${PRIMARY_BIND} ${HAPROXY_BIND_IP} ${QUIC_BIND_PORT} ${ALT_SVC}' \
        < /scripts/templates/frontend-https-offloading.cfg.tmpl >> "$HAPROXY_CFG"
fi

# Generate TCP backend that forwards to the SSL offloading unix socket (MIXED_SSL_MODE=true only)
if [ "$MIXED_SSL_MODE" = "true" ] && [ "$HAS_CERTS" = "true" ]; then
    cat /scripts/templates/backend-frontend-offloading.cfg.tmpl >> "$HAPROXY_CFG"
fi

# Generate TCP backend that forwards to the IP protection unix socket (FRONTEND_IP_PROTECTION=true only)
if [ "$FRONTEND_IP_PROTECTION" = "true" ] && [ "$HAS_CERTS" = "true" ]; then
    cat /scripts/templates/backend-frontend-offloading-ip-protection.cfg.tmpl >> "$HAPROXY_CFG"
fi

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
replace_placeholder "# \[HTTP-FRONTEND PLACEHOLDER\]" '.frontend.http.config[]' '    '
replace_placeholder "# \[HTTPS-FRONTEND-OFFLOADING PLACEHOLDER\]" '.frontend.https-offloading.config[]' '    '

if [ "$FRONTEND_IP_PROTECTION" = "true" ]; then
    replace_placeholder "# \[HTTPS-FRONTEND-OFFLOADING-IP-PROTECTION PLACEHOLDER\]" '.frontend.https-offloading-ip-protection.config[]' '    '
fi

if [ "$MIXED_SSL_MODE" = "true" ]; then
    replace_placeholder "# \[HTTPS-FRONTEND EXTRA PLACEHOLDER\]" '.frontend.https.config[]' '    '
elif [ "$FRONTEND_IP_PROTECTION" = "true" ]; then
    # Generate individual ACLs for frontend-offloading-ip-protection
    while read -r domain; do
        config="${config}    acl            https-offloading-ip-protection req.ssl_sni -i ${domain}
"
    done < <(echo "$JSON_CONFIG" | jq -r '.https_frontend_rules[] | select(.backend == "frontend-offloading-ip-protection") | select(.domains != null and (.domains | length > 0)) | .domains[]')
fi

# Function to generate HTTPS frontend configuration
generate_https_frontend_config() {
    local config=""

    debug_log "Generating ACLs and use_backend rules for HTTPS frontend"

    # Generate individual ACLs for frontend-offloading-ip-protection from the https-offloading-ip-protection frontend
    while read -r domain; do
        config="${config}    acl            https-offloading-ip-protection req.ssl_sni -i ${domain}
"
    done < <(echo "$JSON_CONFIG" | jq -r '.frontend["https-offloading-ip-protection"].domains[] | select(.backend == "frontend-offloading-ip-protection") | .patterns[]')

    # Generate individual ACLs for frontend-offloading from the https frontend
    while read -r domain; do
        config="${config}    acl            https-offloading req.ssl_sni -m end -i ${domain}
"
    done < <(echo "$JSON_CONFIG" | jq -r '.frontend.https.domains[] | select(.backend == "frontend-offloading") | .patterns[]')

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
    done < <(echo "$JSON_CONFIG" | jq -r '.domain_mappings[] | select(.frontend == "https-offloading" and .frontend != "https-offloading-ip-protection") | select(.domains != null and (.domains | length > 0)) | .domains[] + " " + .backend')

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
    done < <(echo "$JSON_CONFIG" | jq -r '.domain_mappings[] | select(.frontend == "https-offloading-ip-protection") | select(.domains != null and (.domains | length > 0)) | .domains[] + " " + .backend')

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
    done < <(echo "$JSON_CONFIG" | jq -r '.domain_mappings[] | select(.frontend == "https-offloading-ip-protection") | select(.domains != null and (.domains | length > 0)) | .domains[] + " " + .backend')

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
        # Single jq call to extract all scalar fields at once
        read -r name mode is_ssl ssl_verify enable_h2 use_send_proxy has_cache < <(
            echo "$backend" | jq -r '[
                .name,
                (.mode // "http"),
                (.ssl // false | tostring),
                (.ssl_verify // false | tostring),
                (.enable_h2 // false | tostring),
                (.use_send_proxy // false | tostring),
                (.cache == true | tostring)
            ] | @tsv'
        )

        debug_log "Processing backend: $name"

        # Skip this backend if essential information is missing
        if [ "$name" = "null" ] || [ -z "$name" ] ||
           [ "$mode" = "null" ] || [ -z "$mode" ]; then
            debug_log "Warning: Skipping backend with missing essential information. Name: $name, Mode: $mode" | ts '%Y-%m-%d %H:%M:%S'
            continue
        fi

        # Get hosts array
        if ! echo "$backend" | jq -e '.hosts | length > 0' > /dev/null 2>&1; then
            debug_log "Warning: No hosts defined for backend $name" | ts '%Y-%m-%d %H:%M:%S'
            continue
        fi

        # Handle options and other directives
        options_config=""
        if echo "$backend" | jq -e '.options | length > 0' > /dev/null 2>&1; then
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
        if echo "$backend" | jq -e '.http_check | length > 0' > /dev/null 2>&1; then
            # Add http-check directives without "option" prefix
            http_check_config=$(echo "$backend" | jq -r '.http_check[]? | "    http-check " + .')
        fi

        # Handle extra_config directives
        extra_config=""
        if echo "$backend" | jq -e '.extra_config | length > 0' > /dev/null 2>&1; then
            # Add extra_config directives without any prefix
            extra_config=$(echo "$backend" | jq -r '.extra_config[]? | "    " + .')
        fi

        health_check=""
        retries="retries 3"

        cache=""
        if [ "$has_cache" = "true" ]; then
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
            [ -z "$host_entry" ] && continue

            host_check=""
            host_enable_h2="false"

            # Check if the host entry is a simple string or a JSON object
            if [[ "$host_entry" == {* ]]; then
                # Single jq call for all host fields
                read -r host check_type check_interval check_fall check_rise check_slowstart check_uri host_h2 < <(
                    echo "$host_entry" | jq -r '[
                        .host,
                        (.check.type // "tcp"),
                        (.check.interval // "2000" | tostring),
                        (.check.fall // "3" | tostring),
                        (.check.rise // "2" | tostring),
                        (.check.slowstart // false | tostring),
                        (.check.uri // "/"),
                        (.enable_h2 // false | tostring)
                    ] | @tsv'
                )

                if echo "$host_entry" | jq -e '.check' > /dev/null 2>&1; then
                    host_check="check inter ${check_interval} fall ${check_fall} rise ${check_rise}"
                    if [ "$check_slowstart" != "false" ]; then
                        host_check="${host_check} slowstart ${check_slowstart}"
                    fi

                    # Add health check option based on check type if not already defined
                    if [ -z "$health_check" ]; then
                        case $check_type in
                            http)
                                health_check="option httpchk GET ${check_uri}"
                                ;;
                            ssl)
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
                host_enable_h2="$host_h2"
            else
                # Simple string host - no check config
                host="$host_entry"
            fi

            # Parse host to extract address and options (like 'backup')
            host_address=$(echo "$host" | awk '{print $1}' | tr -d '"')
            host_options=$(echo "$host" | cut -d' ' -f2- -s | tr -d '"')

            # If host explicitly sets enable_h2, use that value
            # Otherwise fall back to backend-level setting
            if [ "$host_enable_h2" = "false" ] && [ "$enable_h2" = "true" ]; then
                host_enable_h2="true"
            fi

            h2_options=""
            if [ "$host_enable_h2" = "true" ]; then
                h2_options=" alpn h2 check-reuse-pool idle-ping 30s"
            fi

            server_lines="${server_lines}    server ${name}-srv${server_count} ${host_address}${ssl_options:+ $ssl_options}${h2_options}${host_check:+ $host_check}${host_options:+ $host_options}${send_proxy:+ $send_proxy}
"
            server_count=$((server_count + 1))
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
    done
}

generate_https_offloading_frontend_config;

if [ "$FRONTEND_IP_PROTECTION" = "true" ]; then
    generate_https_offloading_ip_protection_frontend_config;
fi

if [ "$MIXED_SSL_MODE" = "true" ]; then
    generate_https_frontend_config;
fi

generate_backend_configs;

echo "[haproxy] Configuration generation complete." | ts '%Y-%m-%d %H:%M:%S'
