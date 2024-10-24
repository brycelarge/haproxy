#!/usr/bin/with-contenv bash
# shellcheck shell=bash

YAML_FILE=/config/haproxy.yaml
HAPROXY_CFG="/config/haproxy.cfg"
ACME_THUMBPRINT_PATH="/config/acme/ca/thumbprint"

# Remove existing config file if it exists and create a new one
[ -e "$HAPROXY_CFG" ] && rm "$HAPROXY_CFG"
touch "$HAPROXY_CFG"

# Loop until ACME_THUMBPRINT_PATH exists
while [ ! -f "$ACME_THUMBPRINT_PATH" ]; do
    echo "[haproxy] Waiting for $ACME_THUMBPRINT_PATH to be created before creating configuration..." | ts '%Y-%m-%d %H:%M:%S'
    sleep 3
done

THUMBPRINT=$(cat "${ACME_THUMBPRINT_PATH}")

# Remove existing config file if it exists and create a new one
[ -e "$HAPROXY_CFG" ] && rm "$HAPROXY_CFG"
touch "$HAPROXY_CFG"

source /scripts/debug.sh

echo "[haproxy] Generating configuration..." | ts '%Y-%m-%d %H:%M:%S'

# Generate HAProxy globals configuration
cat <<EOF >> "$HAPROXY_CFG"
global
    maxconn 4096
    daemon
    hard-stop-after 15m

    # Performance Optimizations
    nbthread 4
    cpu-map auto:1/1-4 0-3
    # tune.ssl.maxrecord 1400
    # tune.bufsize 32768

    # acme thumbprnt
    setenv ACCOUNT_THUMBPRINT '${THUMBPRINT}'

    # Default socket configurations
    # used for newer reload mechanism. See https://www.haproxy.com/blog/hitless-reloads-with-haproxy-howto/
    stats socket /var/lib/haproxy/admin.sock level admin mode 660 expose-fd listeners
    stats timeout 30s

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
    tune.ssl.lifetime 600

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
    log-format "[%[date,ltime(%Y-%m-%d %H:%M:%S)].%ms %[date,ltime(%z)]] %ci:%cp %ft %b/%s %TR/%Tw/%Tc/%Tr/%Ta %ST %B %CC %CS %tsc %ac/%fc/%bc/%sc/%rc %sq/%bq %hr %hs %{+Q}r %[ssl_fc_sni]"
    error-log-format "[%[date,ltime(%Y-%m-%d %H:%M:%S)].%ms %[date,ltime(%z)]] %ci:%cp %ft %ac/%fc %[fc_err_str]/%[ssl_fc_err,hex]/%[ssl_c_err]/%[ssl_c_ca_err]/%[ssl_fc_is_resumed] %{+Q}r %[ssl_fc_sni]/%sslv/%sslc"

EOF

# Generate HAProxy defaults configuration
cat <<EOF >> "$HAPROXY_CFG"
cache my-cache
    total-max-size 100     # MB
    max-object-size 100000 # bytes
    max-age 3600           # seconds
    process-vary on

EOF

cat <<'EOF' >> "$HAPROXY_CFG"
frontend http
    bind *:80
    mode http
    log	 global

    # ACME challenge
    http-request return status 200 content-type text/plain lf-string "%[path,field(-1,/)].${ACCOUNT_THUMBPRINT}\n" if { path_beg '/.well-known/acme-challenge/' }

    # Placed by yaml frontend http:
    # [HTTP-FRONTEND PLACEHOLDER]

    http-request set-header X-Forwarded-Proto https if { ssl_fc } # For Proto
    http-request add-header X-Real-Ip %[src] # Custom header with src IP
    option forwardfor # X-forwarded-for
    http-request redirect scheme https
EOF

# Generate HAProxy frontend https configuration
cat <<EOF >> "$HAPROXY_CFG"
frontend https
    bind        :443
	mode        tcp
	log			global
	acl         https ssl_fc
    tcp-request inspect-delay	1s
	tcp-request content accept if { req.ssl_hello_type 1 }

    # Placed by yaml https_frontend_rules
    # [HTTPS-FRONTEND USE_BACKEND PLACEHOLDER]

    # Placed by yaml domain_mappings
    # [HTTPS-FRONTEND EXTRA PLACEHOLDER]

EOF

# Generate HAProxy frontend https-offloading-ip-protection configuration
cat <<EOF >> "$HAPROXY_CFG"
frontend https-offloading-ip-protection
	bind			127.0.0.1:8443 name 127.0.0.1:8443 ssl crt /etc/haproxy/certs/ strict-sni alpn h3,h2,http/1.1
	bind            unix@/var/lib/haproxy/frontend-offloading-ip-protection.sock accept-proxy ssl crt /etc/haproxy/certs/ strict-sni alpn h3,h2,http/1.1

	mode			http
	log			    global
    option			http-keep-alive
	acl             https ssl_fc

	http-request    set-var(txn.txnhost) hdr(host)
	http-response   del-header ^Server:.*$
	http-response   del-header ^X-Powered.*$
    http-response   set-header X-Frame-Options sameorigin
    http-response   set-header Strict-Transport-Security "max-age=63072000"
	http-response   set-header X-XSS-Protection "1; mode=block"
	http-response   set-header Referrer-Policy no-referrer-when-downgrade

    http-after-response add-header alt-svc 'h3=":443"; ma=60'

    # Placed by yaml domain_mappings
    # [HTTPS-FRONTEND-OFFLOADING-IP-PROTECTION USE_BACKEND PLACEHOLDER]
    # Placed by yaml frontend https-offloading-ip-protection:
    # [HTTPS-FRONTEND-OFFLOADING-IP-PROTECTION PLACEHOLDER]
EOF

# Generate HAProxy frontend https-offloading configuration
cat <<EOF >> "$HAPROXY_CFG"
frontend https-offloading
	bind			127.0.0.1:8444 name 127.0.0.1:8444 ssl crt /etc/haproxy/certs/ strict-sni alpn h3,h2,http/1.1
	bind            unix@/var/lib/haproxy/frontend-offloading.sock accept-proxy ssl crt /etc/haproxy/certs/ strict-sni alpn h3,h2,http/1.1

	mode			http
	log			    global
    option			http-keep-alive
	option			forwardfor
	acl             https ssl_fc

	http-request    set-var(txn.txnhost) hdr(host)
	http-response   del-header ^Server:.*$
	http-response   del-header ^X-Powered.*$
    http-response   set-header X-Frame-Options sameorigin
    http-response   set-header Strict-Transport-Security "max-age=63072000"
	http-response   set-header X-XSS-Protection "1; mode=block"
	http-response   set-header Referrer-Policy no-referrer-when-downgrade

    http-after-response add-header alt-svc 'h3=":443"; ma=60'

    # Placed by yaml domain_mappings
    # [HTTPS-FRONTEND-OFFLOADING USE_BACKEND PLACEHOLDER]
    # Placed by yaml frontend https-offloading:
    # [HTTPS-FRONTEND-OFFLOADING PLACEHOLDER]

EOF

# Convert YAML to JSON
JSON_CONFIG=$(yq eval -o=json "$YAML_FILE")

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
replace_placeholder "# \[HTTPS-FRONTEND EXTRA PLACEHOLDER\]" '.frontend.https[]' '    '
replace_placeholder "# \[HTTPS-FRONTEND-OFFLOADING PLACEHOLDER\]" '.frontend.https-offloading[]' '    '
replace_placeholder "# \[HTTPS-FRONTEND-OFFLOADING-IP-PROTECTION PLACEHOLDER\]" '.frontend.https-offloading-ip-protection[]' '    '

# Function to generate HTTPS frontend configuration
generate_https_frontend_config() {
    local config=""
    
    debug_log "Generating ACLs and use_backend rules for HTTPS frontend"
    
    # Generate individual ACLs for frontend-offloading
    while read -r domain; do
        config="${config}    acl            https-offloading req.ssl_sni -m end -i ${domain}
"
    done < <(echo "$JSON_CONFIG" | jq -r '.https_frontend_rules[] | select(.backend == "frontend-offloading") | .domains[]')
    
    # Generate individual ACLs for frontend-offloading-ip-protection
    while read -r domain; do
        config="${config}    acl            https-offloading-ip-protection req.ssl_sni -i ${domain}
"
    done < <(echo "$JSON_CONFIG" | jq -r '.https_frontend_rules[] | select(.backend == "frontend-offloading-ip-protection") | .domains[]')
    
    # Add use_backend rules
    config="${config}    use_backend frontend-offloading if https-offloading
    use_backend frontend-offloading-ip-protection if https-offloading-ip-protection
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
    local backend_id=10
    local server_id=100

    debug_log "Generating backend configurations"
    echo "$JSON_CONFIG" | jq -c '.backends[]' | while read -r backend; do
        name=$(echo "$backend" | jq -r '.name')
        mode=$(echo "$backend" | jq -r '.mode')
        timeout_connect=$(echo "$backend" | jq -r '.timeout_connect')
        timeout_server=$(echo "$backend" | jq -r '.timeout_server')
        server_address=$(echo "$backend" | jq -r '.server_address')
        is_ssl=$(echo "$backend" | jq -r '.ssl // false')
        ssl_verify=$(echo "$backend" | jq -r '.ssl_verify // false')
        
        debug_log "Processing backend: $name"
        
        # Skip this backend if essential information is missing
        if [ "$name" = "null" ] || [ -z "$name" ] || 
           [ "$mode" = "null" ] || [ -z "$mode" ] || 
           [ "$server_address" = "null" ] || [ -z "$server_address" ]; then
            debug_log "Warning: Skipping backend with missing essential information. Name: $name, Mode: $mode, Server Address: $server_address" | ts '%Y-%m-%d %H:%M:%S'
            continue
        fi

        # Set default values for timeout if they are null or empty
        timeout_connect=${timeout_connect:-5000}
        timeout_server=${timeout_server:-50000}
        
        health_check=""
        retries="retries 3"
        cache=""
        
        # Special handling for frontend-offloading and frontend-offloading-ip-protection
        if [[ $name == "frontend-offloading" || $name == "frontend-offloading-ip-protection" ]]; then
            socket_path="/var/lib/haproxy/${name}.sock"
            server_line="server ${name}-srv unix@${socket_path} send-proxy-v2-ssl-cn"
            health_check="check inter 5000"
        else
            if echo "$backend" | jq -e '.check' > /dev/null; then
                check_type=$(echo "$backend" | jq -r '.check.type // "tcp"')
                check_interval=$(echo "$backend" | jq -r '.check.interval // "2000"')
                check_fall=$(echo "$backend" | jq -r '.check.fall // "3"')
                check_rise=$(echo "$backend" | jq -r '.check.rise // "2"')
                cache="acl is_image path_end -i .jpg .jpeg .png .gif
http-request cache-use my-cache if is_image
http-response cache-store my-cache if { res.hdr(Content-Type) -m sub image/ }
"
                
                health_check="check inter ${check_interval} fall ${check_fall} rise ${check_rise}"
                
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

            ssl_options=""
            if [ "$is_ssl" = "true" ]; then
                ssl_options="ssl"
                if [ "$ssl_verify" = "false" ]; then
                    ssl_options="${ssl_options} verify none"
                fi
            fi
            server_line="server ${name}-srv ${server_address}${ssl_options:+ $ssl_options}"
        fi

        debug_log "Server line for backend $name: $server_line ${health_check}"

        cat <<EOF >> "$HAPROXY_CFG"
backend $name
    mode $mode
    id $backend_id
    log global
    ${retries}
    ${server_line} ${health_check}
    ${cache}

EOF

        backend_id=$((backend_id + 1))
        server_id=$((server_id + 1))
    done
}

# Main execution
generate_https_frontend_config;
generate_https_offloading_frontend_config;
generate_https_offloading_ip_protection_frontend_config;
generate_backend_configs;

echo "[haproxy] Configuration generation complete." | ts '%Y-%m-%d %H:%M:%S'