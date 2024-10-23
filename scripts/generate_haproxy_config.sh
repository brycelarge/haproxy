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
    user haproxy
    group haproxy
    daemon
    hard-stop-after 15m
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

EOF

# Generate HAProxy defaults configuration
cat <<EOF >> "$HAPROXY_CFG"
defaults
    log global
    mode http
    # Placed by yaml defaults
    # [DEFAULTS PLACEHOLDER]

    # used for newer reload mechanism. See https://www.haproxy.com/blog/hitless-reloads-with-haproxy-howto/

    # For log-format see https://www.haproxy.com/documentation/hapee/latest/onepage/#8.2.3
    # For ltime see https://www.haproxy.com/documentation/hapee/latest/onepage/#ltime
    #
    # Use the terribly documented ltime() function.
    # No reference to it in the docs except function the api itself
    # Uses the same formatting params as strftime()
    #
    # C can't natively go more precise than seconds, but haproxy exposes the %ms
    # variable we can use here
    #
    # Our format here will produce 2021-01-01 08:00:01.565 +0200
    log-format "%ci:%cp [%[date,ltime(%Y-%m-%d %H:%M:%S)].%ms %[date,ltime(%z)]] %ft %b/%s %TR/%Tw/%Tc/%Tr/%Ta %ST %B %CC %CS %tsc %ac/%fc/%bc/%sc/%rc %sq/%bq %hr %hs %{+Q}r %[ssl_fc_sni]"
    # https://cbonte.github.io/haproxy-dconv/2.5/configuration.html#8.2.5
    # You can look up the ssl_fc_err with $ openssl errstr + the hex
    error-log-format "%ci:%cp [%[date,ltime(%Y-%m-%d %H:%M:%S)].%ms %[date,ltime(%z)]] %ft %ac/%fc %[fc_err_str]/%[ssl_fc_err,hex]/%[ssl_c_err]/%[ssl_c_ca_err]/%[ssl_fc_is_resumed] %{+Q}r %[ssl_fc_sni]/%sslv/%sslc"

EOF

cat <<'EOF' >> "$HAPROXY_CFG"
frontend http
    bind *:80

    # ACME challenge
    http-request return status 200 content-type text/plain lf-string "%[path,field(-1,/)].${ACCOUNT_THUMBPRINT}\n" if { path_beg '/.well-known/acme-challenge/' }

    # Placed by yaml frontend http:
    # [HTTP-FRONTEND PLACEHOLDER]

    acl https ssl_fc
    http-request set-header X-Forwarded-Proto http
    http-request redirect scheme https
EOF

# Generate HAProxy frontend https configuration
cat <<EOF >> "$HAPROXY_CFG"
frontend https
	mode        tcp
	log			global
	tcp-request inspect-delay	5s
    tcp-request content accept if { req.ssl_hello_type 1 }

    # Placed by yaml frontend https:
    # [HTTPS-FRONTEND PLACEHOLDER]

    # Placed by yaml https_frontend_rules
    # [HTTPS-FRONTEND USE_BACKEND PLACEHOLDER]
EOF

# Generate HAProxy frontend https-offloading-ip-protection configuration
cat <<EOF >> "$HAPROXY_CFG"
frontend https-offloading-ip-protection
	bind			127.0.0.1:8443 name 127.0.0.1:8443 ssl crt /config/acme/certs/default.pem crt /etc/haproxy/certs/ strict-sni alpn h3,h2,http/1.1
	mode			http
	log			    global
	timeout client	300000
	http-request    set-var(txn.txnhost) hdr(host)
    http-request    add-header X-Forwarded-Proto https
    http-response   set-header X-Frame-Options sameorigin

    # Placed by yaml frontend https-offloading-ip-protection:
    # [HTTPS-FRONTEND-OFFLOADING-IP-PROTECTION PLACEHOLDER]

    # Placed by yaml domain_mappings
    # [HTTPS-FRONTEND-OFFLOADING-IP-PROTECTION USE_BACKEND PLACEHOLDER]
EOF

# Generate HAProxy frontend https-offloading configuration
cat <<EOF >> "$HAPROXY_CFG"
frontend https-offloading
	bind			127.0.0.1:8444 name 127.0.0.1:8444 ssl crt /config/acme/certs/default.pem crt /etc/haproxy/certs/ strict-sni alpn h3,h2,http/1.1
	mode			http
	log			    global
	timeout client	300000
    http-after-response add-header alt-svc 'h3=":443"; ma=60'
    http-request add-header X-Forwarded-Proto https
    http-response set-header X-Frame-Options sameorigin

    # Placed by yaml frontend https-offloading:
    # [HTTPS-FRONTEND-OFFLOADING PLACEHOLDER]

    # Placed by yaml domain_mappings
    # [HTTPS-FRONTEND-OFFLOADING USE_BACKEND PLACEHOLDER]
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
replace_placeholder "# \[HTTPS-FRONTEND PLACEHOLDER\]" '.frontend.https[]' '    '
replace_placeholder "# \[HTTPS-FRONTEND-OFFLOADING PLACEHOLDER\]" '.frontend.https-offloading[]' '    '
replace_placeholder "# \[HTTPS-FRONTEND-OFFLOADING-IP-PROTECTION PLACEHOLDER\]" '.frontend.https-offloading-ip-protection[]' '    '

# Function to generate HTTPS frontend configuration
generate_https_frontend_config() {
    local config=""
    
    debug_log "Generating ACLs and use_backend rules for HTTPS frontend"
    
    # Generate ACLs for frontend-offloading and frontend-offloading-ip-protection
    config="${config}    acl frontend-offloading ssl_fc_sni_end"
    config="${config} $(echo "$JSON_CONFIG" | jq -r '.https_frontend_rules[] | select(.backend == "frontend-offloading") | .domains[]' | tr '\n' ' ')"
    config="${config}
"
    
    config="${config}    acl frontend-offloading-ip-protection ssl_fc_sni -i"
    config="${config} $(echo "$JSON_CONFIG" | jq -r '.https_frontend_rules[] | select(.backend == "frontend-offloading-ip-protection") | .domains[]' | tr '\n' ' ')"
    config="${config}
"
    
    # Generate use_backend rules based on the ACLs defined above
    config="${config}    use_backend frontend-offloading if frontend-offloading
"
    config="${config}    use_backend frontend-offloading-ip-protection if frontend-offloading-ip-protection
"
    
    if [ -n "$config" ]; then
        debug_log "Inserting generated config into HAPROXY_CFG"
        sed -i "/# \[HTTPS-FRONTEND USE_BACKEND PLACEHOLDER\]/r /dev/stdin" "$HAPROXY_CFG" << EOF
$config
EOF
        sed -i '/# \[HTTPS-FRONTEND USE_BACKEND PLACEHOLDER\]/d' "$HAPROXY_CFG"
    else
        debug_log "Warning: No HTTPS frontend rules generated." | ts '%Y-%m-%d %H:%M:%S'
    fi
    
    debug_log "Final generated config for HTTPS frontend:"
    debug_log "$config"
}

# Function to generate HTTPS offloading frontend configuration
generate_https_offloading_frontend_config() {
    local acl_config=""
    local backend_config=""
    
    debug_log "Generating configuration for https-offloading"
    while read -r domain backend offloading_match_condition; do
        if [ -n "$domain" ] && [ "$domain" != "null" ] && [ "$backend" != "null" ]; then
            debug_log "Processing domain: $domain"
            acl_config="${acl_config}    acl ${domain/./-} ${offloading_match_condition}
"
            backend_config="${backend_config}    use_backend ${backend} if ${domain/./-}
"
        fi
    done < <(echo "$JSON_CONFIG" | jq -r '.domain_mappings[] | select(.frontend == "https-offloading") | "\(.domain) \(.backend) \(.offloading_match_condition)"')
    
    local config="${acl_config}
${backend_config}"
    
    if [ -n "$config" ]; then
        debug_log "Inserting generated config into HAPROXY_CFG"
        sed -i "/# \[HTTPS-FRONTEND-OFFLOADING USE_BACKEND PLACEHOLDER\]/r /dev/stdin" "$HAPROXY_CFG" << EOF
$config
EOF
        sed -i '/# \[HTTPS-FRONTEND-OFFLOADING USE_BACKEND PLACEHOLDER\]/d' "$HAPROXY_CFG"
    else
        debug_log "[Haproxy] Warning: No HTTPS offloading frontend rules generated." | ts '%Y-%m-%d %H:%M:%S'
    fi
    
    debug_log "Final generated config for https-offloading frontend:"
    debug_log "$config"
}

# Function to generate HTTPS offloading IP protection frontend configuration
generate_https_offloading_ip_protection_frontend_config() {
    local acl_config=""
    local backend_config=""
    
    debug_log "Generating configuration for https-offloading-ip-protection frontend"
    while read -r domain backend offloading_match_condition; do
        if [ -n "$domain" ] && [ "$domain" != "null" ] && [ "$backend" != "null" ]; then
            debug_log "Processing domain: $domain"
            acl_config="${acl_config}    acl ${domain/./-} ${offloading_match_condition}
"
            backend_config="${backend_config}    use_backend ${backend} if ${domain/./-}
"
        fi
    done < <(echo "$JSON_CONFIG" | jq -r '.domain_mappings[] | select(.frontend == "https-offloading-ip-protection") | "\(.domain) \(.backend) \(.offloading_match_condition)"')
    
    local config="${acl_config}
${backend_config}"
    
    if [ -n "$config" ]; then
        debug_log "Inserting generated config into HAPROXY_CFG"
        sed -i "/# \[HTTPS-FRONTEND-OFFLOADING-IP-PROTECTION USE_BACKEND PLACEHOLDER\]/r /dev/stdin" "$HAPROXY_CFG" << EOF
$config
EOF
        sed -i '/# \[HTTPS-FRONTEND-OFFLOADING-IP-PROTECTION USE_BACKEND PLACEHOLDER\]/d' "$HAPROXY_CFG"
    else
        debug_log "Warning: No HTTPS offloading IP protection frontend rules generated." | ts '%Y-%m-%d %H:%M:%S'
    fi
    
    debug_log "Final generated config for https-offloading-ip-protection frontend:"
    debug_log "$config"
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
    timeout connect ${timeout_connect}
    timeout server ${timeout_server}
    ${retries}
    ${server_line} ${health_check}
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