#!/usr/bin/with-contenv bash
# shellcheck shell=bash

if [ -f /etc/profile ]; then
    source /etc/profile
fi

# Variables
USER="acme"
HOME_DIR="/config/acme"
CERT_HOME="/config/acme/certs"
HAPROXY_CERTS_DIR="/etc/haproxy/certs"
LOG_FILE="/var/log/acme-renewals.log"
HAPROXY_YAML="/config/haproxy.yaml"

# determine the challenge type
ACME_CHALLENGE_TYPE="${ACME_CHALLENGE_TYPE:-dns_cf}"

chown haproxy:haproxy /etc/haproxy/certs
chmod 770 /etc/haproxy/certs

source /scripts/debug.sh;
source /scripts/acme_lock.sh;

install_acme() {
    # Check if email is empty
    if [ -z "$ACME_EMAIL" ]; then
        echo "[acme] Error: ACME_EMAIL env is not set" | ts '%Y-%m-%d %H:%M:%S'
        exit 0
    fi

    echo "[acme] Installing acme.sh...." | ts '%Y-%m-%d %H:%M:%S'

    # Download the master branch archive
    cd /config/;
    curl -L -o acme.sh.zip https://github.com/acmesh-official/acme.sh/archive/master.zip

    # Extract the archive
    unzip -q acme.sh.zip

    # Move to the extracted directory
    cd acme.sh-master
    # Set permissions
    chmod 755 acme.sh

    # install as root then convert to itetech user
    bash acme.sh \
        --install \
        --nocron \
        --home "${HOME_DIR}" \
        --config-home "${HOME_DIR}" \
        --cert-home "${CERT_HOME}" \
        --accountemail "${ACME_EMAIL}";

    cd /config;
    rm -rf acme.sh-master;

    debug_log "${HOME_DIR} ${CERT_HOME} ${ACME_EMAIL}"

    # Check if installation was successful
    if [ ! -f "${HOME_DIR}/acme.sh" ] || [ ! -f "${HOME_DIR}/acme.sh.env" ]; then
        echo "[acme] Installation failed" | ts '%Y-%m-%d %H:%M:%S'
        exit 0
    fi

    chown -R ${USER}:${USER} /config/acme;
    echo "[acme] Installed successfully" | ts '%Y-%m-%d %H:%M:%S'

    # Create environment file
    echo "[acme] Setting up acme environment variables..." | ts '%Y-%m-%d %H:%M:%S'

    # Create environment file
    s6-setuidgid "${USER}" cat <<EOF > "${HOME_DIR}/acme.sh.env"
# HAProxy deployment settings
export DEPLOY_HAPROXY_HOT_UPDATE=yes
export DEPLOY_HAPROXY_STATS_SOCKET=/var/lib/haproxy/admin.sock
export DEPLOY_HAPROXY_PEM_PATH=/etc/haproxy/certs

# ACME core settings
export LE_WORKING_DIR=/config/acme
export LE_CONFIG_HOME=/config/acme
export CERT_HOME=/config/acme/certs

# Debug and logging
export LOG_LEVEL=\${LOG_LEVEL:-2}

# ACME server settings
export ACME_SERVER=https://acme-v02.api.letsencrypt.org/directory
export DEFAULT_ACME_SERVER=\${ACME_SERVER}

# Verification method (http is default, can be overridden)
export ACME_VERIFY_METHOD=\${ACME_VERIFY_METHOD:-http}

# Optional Cloudflare settings (only used if ACME_VERIFY_METHOD=dns_cf)
export CF_Token=\${CF_Token:-}
export CF_Account_ID=\${CF_Account_ID:-}
export CF_Zone_ID=\${CF_Zone_ID:-}
export CF_Key=\${CF_Key:-}
export CF_Email=\${CF_Email:-}
EOF

    # Set permissions on env file
    chmod 600 "${HOME_DIR}/acme.sh.env"
    chown "${USER}:${USER}" "${HOME_DIR}/acme.sh.env"

    echo "[acme] Installation completed successfully" | ts '%Y-%m-%d %H:%M:%S'
}

register_acme() {
    echo "[acme] registering an account with letsencrypt..." | ts '%Y-%m-%d %H:%M:%S'

    # Register account with letsencrypt
    source "$HOME_DIR/acme.sh.env";
    s6-setuidgid ${USER} "$HOME_DIR/acme.sh" \
        --register-account \
        --accountemail "${ACME_EMAIL}" \
        --stateless \
        --home "${HOME_DIR}" \
        --config-home "${HOME_DIR}" \
        --cert-home "${CERT_HOME}" \
        --debug > /tmp/acme_reg.log 2>&1

    # Extract and save thumbprint
    THUMBPRINT=$(grep "ACCOUNT_THUMBPRINT" /tmp/acme_reg.log | cut -d"'" -f2)
    echo "[acme] account THUMBPRINT: ${THUMBPRINT}" | ts '%Y-%m-%d %H:%M:%S';
    echo "${THUMBPRINT}" >> /config/acme/ca/thumbprint;
}

issue_cert() {
    if ! acquire_lock; then
        return 1
    fi

    trap cleanup EXIT

    local hot_update=${2:-"yes"}

    # If hot_update is "block", treat it as "no"
    if [ "$hot_update" = "block" ]; then
        hot_update="no"
    fi

    if [ "$DEBUG" = "true" ]; then
        DEBUG_FLAG="--debug"
    else
        DEBUG_FLAG=""
    fi

    if [ "$ACME_CHALLENGE_TYPE" = "http" ]; then
        echo "[acme] Attempting to issue ${1} using HTTP challenge with standalone mode" | ts '%Y-%m-%d %H:%M:%S'
        add_domain_to_haproxy "$1"

        source "$HOME_DIR/acme.sh.env";
        ACME_OUTPUT=$(s6-setuidgid ${USER} "$HOME_DIR/acme.sh" ${DEBUG_FLAG} \
            --issue \
            --stateless \
            -d "${1}" 2>&1)

        debug_log "$ACME_OUTPUT"
        release_lock;

        if echo "$ACME_OUTPUT" | grep -q "Error"; then
            echo "[acme] Certificate issuance failed for ${1}" | ts '%Y-%m-%d %H:%M:%S'
            return 1;
        elif echo "$ACME_OUTPUT" | grep -q "key authorization file from the server did not match this challenge"; then
            echo "[acme] Certificate issuance failed due to key authorization error for ${1}" | ts '%Y-%m-%d %H:%M:%S'
            return 1;
        fi
    else
        echo "[acme] Attempting to issue ${1} using DNS challenge (Cloudflare)" | ts '%Y-%m-%d %H:%M:%S';

        source "$HOME_DIR/acme.sh.env";
        ACME_OUTPUT=$(s6-setuidgid ${USER} "$HOME_DIR/acme.sh" ${DEBUG_FLAG} \
            --issue \
            --dns dns_cf \
            -d "${1}" 2>&1)

        debug_log "$ACME_OUTPUT"
        release_lock;

        if echo "$ACME_OUTPUT" | grep -q "Error"; then
            echo "[acme] Certificate issuance failed for ${1}" | ts '%Y-%m-%d %H:%M:%S'
            return 1;
        fi
    fi

    deploy_cert "${1}" "${hot_update}";
}

deploy_cert() {
    local hot_update=${2:-"yes"}

    # If hot_update is "block", treat it as "no"
    if [ "$hot_update" = "block" ]; then
        hot_update="no"
    fi

    local domain="${1}"
    local cert_path="/etc/haproxy/certs/${domain}.pem"

    if [ "$DEBUG" = "true" ]; then
        DEBUG_FLAG="--debug"
    else
        DEBUG_FLAG=""
    fi

    echo "[acme] Deploying ssl certificate for: ${domain}" | ts '%Y-%m-%d %H:%M:%S';

    {
        # Change to acme.sh directory first
        cd $HOME_DIR;

        source "$HOME_DIR/acme.sh.env";
        ACME_OUTPUT=$(DEPLOY_HAPROXY_HOT_UPDATE="$hot_update" s6-setuidgid ${USER} "$HOME_DIR/acme.sh" ${DEBUG_FLAG} \
            --deploy -d "${domain}" \
            --deploy-hook haproxy 2>&1)

        debug_log "$ACME_OUTPUT"

        if ! echo "$ACME_OUTPUT" | grep -q "Success"; then
            echo "[acme] Certificate deployment failed for: ${domain}" | ts '%Y-%m-%d %H:%M:%S'
            return 1
        fi

        # Verify certificate exists and is valid
        if [ -f "$cert_path" ] && openssl x509 -in "$cert_path" -noout -checkend 0 >/dev/null 2>&1; then
            echo "[acme] Certificate successfully deployed and validated for: ${domain}" | ts '%Y-%m-%d %H:%M:%S'
            kill -HUP $(pidof rsyslogd)
            return 0
        else
            echo "[acme] Warning: Certificate deployment completed but validation failed for: ${domain}" | ts '%Y-%m-%d %H:%M:%S'
            return 1
        fi
    } || {
        echo "[acme] Certificate failed to deploy for: ${domain}, check your DNS!" | ts '%Y-%m-%d %H:%M:%S';
        # remove the empty file
        if [ -f "$cert_path" ]; then
            rm -f "$cert_path"
        fi
        return 1
    }
}

renew_cert() {
    if ! acquire_lock; then
        return 1
    fi

    trap cleanup EXIT
    local hot_update=${2:-"yes"}

    # If hot_update is "block", treat it as "no"
    if [ "$hot_update" = "block" ]; then
        hot_update="no"
    fi

    local domain="${1}"

    source "$HOME_DIR/acme.sh.env";

    echo "[acme] Running renewal for ${domain}" | ts '%Y-%m-%d %H:%M:%S'
    add_domain_to_haproxy "$domain"

    if [ "$DEBUG" = "true" ]; then
        DEBUG_FLAG="--debug"
    else
        DEBUG_FLAG=""
    fi

    ACME_OUTPUT=$(s6-setuidgid ${USER} "$HOME_DIR/acme.sh" ${DEBUG_FLAG} \
        --renew \
        --stateless \
        -d "${domain}" 2>&1)

    debug_log " /config/acme/http.header contents: $(cat /config/acme/http.header)";
    debug_log "$ACME_OUTPUT";
    release_lock;

    # Check if renewal was successful
    if echo "$ACME_OUTPUT" | grep -q "Skip, Next renewal time is:"; then
        echo "[acme] Certificate for ${domain} is not due for renewal yet" | ts '%Y-%m-%d %H:%M:%S'
        return 0;
    fi

    if echo "$ACME_OUTPUT" | grep -q "Error"; then
        echo "[acme] Certificate renewal failed for ${domain}" | ts '%Y-%m-%d %H:%M:%S'
        return 1;
    elif echo "$ACME_OUTPUT" | grep -q "key authorization file from the server did not match this challenge"; then
        echo "[acme] Certificate renewal failed due to key authorization error for ${domain}" | ts '%Y-%m-%d %H:%M:%S'
        return 1;
    fi

    # Check if certificate was renewed
    if [ ! -f "${CERT_HOME}/${domain}_ecc/${domain}.cer" ]; then
        echo "[acme] Certificate was not renewed for ${domain}, skipping deployment" | ts '%Y-%m-%d %H:%M:%S'
        return 1;
    fi

    deploy_cert "${domain}" "${hot_update}";
}

extract_domains() {
    yq e '.domain_mappings[].domains[]' "$HAPROXY_YAML" | grep -v '^null$' | sort | uniq
}

function check_for_missing_domain_certs() {
    # Should we reload haproxy
    local hot_update=${1:-"yes"}
    local certs_updated=false

    # Wait for HAProxy to fully initialize
    debug_log "[acme] Waiting for HAProxy to fully initialize before processing certificates..." | ts '%Y-%m-%d %H:%M:%S'
    sleep 5

    # Verify HAProxy is running by checking the socket
    if [ -S "/var/lib/haproxy/admin.sock" ]; then
        if ! echo "show info" | socat stdio "unix-connect:/var/lib/haproxy/admin.sock" &>/dev/null; then
            debug_log "[acme] Warning: HAProxy is not responding, but proceeding anyway..." | ts '%Y-%m-%d %H:%M:%S'
        else
            debug_log "[acme] HAProxy is running and responsive" | ts '%Y-%m-%d %H:%M:%S'
        fi
    else
        debug_log "[acme] Warning: HAProxy socket not found, but proceeding anyway..." | ts '%Y-%m-%d %H:%M:%S'
    fi

    # Create an array of domains
    mapfile -t domains < <(extract_domains)

    # Print the number of domains found
    echo "[acme] Found ${#domains[@]} domains in your haproxy.yaml file, going through them to see if we need to issue or renew..." | ts '%Y-%m-%d %H:%M:%S'

    FAILED_DOMAINS=()

    # Loop through the domains and process them
    for domain in "${domains[@]}"; do
        debug_log "Processing domain: $domain" | ts '%Y-%m-%d %H:%M:%S'
        {
            if [ -f "${HAPROXY_CERTS_DIR}/${domain}.pem" ]; then
                debug_log "Certificate for $domain is deployed in haproxy" | ts '%Y-%m-%d %H:%M:%S'

                # Check expiration
                expiration=$(openssl x509 -enddate -noout -in "${HAPROXY_CERTS_DIR}/${domain}.pem" | cut -d= -f2)
                debug_log "$domain Certificate expires on: $expiration" | ts '%Y-%m-%d %H:%M:%S'

                # Convert expiration date to seconds since epoch using /bin/date
                expiration_seconds=$(date -d "$expiration" +%s 2>/dev/null || date -D "%b %d %H:%M:%S %Y %Z" -d "$expiration" +%s)
                thirty_days_from_now=$(date -d "+30 days" +%s 2>/dev/null || date -d "$(date +%Y-%m-%d) +30 days" +%s)

                # Add logic to renew if close to expiration
                if [ "$expiration_seconds" -lt "$thirty_days_from_now" ]; then
                    echo "[acme] $domain Certificate will expire soon, renewing..." | ts '%Y-%m-%d %H:%M:%S'
                    if renew_cert "$domain" "$hot_update"; then
                        certs_updated=true
                    fi
                fi
            else
                # Check if certificate exists in ACME directory
                if [ -f "${CERT_HOME}/${domain}_ecc/${domain}.cer" ]; then
                    echo "[acme] $domain certificate exists in acme directory but not deployed, validating before deployment..." | ts '%Y-%m-%d %H:%M:%S'

                    # Validate the certificate in ACME directory
                    if [ -f "${CERT_HOME}/${domain}_ecc/${domain}.cer" ]; then
                        # Check certificate validity
                        cert_expiration=$(openssl x509 -enddate -noout -in "${CERT_HOME}/${domain}_ecc/${domain}.cer" | cut -d= -f2)
                        debug_log "$domain ACME certificate expires on: $cert_expiration" | ts '%Y-%m-%d %H:%M:%S'

                        # Convert expiration date to seconds since epoch
                        cert_expiration_seconds=$(date -d "$cert_expiration" +%s 2>/dev/null || date -D "%b %d %H:%M:%S %Y %Z" -d "$cert_expiration" +%s)
                        current_time=$(date +%s)

                        # Check if certificate is valid (not expired)
                        if [ "$cert_expiration_seconds" -gt "$current_time" ]; then
                            echo "[acme] $domain certificate in acme directory is valid, deploying..." | ts '%Y-%m-%d %H:%M:%S'
                            if deploy_cert "$domain" "$hot_update"; then
                                certs_updated=true
                            fi
                        else
                            echo "[acme] $domain certificate in acme directory is expired, issuing new certificate..." | ts '%Y-%m-%d %H:%M:%S'
                            if issue_cert "$domain" "$hot_update"; then
                                certs_updated=true
                            fi
                        fi
                    else
                        echo "[acme] $domain certificate file not found in expected location, issuing new certificate..." | ts '%Y-%m-%d %H:%M:%S'
                        if issue_cert "$domain" "$hot_update"; then
                            certs_updated=true
                        fi
                    fi
                else
                    echo "[acme] $domain certificate does not exist, issuing new certificate..." | ts '%Y-%m-%d %H:%M:%S'
                    if issue_cert "$domain" "$hot_update"; then
                        certs_updated=true
                    fi
                fi
            fi
        } || {
            echo "[acme] Failed to process ${domain}, moving to next domain..." | ts '%Y-%m-%d %H:%M:%S'
            FAILED_DOMAINS+=("$domain")
            continue
        }
    done

    # Report any failed domains
    if [ ${#FAILED_DOMAINS[@]} -gt 0 ]; then
        echo "[acme] The following domains failed processing:" | ts '%Y-%m-%d %H:%M:%S'
        printf '%s\n' "${FAILED_DOMAINS[@]}" | ts '%Y-%m-%d %H:%M:%S'
    fi

    # If hot_update is "no" but certificates were updated, reload HAProxy
    if [ "$hot_update" = "no" ] && [ "$certs_updated" = true ]; then
        echo "[acme] Certificates were updated and hot_update is disabled, reloading HAProxy..." | ts '%Y-%m-%d %H:%M:%S'
        if [ -f "/scripts/reload-haproxy.sh" ]; then
            /scripts/reload-haproxy.sh
        else
            echo "[acme] Error: reload-haproxy.sh script not found" | ts '%Y-%m-%d %H:%M:%S'
        fi
    fi
}

# Add a new function to add the domain to the HAProxy stick table
add_domain_to_haproxy() {
    local DOMAIN="$1"
    local SOCAT_SOCKET="/var/lib/haproxy/admin.sock"

    if [ -z "$DOMAIN" ]; then
        echo "[acme] No domain provided" | ts '%Y-%m-%d %H:%M:%S'
        return 1
    fi

    # Check if socket exists
    if [ ! -S "$SOCAT_SOCKET" ]; then
        echo "[acme] HAProxy socket not found" | ts '%Y-%m-%d %H:%M:%S'
        return 1
    fi

    echo "[acme] Adding domain to stick table: ${DOMAIN}" | ts '%Y-%m-%d %H:%M:%S'

    # Add the full domain to the stick table and set counter to 1
    # Use the correct syntax: set table <table> key <key> [data.<type> <value>]
    if ! echo "set table http key ${DOMAIN} data.http_req_cnt 1" | socat stdio "unix-connect:${SOCAT_SOCKET}" &>/dev/null; then
        echo "[acme] ERROR: Failed to add domain to stick table" | ts '%Y-%m-%d %H:%M:%S'
        return 1
    fi

    # Extract domain without the first subdomain part - handles domains with multiple levels
    if [[ "$DOMAIN" == *"."*"."* ]]; then
        # Domain has at least one subdomain, remove the first part
        MAIN_DOMAIN=$(echo "$DOMAIN" | cut -d. -f2-)
        echo "[acme] Adding main domain to stick table: ${MAIN_DOMAIN}" | ts '%Y-%m-%d %H:%M:%S'

        if ! echo "set table http key ${MAIN_DOMAIN} data.http_req_cnt 1" | socat stdio "unix-connect:${SOCAT_SOCKET}" &>/dev/null; then
            echo "[acme] Warning: Failed to add main domain to stick table" | ts '%Y-%m-%d %H:%M:%S'
            # Don't return error here to avoid failing the entire process
        fi
    fi

    # Verify domains were added
    echo "[acme] Verifying domains in stick table..." | ts '%Y-%m-%d %H:%M:%S'
    TABLE_CONTENTS=$(echo "show table http" | socat stdio "unix-connect:${SOCAT_SOCKET}" 2>/dev/null)
    if ! echo "$TABLE_CONTENTS" | grep -q -E "${DOMAIN}|${MAIN_DOMAIN}"; then
        echo "[acme] ERROR: domain ${DOMAIN} not found in stick table after adding" | ts '%Y-%m-%d %H:%M:%S'
        debug_log "$TABLE_CONTENTS"
        return 1
    fi

    echo "[acme] Successfully verified domain(s) in stick table" | ts '%Y-%m-%d %H:%M:%S'

    sleep 2
    return 0
}
