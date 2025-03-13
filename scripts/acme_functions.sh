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
export DEBUG=\${DEBUG:-1}
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

    setup_acme_renewal
}

issue_cert() {
    if ! acquire_lock; then
        return 1
    fi

    trap cleanup EXIT
    local hot_update=${2:-"yes"}
    source /config/acme/acme.sh.env;

    echo "[acme] Attempting to issue ${1}" | ts '%Y-%m-%d %H:%M:%S';

    if [ "$ACME_CHALLENGE_TYPE" = "http" ]; then
        echo "[acme] Using HTTP challenge with standalone mode" | ts '%Y-%m-%d %H:%M:%S'
        
        # Run acme.sh and capture the output directly
        ACME_OUTPUT=$(s6-setuidgid ${USER} "$HOME_DIR/acme.sh" \
            --issue \
            --stateless \
            -d "${1}" \
            --debug 2>&1) || {
                echo "[acme] Failed to issue certificate for ${1}" | ts '%Y-%m-%d %H:%M:%S'
                release_lock;
                return 1;
            };
        
        # Extract token directly from the command output
        CHALLENGE_TOKEN=$(echo "$ACME_OUTPUT" | grep -o "Adding challenge entry '[^']*'" | cut -d "'" -f 2)
        if [ -z "$CHALLENGE_TOKEN" ]; then
            CHALLENGE_TOKEN=$(echo "$ACME_OUTPUT" | grep -o "http-01 challenge for [^:]*: [^,]*" | cut -d ":" -f 2 | tr -d " ")
        fi
        
        if [ -n "$CHALLENGE_TOKEN" ]; then
            # Store directly in HAProxy's stick table using socket API
            HAPROXY_SOCKET="/var/lib/haproxy/admin.sock"
            if [ -S "$HAPROXY_SOCKET" ]; then
                # Just add the token to the stick table - value doesn't matter, just marking it as valid
                echo "set table http key ${CHALLENGE_TOKEN} data 1" | socat - "unix-connect:${HAPROXY_SOCKET}"
                echo "[acme] Added token to HAProxy stick table: $CHALLENGE_TOKEN" | ts '%Y-%m-%d %H:%M:%S'
                echo "[acme] Token will auto-expire after 5 minutes" | ts '%Y-%m-%d %H:%M:%S'
            else
                echo "[acme] Warning: HAProxy socket not found, cannot store token" | ts '%Y-%m-%d %H:%M:%S'
            fi
        else
            echo "[acme] Warning: Failed to extract challenge token from output" | ts '%Y-%m-%d %H:%M:%S'
        fi
    else
        echo "[acme] Using DNS challenge (Cloudflare)" | ts '%Y-%m-%d %H:%M:%S';
        s6-setuidgid ${USER} "$HOME_DIR/acme.sh" \
            --issue \
            --stateless \
            --dns dns_cf \
            -d "${1}" || {
                release_lock;
                return 1;
            };
    fi

    release_lock;

    # If certificate was issued successfully deploy it
    deploy_cert "${1}" "${hot_update}"
}

deploy_cert() {
    local hot_update=${2:-"yes"}
    echo "[acme] Deploying ssl certificate for: ${1}" | ts '%Y-%m-%d %H:%M:%S';

    {
        # Change to acme.sh directory first
        cd $HOME_DIR;

        source "$HOME_DIR/acme.sh.env";
        DEPLOY_HAPROXY_HOT_UPDATE="$hot_update" s6-setuidgid ${USER} "$HOME_DIR/acme.sh" \
            --deploy -d "${1}" \
            --deploy-hook haproxy;

        echo "[acme] Certificate successfully deployed for:${1}" | ts '%Y-%m-%d %H:%M:%S';
    } || {
        echo "[acme] Certificate failed to deploy for:${1}, check your DNS!" | ts '%Y-%m-%d %H:%M:%S';
        # remove the empty file
        if [ -f "/etc/haproxy/certs/${1}.pem" ]; then
            rm -f "/etc/haproxy/certs/${1}.pem"
        fi
    }
}

renew_cert() {
    if ! acquire_lock; then
        return 1
    fi

    trap cleanup EXIT
    local hot_update=${2:-"yes"}

    source "$HOME_DIR/acme.sh.env";
    s6-setuidgid ${USER} /config/acme/acme.sh \
        --renew -d "${1}"

    release_lock;
    deploy_cert "${1}" "${hot_update}";
}

# Function to extract domains from the YAML file
extract_domains() {
    yq e '.domain_mappings[].domain' "$HAPROXY_YAML" | sort | uniq
}

function check_for_missing_domain_certs() {
    # Should we reload haproxy
    local hot_update=${1:-"yes"}

    # Wait for HAProxy to fully initialize
    echo "[acme] Waiting for HAProxy to fully initialize before processing certificates..." | ts '%Y-%m-%d %H:%M:%S'
    sleep 10
    
    # Verify HAProxy is running by checking the socket
    if [ -S "/var/lib/haproxy/admin.sock" ]; then
        if ! echo "show info" | socat stdio "unix-connect:/var/lib/haproxy/admin.sock" &>/dev/null; then
            echo "[acme] Warning: HAProxy is not responding, but proceeding anyway..." | ts '%Y-%m-%d %H:%M:%S'
        else
            echo "[acme] HAProxy is running and responsive" | ts '%Y-%m-%d %H:%M:%S'
        fi
    else
        echo "[acme] Warning: HAProxy socket not found, but proceeding anyway..." | ts '%Y-%m-%d %H:%M:%S'
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
                    renew_cert "$domain" "$hot_update"
                fi
            else
                # Check if certificate exists in ACME directory
                if [ -f "${CERT_HOME}/${domain}_ecc/${domain}.cer" ]; then
                    echo "[acme] $domain certificate exists in acme directory but not deployed, deploying..." | ts '%Y-%m-%d %H:%M:%S'
                    deploy_cert "$domain" "$hot_update"
                else
                    echo "[acme] $domain certificate does not exist, issuing new certificate..." | ts '%Y-%m-%d %H:%M:%S'
                    issue_cert "$domain" "$hot_update"
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
}

verify_cron() {
    echo "[acme] Verifying ACME cron job and installing if it does not exist" | ts '%Y-%m-%d %H:%M:%S'

    # Check if cron job exists
    if ! s6-setuidgid "$USER" crontab -l 2>/dev/null | grep -q "/usr/local/bin/renew-certs.sh"; then
        setup_acme_renewal
    fi
}

function setup_acme_renewal() {
    echo "[acme] Setting up ACME certificate renewal job" | ts '%Y-%m-%d %H:%M:%S'

    # Ensure log file exists and has correct permissions
    touch "$LOG_FILE"
    chown "${USER}:${USER}" "$LOG_FILE"
    chmod 640 "$LOG_FILE"

    # Create the renewal script
    cat << 'EOF' > /usr/local/bin/renew-certs.sh
#!/usr/bin/with-contenv bash

# Ensure all required packages are available
if ! command -v socat &> /dev/null; then
    echo "Error: socat not found. Please install it."
    exit 1
fi

# Source environment variables and make path available
if [ -f /etc/profile ]; then
    source /etc/profile
fi

export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH"

# Source environment variables
if [ -f /config/acme/acme.sh.env ]; then
    source /config/acme/acme.sh.env
else
    echo "Error: /config/acme/acme.sh.env not found"
    exit 1
fi

# make sure acme is not running multiple times
if [ -f /scripts/acme_lock.sh ]; then
    source /scripts/acme_lock.sh
else
    echo "Error: /scripts/acme_lock.sh not found"
    exit 1
fi

# Lock file path
LOCK_FILE="/tmp/acme.lock"

# Log file path
LOG_FILE="/var/log/acme-renewals.log"

# Function to log messages
log_message() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [acme] - $1" | tee -a "$LOG_FILE"
}

log_message "Starting certificate renewal process"

# Main renewal process
if ! acquire_lock; then
    log_message "Another ACME process is running, skipping renewal"
    exit 1
fi

trap cleanup EXIT

# HAProxy socket check
HAPROXY_SOCKET="/var/lib/haproxy/admin.sock"
if [ ! -S "$HAPROXY_SOCKET" ]; then
    log_message "Error: HAProxy socket not found at $HAPROXY_SOCKET"
    exit 1
fi

# Function to verify HAProxy is running
verify_haproxy() {
    if ! echo "show info" | socat stdio "unix-connect:$HAPROXY_SOCKET" &>/dev/null; then
        log_message "Error: HAProxy is not responding"
        return 1
    fi
    return 0
}

# Check HAProxy before proceeding
if ! verify_haproxy; then
    log_message "Aborting: HAProxy is not operational"
    exit 1
fi

# Function to renew a single certificate
renew_certificate() {
    local domain="$1"
    log_message "Starting renewal for ${domain}"
    
    # Debug output - show environment 
    env >> "$LOG_FILE" 2>&1
    
    # Check if acme.sh exists
    if [ ! -f "/config/acme/acme.sh" ]; then
        log_message "Error: acme.sh not found at /config/acme/acme.sh"
        return 1
    fi
    
    # Ensure we have write permissions to cert directories
    if [ ! -w "/config/acme/certs" ] || [ ! -w "/etc/haproxy/certs" ]; then
        log_message "Error: Missing write permissions to certificate directories"
        return 1
    fi

    # Run renewal with verbose output
    log_message "Executing renew command for ${domain}"
    /config/acme/acme.sh \
        --renew -d "${domain}" \
        --force --debug >> "$LOG_FILE" 2>&1 || {
            log_message "Failed to renew certificate for ${domain}"
            return 1
        }

    # Deploy the renewed certificate
    log_message "Deploying renewed certificate for ${domain}"
    /config/acme/acme.sh \
        --deploy -d "${domain}" \
        --deploy-hook haproxy --debug >> "$LOG_FILE" 2>&1 || {
            log_message "Failed to deploy certificate for ${domain}"
            return 1
        }

    log_message "Successfully renewed and deployed certificate for ${domain}"
    return 0
}

# Get list of all domains with certificates
log_message "Scanning for domains that need renewal"
DOMAINS_FOUND=0
if [ -d "/config/acme/certs" ]; then
    find /config/acme/certs -name "*.conf" | while read -r conf_file; do
        domain=$(basename "$conf_file" .conf)
        log_message "Found domain: $domain"
        DOMAINS_FOUND=$((DOMAINS_FOUND+1))
        renew_certificate "$domain"
    done
else
    log_message "Error: Certificate directory /config/acme/certs not found"
fi

if [ "$DOMAINS_FOUND" -eq 0 ]; then
    log_message "No domains found for renewal. Checking YAML file."
    
    # If no domains found in certs directory, try to get domains from yaml
    if [ -f "/config/haproxy.yaml" ]; then
        if command -v yq &> /dev/null; then
            DOMAINS=$(yq e '.domain_mappings[].domain' "/config/haproxy.yaml" | sort | uniq)
            if [ -n "$DOMAINS" ]; then
                log_message "Found domains in YAML file: $DOMAINS"
                echo "$DOMAINS" | while read -r domain; do
                    renew_certificate "$domain"
                done
            else
                log_message "No domains found in YAML file"
            fi
        else
            log_message "Warning: yq command not found, cannot extract domains from YAML"
        fi
    else
        log_message "Warning: /config/haproxy.yaml not found"
    fi
fi

log_message "Certificate renewal process completed"
EOF

    # Make the renewal script executable
    chmod +x /usr/local/bin/renew-certs.sh
    chown "${USER}:${USER}" /usr/local/bin/renew-certs.sh

    # Instead of using crontab, we'll create a direct cron entry in /etc/cron.d
    echo "[acme] Creating renewal job in /etc/cron.d" | ts '%Y-%m-%d %H:%M:%S'
    
    # Create the cron.d directory if it doesn't exist
    mkdir -p /etc/cron.d
    
    # Create the cron file in /etc/cron.d with proper ownership
    cat << EOF > /etc/cron.d/acme-renewal
# Run certificate renewal at 2:30 AM on Monday and Thursday
30 2 * * 1,4 ${USER} /usr/local/bin/renew-certs.sh > ${LOG_FILE} 2>&1
EOF

    # Make sure cron file has correct permissions
    chmod 0644 /etc/cron.d/acme-renewal
    
    echo "[acme] Cron job set up successfully" | ts '%Y-%m-%d %H:%M:%S'
    echo "[acme] Renewal schedule: 2:30 AM on Monday and Thursday" | ts '%Y-%m-%d %H:%M:%S'

    # Show the current cron configuration
    if [ "${HA_DEBUG_ENABLED}" == "true" ]; then
        debug_log "Current cron configuration:"
        cat /etc/cron.d/acme-renewal
    fi
}
