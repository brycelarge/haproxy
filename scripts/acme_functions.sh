#!/usr/bin/with-contenv bash

if [ -f /etc/profile ]; then
    source /etc/profile
fi

set -eo pipefail
shopt -s nullglob
shopt -s lastpipe

# Variables
USER="acme"
HOME_DIR="/config/acme"
CERT_HOME="/config/acme/certs"
CRON_FILE="/etc/crontabs/${USER}"
LOG_FILE="/var/log/acme-renewals.log"

# New variable to determine the challenge type
ACME_CHALLENGE_TYPE="${ACME_CHALLENGE_TYPE:-dns_cf}"

source /scripts/debug.sh;
source /scripts/acme_lock.sh;

install_acme() {
    # Check if email is empty
    if [ -z "$ACME_EMAIL" ]; then
        echo "[acme] Error: ACME_EMAIL env is not set" | ts '%Y-%m-%d %H:%M:%S'
        exit 0
    fi

    echo "[acme] Installing acme.sh...." | ts '%Y-%m-%d %H:%M:%S'

    curl -o /config/acme.sh https://raw.githubusercontent.com/acmesh-official/acme.sh/master/acme.sh;
    chmod 755 /config/acme.sh;
    mkdir -p /config/acme;
    cd /config/; # make sure we are in a writable directory

    # install as root then convert to itetech user
    bash acme.sh \
        --install \
        --nocron \
        --home "${HOME_DIR}" \
        --config-home "${HOME_DIR}" \
        --cert-home "${CERT_HOME}" \
        --accountemail "${ACME_EMAIL}";

    debug_log "${HOME_DIR} ${CERT_HOME} ${ACME_EMAIL}"

    # Check if installation was successful
    if [ ! -f "${HOME_DIR}/acme.sh" ] || [ ! -f "${HOME_DIR}/acme.sh.env" ]; then
        echo "[acme] Installation failed" | ts '%Y-%m-%d %H:%M:%S'
        exit 0
    fi

    chown -R ${USER}:${USER} /config/acme;
    # rm -rf "${TEMP_DIR}"
    echo "[acme] Installed successfully" | ts '%Y-%m-%d %H:%M:%S'

    # Create environment file
    echo "[acme] Setting up acme environment variables..." | ts '%Y-%m-%d %H:%M:%S'
    
    # Create environment file
    s6-setuidgid "${USER}" cat <<EOF > "${HOME_DIR}/acme.sh.env"
export DEPLOY_HAPROXY_HOT_UPDATE=yes
export DEPLOY_HAPROXY_STATS_SOCKET=/var/lib/haproxy/admin.sock
export DEPLOY_HAPROXY_PEM_PATH=/etc/haproxy/certs

# Cloudflare settings
export CF_Token=
export CF_Account_ID=
export CF_Zone_ID=

# Alternative Cloudflare settings
export CF_Key=
export CF_Email=
EOF

    # Set permissions on env file
    chmod 600 "${HOME_DIR}/acme.sh.env"
    chown "${USER}:${USER}" "${HOME_DIR}/acme.sh.env"

    echo "[acme] Installation completed successfully" | ts '%Y-%m-%d %H:%M:%S'
}

register_acme() {
    source /config/acme/acme.sh.env;
    echo "[acme] registering an account with letsencrypt..." | ts '%Y-%m-%d %H:%M:%S'
    REGISTER_RESPONSE=$(exec s6-setuidgid ${USER} $HOME_DIR/acme.sh --home $HOME_DIR --config-home $HOME_DIR --cert-home $CERT_HOME --register-account --server letsencrypt_test -m "${CF_Email}");
    ACCOUNT_THUMBPRINT=$(echo "${REGISTER_RESPONSE}" | grep ACCOUNT_THUMBPRINT | sed "s/.*='\(.*\)'/\1/");
    echo "[acme] account THUMBPRINT: ${ACCOUNT_THUMBPRINT}" | ts '%Y-%m-%d %H:%M:%S';
    echo "${ACCOUNT_THUMBPRINT}" >> /config/acme/ca/thumbprint;

    setup_acme_renewal
}

issue_cert() {
    if ! acquire_lock; then
        return 1
    fi
    trap cleanup EXIT

    echo "[acme] Attempting to issue ${1}" | ts '%Y-%m-%d %H:%M:%S';

    source /config/acme/acme.sh.env;

    if [ "$ACME_CHALLENGE_TYPE" = "http" ]; then
        echo "[acme] Using HTTP challenge with HAProxy" | ts '%Y-%m-%d %H:%M:%S';
        s6-setuidgid ${USER} /config/acme/acme.sh \
            --issue \
            --standalone \
            --pre-hook "echo 'Using HAProxy for ACME challenge'" \
            --home $HOME_DIR \
            --config-home $HOME_DIR \
            --cert-home $CERT_HOME \
            -d "${1}";
    else
        echo "[acme] Using DNS challenge (Cloudflare)" | ts '%Y-%m-%d %H:%M:%S';
        s6-setuidgid ${USER} /config/acme/acme.sh \
            --issue \
            --dns dns_cf \
            --home $HOME_DIR \
            --config-home $HOME_DIR \
            --cert-home $CERT_HOME \
            -d "${1}";
    fi

    deploy_cert "${1}";
}

deploy_cert() {
    echo "[acme] Deploying ssl certificate for: ${1}" | ts '%Y-%m-%d %H:%M:%S';

    source /config/acme/acme.sh.env;
    s6-setuidgid ${USER} /config/acme/acme.sh \
        --home $HOME_DIR \
        --config-home $HOME_DIR \
        --cert-home $CERT_HOME \
        --deploy -d "${1}" \
        --deploy-hook haproxy;

    echo "[acme] Certificate successfully deployed for:${1}" | ts '%Y-%m-%d %H:%M:%S';
}

renew_cert() {
    if ! acquire_lock; then
        return 1
    fi
    trap cleanup EXIT

    source /config/acme/acme.sh.env;
    s6-setuidgid ${USER} /config/acme/acme.sh \
        --home $HOME_DIR \
        --config-home $HOME_DIR \
        --cert-home $CERT_HOME \
        --renew -d "${1}"

    deploy_cert "${1}";
}

verify_cron() {
    echo "[acme] Verifying ACME cron job and installing if it does not exist" | ts '%Y-%m-%d %H:%M:%S'

    # Check if cron job exists
    if ! s6-setuidgid "$USER" crontab -l 2>/dev/null | grep -q "/usr/local/bin/renew-certs.sh"; then
        setup_acme_renewal
    fi
}

setup_acme_renewal() {
    echo "[acme] Setting up ACME certificate renewal cron job" | ts '%Y-%m-%d %H:%M:%S'

    # Ensure log file exists and has correct permissions
    touch "$LOG_FILE"
    chown "${USER}:${USER}" "$LOG_FILE"
    chmod 640 "$LOG_FILE"

    # Create the renewal script
    cat << 'EOF' > /usr/local/bin/renew-certs.sh
#!/usr/bin/with-contenv bash

# Source environment variables
source /config/acme/acme.sh.env

# make sure acme is not running multiple times
source /scripts/acme_lock.sh;

# Lock file path
LOCK_FILE="/run/acme.lock"

# Log file path
LOG_FILE="/var/log/haproxy/acme-renewals.log"

# Function to log messages
log_message() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') [acme] - $1" | tee -a "$LOG_FILE"
}

# Main renewal process
if ! acquire_lock; then
    echo "$(date '+%Y-%m-%d %H:%M:%S') [acme] - Another ACME process is running, skipping renewal" | tee -a "$LOG_FILE"
    exit 1
fi

trap cleanup EXIT

# Function to renew a single certificate
renew_certificate() {
    local domain="$1"
    log_message "Starting renewal for ${domain}"

        s6-setuidgid ${USER} /config/acme/acme.sh \
        --home $HOME_DIR \
        --config-home $HOME_DIR \
        --cert-home $CERT_HOME \
        --renew -d "${1}"

    /config/acme/acme.sh \
        --home /config/acme \
        --config-home /config/acme \
        --cert-home /config/acme/certs \
        --renew -d "${domain}" \
        --force || {
            log_message "Failed to renew certificate for ${domain}"
            return 1
        }

    # Deploy the renewed certificate
    /config/acme/acme.sh \
        --home /config/acme \
        --config-home /config/acme \
        --cert-home /config/acme/certs \
        --deploy -d "${domain}" \
        --deploy-hook haproxy || {
            log_message "Failed to deploy certificate for ${domain}"
            return 1
        }

    log_message "Successfully renewed and deployed certificate for ${domain}"
    return 0
}

# Main renewal process
log_message "Starting certificate renewal process"

# Get list of all domains with certificates
find /config/acme/certs -name "*.conf" | while read -r conf_file; do
    domain=$(basename "$conf_file" .conf)
    renew_certificate "$domain"
done

log_message "Certificate renewal process completed"
EOF

    # Make the renewal script executable
    chmod +x /usr/local/bin/renew-certs.sh
    chown "${USER}:${USER}" /usr/local/bin/renew-certs.sh

    # Create the cron job
    # Run at 2:30 AM on Monday and Thursday
    echo "30 2 * * 1,4 /usr/local/bin/renew-certs.sh > /dev/null 2>&1" > "$CRON_FILE"

    # Make sure cron file has correct permissions
    chmod 600 "$CRON_FILE"
    chown "${USER}:${USER}" "$CRON_FILE"

    echo "[acme] Cron job set up successfully" | ts '%Y-%m-%d %H:%M:%S'
    echo "[acme] Renewal schedule: 2:30 AM on Monday and Thursday" | ts '%Y-%m-%d %H:%M:%S'

    # Show the current cron configuration
    if [ "${HA_DEBUG_ENABLED}" == "true" ]; then
        debug_log "Current cron configuration:"
        cat "$CRON_FILE"
    fi
}

