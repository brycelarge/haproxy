#!/bin/bash
set -e

# Default settings
INCLUDE_DEV=false
USE_VERSION_2=false
UPDATE_GITHUB=false
TAG_AS_NEXT=false
GITHUB_API="https://api.github.com"
GITHUB_REPO="haproxy/haproxy"
VERSION_CACHE_DIR="/tmp/haproxy_version_cache"
VERSION_CACHE_TTL=86400  # 24 hours in seconds

# Enable debug logging
export HA_DEBUG=true

# Parse command line arguments FIRST
while getopts "v:r:d2unh" opt; do
    case $opt in
        v) VERSION="$OPTARG" ;;
        r) DOCKER_REPO="$OPTARG" ;;
        d) INCLUDE_DEV=true ;;
        2) USE_VERSION_2=true ;;
        u) UPDATE_GITHUB=true ;;
        n) TAG_AS_NEXT=true; INCLUDE_DEV=true ;;
        h) usage ;;
        \?) usage ;;
    esac
done

# Function to display usage information
usage() {
    echo "Usage: $(basename "$0") [options]"
    echo "Options:"
    echo "  -v VERSION    Specify HAProxy version to build"
    echo "  -r REPO       Specify Docker repository (default: brycelarge/haproxy)"
    echo "  -d            Include development versions"
    echo "  -2            Use latest version 2.x"
    echo "  -u            Update version cache (ignore cached version)"
    echo "  -n            Tag latest dev version as 'next' and push"
    echo "  -h            Display this help message"
    exit 1
}

log() {
    echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1" >&2
}

debug_log() {
    if [ "${HA_DEBUG}" = "true" ]; then
        log "DEBUG: $1"
    fi
}

trap 'log "Error on line $LINENO"' ERR

version_gt() {
    test "$(printf '%s\n' "$@" | sort -V | head -n 1)" != "$1"
}

get_cache_key() {
    local branch="$1"
    local dev_flag="stable"
    local version_flag="auto"

    # Create a unique cache key based on settings
    if [ "$INCLUDE_DEV" = "true" ]; then
        dev_flag="dev"
    fi

    if [ "$USE_VERSION_2" = "true" ]; then
        version_flag="v2"
    elif [ -n "$branch" ]; then
        version_flag="v${branch}"
    fi

    echo "${dev_flag}_${version_flag}"
}

check_version_cache() {
    local branch="$1"
    local current_time
    local cache_time
    local cached_version
    local cache_key

    # Create cache directory if it doesn't exist
    mkdir -p "$VERSION_CACHE_DIR"

    # Get cache key based on current settings
    cache_key=$(get_cache_key "$branch")
    local cache_file="${VERSION_CACHE_DIR}/${cache_key}"

    debug_log "Using cache key: $cache_key"

    if [ -f "$cache_file" ]; then
        current_time=$(date +%s)
        cache_time=$(stat -f %m "$cache_file")
        if [ $((current_time - cache_time)) -lt "$VERSION_CACHE_TTL" ] && [ "$UPDATE_GITHUB" = "false" ]; then
            cached_version=$(cat "$cache_file")
            if [ -n "$cached_version" ]; then
                log "Using cached version: $cached_version (cache: $cache_key)"
                echo "$cached_version"
                return 0
            fi
        fi
    fi
    return 1
}

get_latest_release() {
    local response
    local releases
    local version
    local branch="$1"
    local current_major
    local cache_key

    # Check cache first
    if cached_version=$(check_version_cache "$branch"); then
        echo "$cached_version"
        return 0
    fi

    log "Fetching releases from GitHub..."
    # Include pre-releases with the ?per_page=100 parameter to get more results
    response=$(curl -s -H "Accept: application/vnd.github.v3+json" "${GITHUB_API}/repos/${GITHUB_REPO}/releases?per_page=100")

    debug_log "Raw API Response size: ${#response} bytes"

    # Check for rate limit or other API errors
    if echo "$response" | jq -e 'if type=="object" and has("message") then .message else empty end' >/dev/null 2>&1; then
        local error_msg
        error_msg=$(echo "$response" | jq -r '.message')
        log "GitHub API Error: $error_msg"
        exit 1
    fi

    # Check if response is valid JSON
    if ! echo "$response" | jq -e '.' >/dev/null 2>&1; then
        log "Error: Invalid JSON response from GitHub API"
        exit 1
    fi

    # Set the major version based on the USE_VERSION_2 flag or branch
    if [ "$USE_VERSION_2" = "true" ]; then
        current_major="2"
    elif [ -n "$branch" ]; then
        current_major="${branch%.*}"
    else
        # Get all available major versions and use the highest one
        current_major=$(echo "$response" |
                      jq -r '.[].tag_name' |
                      grep -v "dev" |
                      sed 's/^v//' |
                      cut -d'.' -f1 |
                      sort -rn |
                      head -n1)

        if [ -z "$current_major" ]; then
            # If no releases found, try tags
            log "No releases found, checking tags for major version..."
            response=$(curl -s -H "Accept: application/vnd.github.v3+json" "${GITHUB_API}/repos/${GITHUB_REPO}/tags?per_page=100")

            # Check for rate limit or other API errors
            if echo "$response" | jq -e 'if type=="object" and has("message") then .message else empty end' >/dev/null 2>&1; then
                local error_msg
                error_msg=$(echo "$response" | jq -r '.message')
                log "GitHub API Error: $error_msg"
                exit 1
            fi

            # Check if response is valid JSON
            if ! echo "$response" | jq -e '.' >/dev/null 2>&1; then
                log "Error: Invalid JSON response from GitHub API for tags"
                exit 1
            fi

            current_major=$(echo "$response" |
                          jq -r '.[].name' |
                          grep -v "dev" |
                          sed 's/^v//' |
                          cut -d'.' -f1 |
                          sort -rn |
                          head -n1)
        fi

        if [ -z "$current_major" ]; then
            log "Error: Could not determine major version from releases or tags"
            exit 1
        fi
    fi

    if [ -n "$response" ]; then
        if [ "$INCLUDE_DEV" = "true" ]; then
            debug_log "Including development versions"
            # Include pre-releases and filter by major version
            releases=$(echo "$response" |
                      jq -r '.[] | select(.prerelease == true or .prerelease == false) | .tag_name' |
                      grep "^v${current_major}\." |
                      sed 's/^v//')
        else
            debug_log "Stable versions only"
            # Only stable releases
            releases=$(echo "$response" |
                      jq -r '.[] | select(.prerelease == false) | .tag_name' |
                      grep "^v${current_major}\." |
                      grep -v "dev" |
                      sed 's/^v//')
        fi

        if [ -n "$releases" ]; then
            debug_log "Found releases:"
            echo "$releases" | while read -r v; do
                debug_log "  $v"
            done

            version=$(echo "$releases" | sort -V | tail -n1)
            if [ -n "$version" ]; then
                log "Latest version: $version"
            else
                log "No valid version found in releases"
            fi
        else
            log "No matching releases found"
            # Try fetching from tags if no releases found
            log "Fetching tags from GitHub..."
            response=$(curl -s -H "Accept: application/vnd.github.v3+json" "${GITHUB_API}/repos/${GITHUB_REPO}/tags?per_page=100")
            debug_log "Raw Tags Response size: ${#response} bytes"

            if [ -n "$response" ]; then
                if [ "$INCLUDE_DEV" = "true" ]; then
                    releases=$(echo "$response" |
                              jq -r '.[].name' |
                              grep "^v${current_major}\." |
                              sed 's/^v//')
                else
                    releases=$(echo "$response" |
                              jq -r '.[].name' |
                              grep "^v${current_major}\." |
                              grep -v "dev" |
                              sed 's/^v//')
                fi

                if [ -n "$releases" ]; then
                    debug_log "Found tags:"
                    echo "$releases" | while read -r v; do
                        debug_log "  $v"
                    done

                    version=$(echo "$releases" | sort -V | tail -n1)
                    if [ -n "$version" ]; then
                        log "Latest version from tags: $version"
                    else
                        log "No valid version found in tags"
                    fi
                else
                    log "No matching tags found"
                fi
            else
                log "Error: Could not fetch tags from GitHub"
            fi
        fi
    else
        log "Error: Could not fetch releases from GitHub"
        exit 1
    fi

    if [ -z "$version" ]; then
        log "Error: Could not find any valid versions"
        exit 1
    fi

    # Cache the version with the appropriate cache key
    cache_key=$(get_cache_key "$branch")
    local cache_file="${VERSION_CACHE_DIR}/${cache_key}"
    echo "$version" > "$cache_file"
    debug_log "Cached version $version with key: $cache_key"

    echo "$version"
}

download_haproxy() {
    local version="$1"
    local dest="$2"

    version=$(echo "$version" | xargs)

    if [ -z "$version" ]; then
        log "Error: Version not specified"
        exit 1
    fi

    local url="https://github.com/${GITHUB_REPO}/archive/refs/tags/v${version}.tar.gz"
    log "Downloading from $url"

    if ! curl -sfL "$url" -o "$dest"; then
        log "Failed to download from $url"
        rm -f "$dest"
        exit 1
    fi

    if [ ! -s "$dest" ]; then
        log "Downloaded file is empty"
        rm -f "$dest"
        exit 1
    fi

    local sha256
    sha256=$(sha256sum "$dest" | cut -d' ' -f1)
    log "SHA256: $sha256"

    if [ "$sha256" = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" ]; then
        log "Got SHA256 of empty file"
        exit 1
    fi

    echo "$sha256"
}

build_and_push() {
    local version="$1"
    local docker_repo="$2"
    local tarball="$3"
    local build_date
    build_date=$(date -u +'%Y-%m-%dT%H:%M:%SZ')
    local tag_as_latest="${4:-false}"  # Default to false now

    version=$(echo "$version" | xargs)
    docker_repo=$(echo "$docker_repo" | xargs)

    if [ -z "$version" ] || [ -z "$docker_repo" ]; then
        log "Error: Version or Docker repository not specified"
        exit 1
    fi

    log "Building Docker image..."
    docker build --platform linux/amd64 \
        --build-arg BUILD_DATE="$build_date" \
        --pull \
        -t "${docker_repo}:${version}" .

    if [ "$tag_as_latest" = "true" ]; then
        log "Tagging latest..."
        docker tag "${docker_repo}:${version}" "${docker_repo}:latest"
        docker push "${docker_repo}:latest"
    fi

    if [ "$TAG_AS_NEXT" = "true" ]; then
        log "Tagging as next..."
        docker tag "${docker_repo}:${version}" "${docker_repo}:next"
        docker push "${docker_repo}:next"
    fi

    log "Pushing version..."
    docker push "${docker_repo}:${version}"

    log "Successfully built and pushed version $version"

    rm -f "$tarball"
}

update_dockerfile() {
    local version="$1"
    local sha256="$2"
    local branch="${version%.*}"  # Extract major.minor from version

    version=$(echo "$version" | xargs)
    sha256=$(echo "$sha256" | xargs)

    log "Update params: version='$version' sha256='$sha256' branch='$branch'"

    if [ -z "$version" ] || [ -z "$sha256" ] || [ -z "$branch" ]; then
        log "Error: Missing required parameters for Dockerfile update"
        exit 1
    fi

    log "Updating Dockerfile with:"
    log "  HAPROXY_BRANCH:  $branch"
    log "  HAPROXY_MINOR:   $version"
    log "  HAPROXY_SHA256:  $sha256"

    # Create a temporary file with the updated content
    local tmpfile
    tmpfile=$(mktemp)

    # Update the Dockerfile
    sed -E \
        -e "s|^(ARG[[:space:]]+HAPROXY_BRANCH=).*|\1${branch}|" \
        -e "s|^(ARG[[:space:]]+HAPROXY_MINOR=).*|\1${version}|" \
        -e "s|^(ARG[[:space:]]+HAPROXY_SHA256=).*|\1${sha256}|" \
        -e "s|^(ENV[[:space:]]+HAPROXY_BRANCH=).*|\1${branch}|" \
        -e "s|^(ENV[[:space:]]+HAPROXY_MINOR=).*|\1${version}|" \
        -e "s|^(ENV[[:space:]]+HAPROXY_SHA256=).*|\1${sha256}|" \
        -e "s|^(ENV[[:space:]]+HAPROXY_SRC_URL=).*|\1https://github.com/${GITHUB_REPO}/archive/refs/tags|" \
        Dockerfile > "$tmpfile"

    # Move the temporary file back to the original
    mv "$tmpfile" Dockerfile
    rm -f Dockerfile.bak "$tmpfile.bak"

    # Show the changes
    log "Current Dockerfile values:"
    grep -E "HAPROXY_(BRANCH|MINOR|SHA256|SRC_URL)=" Dockerfile | sed 's/^/  /'
}

main() {
    log "Starting build process..."

    local version="$VERSION"  # Use the VERSION from getopts
    local docker_repo="$DOCKER_REPO"  # Use the DOCKER_REPO from getopts
    local tag_as_latest=false  # Default to false

    # If version not provided, detect it
    if [ -z "$version" ]; then
        if [ "$USE_VERSION_2" = "true" ]; then
            version=$(get_latest_release "2")
            log "Detected latest 2.x version: $version"
            tag_as_latest=false  # Don't tag as latest for version 2
        else
            version=$(get_latest_release "")
            log "Detected latest version: $version"
            if [ "$TAG_AS_NEXT" = "false" ]; then
                tag_as_latest=true
            fi
        fi
    fi

    # Download tarball once and compute SHA256 from it
    log "Downloading HAProxy $version..."
    local tarball="/tmp/haproxy-${version}.tar.gz"
    local sha256
    sha256=$(download_haproxy "$version" "$tarball")
    if [ -z "$sha256" ]; then
        log "Error: Could not download or hash version $version"
        exit 1
    fi
    log "Got SHA256: $sha256"

    # Copy tarball to build context so Docker can COPY it in
    cp "$tarball" "./haproxy.tar.gz"

    # Update the Dockerfile with new version and hash
    log "Updating Dockerfile..."
    update_dockerfile "$version" "$sha256"

    # If docker repo not provided, use default
    if [ -z "$docker_repo" ]; then
        docker_repo="brycelarge/haproxy"
    fi

    build_and_push "$version" "$docker_repo" "$tarball" "$tag_as_latest"

    rm -f "./haproxy.tar.gz"
}

main
