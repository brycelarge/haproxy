#!/bin/bash
set -e

# Default settings
INCLUDE_DEV=false
GITHUB_API="https://api.github.com"
GITHUB_REPO="haproxy/haproxy"

# Parse command line arguments
while getopts "d" opt; do
    case $opt in
        d)
            INCLUDE_DEV=true
            ;;
        \?)
            echo "Invalid option: -$OPTARG" >&2
            exit 1
            ;;
    esac
done

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

get_latest_release() {
    local response
    local releases
    local version
    local branch="$1"
    local current_major="${branch%.*}"
    
    log "Fetching releases from GitHub..."
    # Include pre-releases with the ?per_page=100 parameter to get more results
    response=$(curl -s "${GITHUB_API}/repos/${GITHUB_REPO}/releases?per_page=100")
    
    debug_log "Raw API Response size: $(echo "$response" | wc -c) bytes"
    
    if [ -n "$response" ]; then
        if [ "$INCLUDE_DEV" = "true" ]; then
            debug_log "Including development versions"
            # Include pre-releases and filter by major version
            releases=$(echo "$response" | 
                      jq -r '.[] | select(.prerelease == true or .prerelease == false) | .tag_name' |
                      grep "^v${current_major}" |
                      sed 's/^v//')
        else
            debug_log "Stable versions only"
            # Only stable releases
            releases=$(echo "$response" | 
                      jq -r '.[] | select(.prerelease == false) | .tag_name' |
                      grep "^v${current_major}" |
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
            response=$(curl -s "${GITHUB_API}/repos/${GITHUB_REPO}/tags?per_page=100")
            debug_log "Raw Tags Response size: $(echo "$response" | wc -c) bytes"
            
            if [ -n "$response" ]; then
                if [ "$INCLUDE_DEV" = "true" ]; then
                    releases=$(echo "$response" | 
                              jq -r '.[].name' |
                              grep "^v${current_major}" |
                              sed 's/^v//')
                else
                    releases=$(echo "$response" | 
                              jq -r '.[].name' |
                              grep "^v${current_major}" |
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
    
    echo "$version"
}

get_haproxy_sha256() {
    local version="$1"
    local tempfile
    local sha256
    local expected_sha256
    
    version=$(echo "$version" | xargs)
    
    if [ -z "$version" ]; then
        log "Error: Version not specified"
        exit 1
    fi
    
    local url="https://github.com/${GITHUB_REPO}/archive/refs/tags/v${version}.tar.gz"
    log "Downloading from $url"
    tempfile=$(mktemp)
    log "Using temporary file: $tempfile"
    
    # Download the archive
    if ! curl -sfL "$url" -o "$tempfile"; then
        log "Failed to download from $url"
        rm -f "$tempfile"
        exit 1
    fi
    
    log "Download completed, checking file size..."
    local filesize=$(stat -f%z "$tempfile")
    log "File size: $filesize bytes"
    
    if [ ! -s "$tempfile" ]; then
        log "Downloaded file is empty"
        rm -f "$tempfile"
        exit 1
    fi
    
    log "Calculating SHA256..."
    sha256=$(sha256sum "$tempfile" | cut -d' ' -f1)
    log "Raw SHA256 output: $sha256"
    
    # Save the archive for inspection
    if [ "${HA_DEBUG}" = "true" ]; then
        local debug_file="/tmp/haproxy-${version}.tar.gz"
        cp "$tempfile" "$debug_file"
        log "Saved archive to $debug_file for inspection"
        log "You can verify with: sha256sum $debug_file"
        
        # Download the file again to verify consistency
        local verify_file=$(mktemp)
        log "Downloading file again to verify consistency..."
        if curl -sfL "$url" -o "$verify_file"; then
            local verify_sha256=$(sha256sum "$verify_file" | cut -d' ' -f1)
            log "Verification download SHA256: $verify_sha256"
            if [ "$sha256" = "$verify_sha256" ]; then
                log "SHA256 matches between downloads"
            else
                log "WARNING: SHA256 mismatch between downloads!"
                log "First download:  $sha256"
                log "Second download: $verify_sha256"
            fi
        fi
        rm -f "$verify_file"
        
        # Try to get the SHA256 from the GitHub API
        local api_url="https://api.github.com/repos/${GITHUB_REPO}/git/refs/tags/v${version}"
        log "Checking GitHub API for tag info: $api_url"
        local tag_info=$(curl -sfL "$api_url")
        if [ -n "$tag_info" ]; then
            local tag_sha=$(echo "$tag_info" | jq -r '.object.sha')
            log "Tag SHA from GitHub: $tag_sha"
            
            if [ -n "$tag_sha" ] && [ "$tag_sha" != "null" ]; then
                local commit_url="https://api.github.com/repos/${GITHUB_REPO}/git/commits/${tag_sha}"
                log "Checking commit info: $commit_url"
                local commit_info=$(curl -sfL "$commit_url")
                if [ -n "$commit_info" ]; then
                    local tree_sha=$(echo "$commit_info" | jq -r '.tree.sha')
                    log "Tree SHA from GitHub: $tree_sha"
                fi
            fi
        fi
    fi
    
    rm -f "$tempfile"
    
    if [ -z "$sha256" ]; then
        log "Failed to calculate SHA256"
        exit 1
    fi
    
    if [ "$sha256" = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" ]; then
        log "Got SHA256 of empty file"
        exit 1
    fi
    
    echo "$sha256"
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
    local tmpfile=$(mktemp)
    
    # Update the Dockerfile
    sed -e "s|HAPROXY_BRANCH=.*|HAPROXY_BRANCH=${branch} \\\\|" \
        -e "s|HAPROXY_MINOR=.*|HAPROXY_MINOR=${version} \\\\|" \
        -e "s|HAPROXY_SHA256=.*|HAPROXY_SHA256=${sha256} \\\\|" \
        -e "s|HAPROXY_SRC_URL=.*|HAPROXY_SRC_URL=https://github.com/${GITHUB_REPO}/archive/refs/tags \\\\|" \
        Dockerfile > "$tmpfile"
    
    # Move the temporary file back to the original
    mv "$tmpfile" Dockerfile
    rm -f Dockerfile.bak "$tmpfile.bak"
    
    # Show the changes
    log "Current Dockerfile values:"
    grep -E "HAPROXY_(BRANCH|MINOR|SHA256|SRC_URL)=" Dockerfile | sed 's/^/  /'
}

build_and_push() {
    local version="$1"
    local docker_repo="$2"
    local build_date=$(date -u +'%Y-%m-%dT%H:%M:%SZ')
    
    version=$(echo "$version" | xargs)
    docker_repo=$(echo "$docker_repo" | xargs)
    
    if [ -z "$version" ] || [ -z "$docker_repo" ]; then
        log "Error: Version or Docker repository not specified"
        exit 1
    fi
    
    log "Building Docker image..."
    docker build --progress=plain --platform linux/arm64 \
        --build-arg BUILD_DATE="$build_date" \
        -t "${docker_repo}:${version}" .
    
    log "Tagging latest..."
    docker tag "${docker_repo}:${version}" "${docker_repo}:latest"
    
    log "Pushing images..."
    docker push "${docker_repo}:${version}"
    docker push "${docker_repo}:latest"
    
    log "Successfully built and pushed version $version"
}

main() {
    log "Starting build process..."
    
    log "Reading current version from Dockerfile..."
    CURRENT_VERSION=$(grep "HAPROXY_MINOR=" Dockerfile | cut -d'=' -f2- | tr -d '\\' | xargs)
    CURRENT_BRANCH=$(grep "HAPROXY_BRANCH=" Dockerfile | cut -d'=' -f2- | tr -d '\\' | xargs)
    
    log "Current version in Dockerfile: '$CURRENT_VERSION'"
    log "Current branch in Dockerfile: '$CURRENT_BRANCH'"
    
    if [ -z "$CURRENT_VERSION" ] || [ -z "$CURRENT_BRANCH" ]; then
        log "Error: Could not detect current version or branch in Dockerfile"
        exit 1
    fi
    
    LATEST_VERSION=$(get_latest_release "$CURRENT_BRANCH")
    log "Latest version available: $LATEST_VERSION"
    
    if [ "$CURRENT_VERSION" = "$LATEST_VERSION" ]; then
        log "Already at latest HAProxy version $LATEST_VERSION"
    else
        log "New HAProxy version available: $LATEST_VERSION"
        
        # Always calculate new SHA256 when updating version
        log "Getting SHA256 hash..."
        SHA256=$(get_haproxy_sha256 "$LATEST_VERSION")
        log "Got SHA256: $SHA256"
        
        log "Updating Dockerfile..."
        update_dockerfile "$LATEST_VERSION" "$SHA256"
        CURRENT_VERSION="$LATEST_VERSION"
    fi
    
    # Verify the download works with current SHA256
    log "Verifying current version download..."
    VERIFY_SHA256=$(get_haproxy_sha256 "$CURRENT_VERSION")
    if [ "$VERIFY_SHA256" != "$(grep "HAPROXY_SHA256=" Dockerfile | cut -d'=' -f2- | tr -d '\\' | xargs)" ]; then
        log "SHA256 mismatch for current version, updating..."
        update_dockerfile "$CURRENT_VERSION" "$VERIFY_SHA256"
    fi
    
    build_and_push "$CURRENT_VERSION" "brycelarge/haproxy"
}

main
