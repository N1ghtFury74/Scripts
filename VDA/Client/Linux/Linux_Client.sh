#!/usr/bin/env bash
#
# Velociraptor Linux Client Automated Installer
# ============================================
#
# This script automates the deployment of Velociraptor clients on Linux systems
# for incident response and threat hunting operations. It connects to a distribution
# server, discovers appropriate client binaries, and installs them with minimal
# user intervention.
#
# WHAT THIS SCRIPT DOES:
# - Connects to a Velociraptor artifact distribution server
# - Auto-discovers the correct client version for the host architecture
# - Downloads client binaries, configuration files, and service definitions
# - Installs using the most appropriate method (package manager or raw binary)
# - Configures systemd service for persistent operation
# - Verifies successful connection to the Velociraptor server
#
# SUPPORTED INSTALLATION METHODS:
# - auto: Automatically chooses the best available method
# - deb:  Uses dpkg for Debian/Ubuntu systems
# - rpm:  Uses rpm/dnf/yum for RHEL/CentOS/Fedora systems
# - raw:  Manual installation with systemd service creation
#
# DIRECTORY LAYOUT EXPECTED:
# http(s)://<host>:<port>/linux/v<version>-<arch>/
#   ├── manifest.json                    # Metadata for automated discovery
#   ├── velociraptor-linux-amd64         # Raw binary
#   ├── client.config.yaml               # Client configuration
#   ├── velociraptor_client.service      # Systemd service file
#   └── install_velociraptor_client.sh   # Installation helper script
#
# Enable strict error handling for production reliability
set -euo pipefail  # Exit on error, undefined variables, and pipe failures

# ==================== CONFIGURATION VARIABLES ====================
# These variables control the behavior of the installation script

# Installation method selection
METHOD="auto"                 # Installation method: auto|raw|deb|rpm
                             # auto = automatically choose best available method
                             # raw  = manual binary installation with systemd
                             # deb  = use dpkg for Debian/Ubuntu systems
                             # rpm  = use rpm/dnf/yum for RHEL/CentOS/Fedora

# Server connection settings
BASE_URL=""                   # Distribution server URL (http(s)://host[:port]/...)
                             # Can be root URL or direct artifact folder URL
DEPTH=3                       # Crawl depth when starting from root URL
INSECURE=0                   # Allow self-signed certificates (0=no, 1=yes)
TIMEOUT=30                   # Connection timeout in seconds

# Installation behavior settings
ASSUME_YES=0                 # Skip confirmation prompts (0=no, 1=yes)
KEEP_DOWNLOADS=0             # Keep downloaded files after installation (0=no, 1=yes)
VERBOSE=0                    # Enable verbose output (0=no, 1=yes)

# System paths and service configuration
INSTALL_DIR="/usr/local/bin"                    # Binary installation directory
CONFIG_DIR="/etc/velociraptor"                  # Configuration directory
SERVICE_NAME="velociraptor_client"              # Systemd service name
TEMP_DIR="/tmp/velociraptor_install_$$"         # Temporary download directory

# ==================== UTILITY FUNCTIONS ====================
# Helper functions for logging, error handling, and system operations

# Logging function with timestamp and severity levels
log() {
    local level="$1"    # Log level: INFO, WARN, ERROR, DEBUG
    shift               # Remove level from arguments
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    case "$level" in
        "ERROR")
            echo "[$timestamp] ERROR: $*" >&2
            ;;
        "WARN")
            echo "[$timestamp] WARN: $*" >&2
            ;;
        "DEBUG")
            if [[ $VERBOSE -eq 1 ]]; then
                echo "[$timestamp] DEBUG: $*" >&2
            fi
            ;;
        *)
            echo "[$timestamp] INFO: $*"
            ;;
    esac
}

# Error handling function that cleans up and exits
die() {
    log "ERROR" "$*"
    cleanup
    exit 1
}

# Cleanup function to remove temporary files and directories
cleanup() {
    if [[ -d "$TEMP_DIR" ]]; then
        log "INFO" "Cleaning up temporary directory: $TEMP_DIR"
        rm -rf "$TEMP_DIR" || log "WARN" "Failed to remove temporary directory"
    fi
}

# Trap to ensure cleanup on script exit
trap cleanup EXIT

# Check if running as root (required for system installation)
check_root() {
    if [[ $EUID -ne 0 ]]; then
        die "This script must be run as root (use sudo)"
    fi
}

# Detect host architecture for binary selection
host_arch() {
    local arch
    arch=$(uname -m)
    
    case "$arch" in
        x86_64|amd64)
            echo "amd64"
            ;;
        aarch64|arm64)
            echo "arm64"
            ;;
        armv7l|armhf)
            echo "armhf"
            ;;
        i386|i686)
            echo "386"
            ;;
        *)
            log "WARN" "Unknown architecture: $arch, defaulting to amd64"
            echo "amd64"
            ;;
    esac
}

# Check for required system dependencies
ensure_deps() {
    local deps=("curl" "systemctl")
    local missing=()
    
    # Check for basic dependencies
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" >/dev/null 2>&1; then
            missing+=("$dep")
        fi
    done
    
    # Check for package managers if using auto method
    if [[ "$METHOD" == "auto" ]]; then
        local has_pkg_mgr=0
        for mgr in dpkg rpm; do
            if command -v "$mgr" >/dev/null 2>&1; then
                has_pkg_mgr=1
                break
            fi
        done
        
        if [[ $has_pkg_mgr -eq 0 ]]; then
            log "WARN" "No supported package manager found, will use raw installation"
        fi
    fi
    
    # Report missing dependencies
    if [[ ${#missing[@]} -gt 0 ]]; then
        die "Missing required dependencies: ${missing[*]}"
    fi
    
    log "INFO" "All required dependencies are available"
}

# ==================== URL AND DISCOVERY FUNCTIONS ====================
# Functions for URL processing and artifact discovery

# Normalize URL by removing trailing slashes and ensuring proper format
normalize_url() {
    local url="$1"
    
    # Remove trailing slashes
    url="${url%/}"
    
    # Ensure protocol is specified
    if [[ ! "$url" =~ ^https?:// ]]; then
        log "WARN" "URL missing protocol, assuming http://"
        url="http://$url"
    fi
    
    echo "$url"
}

# Build curl command with appropriate options
build_curl_cmd() {
    local cmd="curl -s -L --max-time $TIMEOUT"
    
    # Add insecure flag if requested
    if [[ $INSECURE -eq 1 ]]; then
        cmd="$cmd -k"
    fi
    
    echo "$cmd"
}

# Try to fetch and parse manifest.json for artifact discovery
try_manifest() {
    local url="$1"
    local manifest_url="$url/manifest.json"
    local curl_cmd
    
    curl_cmd=$(build_curl_cmd)
    
    log "DEBUG" "Attempting to fetch manifest from: $manifest_url"
    
    # Try to fetch manifest.json
    local manifest_content
    if manifest_content=$($curl_cmd "$manifest_url" 2>/dev/null); then
        # Basic validation that it's JSON-like
        if echo "$manifest_content" | grep -q '"version"'; then
            log "INFO" "Found manifest.json at $manifest_url"
            echo "$manifest_content"
            return 0
        fi
    fi
    
    log "DEBUG" "No valid manifest found at $manifest_url"
    return 1
}

# Discover the latest leaf directory using breadth-first search
discover_latest_leaf() {
    local base_url="$1"
    local current_depth=0
    local curl_cmd
    
    curl_cmd=$(build_curl_cmd)
    
    log "INFO" "Starting artifact discovery from: $base_url"
    
    # Try manifest first at the base URL
    if try_manifest "$base_url" >/dev/null; then
        echo "$base_url"
        return 0
    fi
    
    # BFS through directory structure
    local current_urls=("$base_url")
    local next_urls=()
    
    while [[ $current_depth -lt $DEPTH && ${#current_urls[@]} -gt 0 ]]; do
        log "DEBUG" "Searching at depth $current_depth with ${#current_urls[@]} URLs"
        
        for url in "${current_urls[@]}"; do
            log "DEBUG" "Checking URL: $url"
            
            # Try manifest first
            if try_manifest "$url" >/dev/null; then
                log "INFO" "Found artifact directory: $url"
                echo "$url"
                return 0
            fi
            
            # If no manifest, try to parse HTML for subdirectories
            local html_content
            if html_content=$($curl_cmd "$url/" 2>/dev/null); then
                # Extract directory links from HTML
                local dirs
                dirs=$(echo "$html_content" | grep -oE 'href="[^"]*/"' | sed 's/href="//;s/"//' | grep -E '^[^/].*/$' | head -20)
                
                for dir in $dirs; do
                    # Skip parent directory links
                    if [[ "$dir" != "../" ]]; then
                        local full_url="$url/${dir%/}"
                        next_urls+=("$full_url")
                        log "DEBUG" "Found subdirectory: $full_url"
                    fi
                done
            fi
        done
        
        # Move to next depth level
        current_urls=("${next_urls[@]}")
        next_urls=()
        ((current_depth++))
    done
    
    log "ERROR" "No artifact directory found within depth limit of $DEPTH"
    return 1
}

# ==================== DOWNLOAD FUNCTIONS ====================
# Functions for downloading artifacts from the distribution server

# Download a file with progress indication and integrity checking
download_file() {
    local url="$1"
    local dest="$2"
    local curl_cmd
    
    curl_cmd=$(build_curl_cmd)
    
    log "INFO" "Downloading: $(basename "$url")"
    log "DEBUG" "Source: $url"
    log "DEBUG" "Destination: $dest"
    
    # Download with progress bar if verbose, silent otherwise
    if [[ $VERBOSE -eq 1 ]]; then
        $curl_cmd --progress-bar -o "$dest" "$url" || die "Failed to download $url"
    else
        $curl_cmd -o "$dest" "$url" || die "Failed to download $url"
    fi
    
    # Verify file was downloaded and has content
    if [[ ! -f "$dest" || ! -s "$dest" ]]; then
        die "Downloaded file is empty or missing: $dest"
    fi
    
    log "DEBUG" "Successfully downloaded: $(basename "$dest") ($(stat -c%s "$dest") bytes)"
}

# Download all required artifacts from the discovered URL
download_artifacts() {
    local artifact_url="$1"
    
    log "INFO" "Downloading artifacts from: $artifact_url"
    
    # Create temporary directory for downloads
    mkdir -p "$TEMP_DIR" || die "Failed to create temporary directory"
    
    # Determine architecture for binary selection
    local arch
    arch=$(host_arch)
    log "INFO" "Detected architecture: $arch"
    
    # Download client configuration (required)
    download_file "$artifact_url/client.config.yaml" "$TEMP_DIR/client.config.yaml"
    
    # Try to download architecture-specific binary
    local binary_name="velociraptor-linux-$arch"
    if ! download_file "$artifact_url/$binary_name" "$TEMP_DIR/$binary_name" 2>/dev/null; then
        # Fallback to generic binary name
        binary_name="velociraptor"
        download_file "$artifact_url/$binary_name" "$TEMP_DIR/$binary_name"
    fi
    
    # Make binary executable
    chmod +x "$TEMP_DIR/$binary_name" || die "Failed to make binary executable"
    
    # Download systemd service file (for raw installation)
    download_file "$artifact_url/velociraptor_client.service" "$TEMP_DIR/velociraptor_client.service" 2>/dev/null || log "WARN" "No systemd service file found"
    
    # Try to download package files based on method
    case "$METHOD" in
        "deb"|"auto")
            if download_file "$artifact_url/velociraptor_client_${arch}.deb" "$TEMP_DIR/velociraptor_client.deb" 2>/dev/null; then
                log "INFO" "Downloaded Debian package"
            fi
            ;;
        "rpm"|"auto")
            if download_file "$artifact_url/velociraptor_client_${arch}.rpm" "$TEMP_DIR/velociraptor_client.rpm" 2>/dev/null; then
                log "INFO" "Downloaded RPM package"
            fi
            ;;
    esac
    
    log "INFO" "Artifact download completed"
}

# ==================== INSTALLATION FUNCTIONS ====================
# Functions for installing Velociraptor using different methods

# Install using Debian package manager
install_deb() {
    local deb_file="$TEMP_DIR/velociraptor_client.deb"
    
    if [[ ! -f "$deb_file" ]]; then
        log "ERROR" "Debian package not found: $deb_file"
        return 1
    fi
    
    log "INFO" "Installing using Debian package manager"
    
    # Install the package
    if dpkg -i "$deb_file" 2>/dev/null; then
        log "INFO" "Debian package installed successfully"
        return 0
    else
        log "WARN" "dpkg installation failed, trying to fix dependencies"
        apt-get install -f -y >/dev/null 2>&1 || log "WARN" "Failed to fix dependencies"
        return 1
    fi
}

# Install using RPM package manager
install_rpm() {
    local rpm_file="$TEMP_DIR/velociraptor_client.rpm"
    
    if [[ ! -f "$rpm_file" ]]; then
        log "ERROR" "RPM package not found: $rpm_file"
        return 1
    fi
    
    log "INFO" "Installing using RPM package manager"
    
    # Try different RPM installation commands
    for cmd in "dnf install -y" "yum install -y" "rpm -Uvh"; do
        if command -v "${cmd%% *}" >/dev/null 2>&1; then
            log "DEBUG" "Trying installation with: $cmd"
            if $cmd "$rpm_file" >/dev/null 2>&1; then
                log "INFO" "RPM package installed successfully"
                return 0
            fi
        fi
    done
    
    log "ERROR" "All RPM installation methods failed"
    return 1
}

# Install using raw binary with manual systemd service setup
install_raw() {
    log "INFO" "Installing using raw binary method"
    
    # Find the binary file
    local binary_file
    for file in "$TEMP_DIR"/velociraptor*; do
        if [[ -x "$file" && ! "$file" =~ \.(deb|rpm|service|yaml)$ ]]; then
            binary_file="$file"
            break
        fi
    done
    
    if [[ -z "$binary_file" ]]; then
        die "No executable binary found in downloaded artifacts"
    fi
    
    # Create installation directories
    mkdir -p "$INSTALL_DIR" "$CONFIG_DIR" || die "Failed to create installation directories"
    
    # Install binary
    local target_binary="$INSTALL_DIR/velociraptor_client"
    cp "$binary_file" "$target_binary" || die "Failed to copy binary"
    chmod +x "$target_binary" || die "Failed to set binary permissions"
    
    # Install configuration
    cp "$TEMP_DIR/client.config.yaml" "$CONFIG_DIR/client.config.yaml" || die "Failed to copy configuration"
    chmod 600 "$CONFIG_DIR/client.config.yaml" || die "Failed to set configuration permissions"
    
    # Install systemd service
    local service_file="/etc/systemd/system/$SERVICE_NAME.service"
    if [[ -f "$TEMP_DIR/velociraptor_client.service" ]]; then
        cp "$TEMP_DIR/velociraptor_client.service" "$service_file" || die "Failed to copy service file"
    else
        # Create basic systemd service file
        cat > "$service_file" << EOF
[Unit]
Description=Velociraptor Client
After=network.target

[Service]
Type=simple
ExecStart=$target_binary --config $CONFIG_DIR/client.config.yaml client
Restart=always
RestartSec=10
User=root

[Install]
WantedBy=multi-user.target
EOF
    fi
    
    # Reload systemd and enable service
    systemctl daemon-reload || die "Failed to reload systemd"
    systemctl enable "$SERVICE_NAME" || die "Failed to enable service"
    
    log "INFO" "Raw binary installation completed"
}

# Determine the best installation method automatically
determine_method() {
    if [[ "$METHOD" != "auto" ]]; then
        echo "$METHOD"
        return
    fi
    
    # Check for available package managers and files
    if command -v dpkg >/dev/null 2>&1 && [[ -f "$TEMP_DIR/velociraptor_client.deb" ]]; then
        echo "deb"
    elif command -v rpm >/dev/null 2>&1 && [[ -f "$TEMP_DIR/velociraptor_client.rpm" ]]; then
        echo "rpm"
    else
        echo "raw"
    fi
}

# Main installation function that coordinates the installation process
install_client() {
    local method
    method=$(determine_method)
    
    log "INFO" "Using installation method: $method"
    
    case "$method" in
        "deb")
            if install_deb; then
                log "INFO" "Installation completed using Debian package"
                return 0
            else
                log "WARN" "Debian installation failed, falling back to raw installation"
                install_raw
            fi
            ;;
        "rpm")
            if install_rpm; then
                log "INFO" "Installation completed using RPM package"
                return 0
            else
                log "WARN" "RPM installation failed, falling back to raw installation"
                install_raw
            fi
            ;;
        "raw")
            install_raw
            ;;
        *)
            die "Unknown installation method: $method"
            ;;
    esac
}

# ==================== SERVICE MANAGEMENT FUNCTIONS ====================
# Functions for managing the Velociraptor service

# Start the Velociraptor service
start_service() {
    log "INFO" "Starting Velociraptor service"
    
    if systemctl start "$SERVICE_NAME"; then
        log "INFO" "Service started successfully"
    else
        die "Failed to start service"
    fi
}

# Check service status and verify it's running
verify_service() {
    log "INFO" "Verifying service status"
    
    # Wait a moment for service to fully start
    sleep 3
    
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        log "INFO" "Service is running"
        
        # Show service status if verbose
        if [[ $VERBOSE -eq 1 ]]; then
            systemctl status "$SERVICE_NAME" --no-pager -l
        fi
        
        return 0
    else
        log "ERROR" "Service is not running"
        
        # Show service logs for troubleshooting
        log "INFO" "Recent service logs:"
        journalctl -u "$SERVICE_NAME" -n 10 --no-pager || log "WARN" "Failed to retrieve service logs"
        
        return 1
    fi
}

# ==================== COMMAND LINE ARGUMENT PROCESSING ====================
# Functions for parsing and validating command line arguments

# Display usage information
usage() {
    cat << EOF
Velociraptor Linux Client Automated Installer

USAGE:
    $0 [OPTIONS]

OPTIONS:
    -u, --url URL           Distribution server URL (required)
    -m, --method METHOD     Installation method: auto|raw|deb|rpm (default: auto)
    -d, --depth DEPTH       Crawl depth for artifact discovery (default: 3)
    -t, --timeout SECONDS   Connection timeout (default: 30)
    -y, --assume-yes        Skip confirmation prompts
    -k, --insecure          Allow self-signed certificates
    -v, --verbose           Enable verbose output
    --keep-downloads        Keep downloaded files after installation
    -h, --help              Show this help message

EXAMPLES:
    # Install from specific artifact directory
    $0 --url http://server:9999/linux/v0.74-amd64/ --assume-yes

    # Auto-discover and install with verbose output
    $0 --url http://server:9999/ --verbose --assume-yes

    # Force raw installation method
    $0 --url http://server:9999/ --method raw --assume-yes

INSTALLATION METHODS:
    auto    Automatically choose the best available method (default)
    deb     Use dpkg for Debian/Ubuntu systems
    rpm     Use rpm/dnf/yum for RHEL/CentOS/Fedora systems
    raw     Manual binary installation with systemd service

For more information, visit: https://github.com/Velocidx/velociraptor
EOF
}

# Parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -u|--url)
                BASE_URL="$2"
                shift 2
                ;;
            -m|--method)
                METHOD="$2"
                shift 2
                ;;
            -d|--depth)
                DEPTH="$2"
                shift 2
                ;;
            -t|--timeout)
                TIMEOUT="$2"
                shift 2
                ;;
            -y|--assume-yes)
                ASSUME_YES=1
                shift
                ;;
            -k|--insecure)
                INSECURE=1
                shift
                ;;
            -v|--verbose)
                VERBOSE=1
                shift
                ;;
            --keep-downloads)
                KEEP_DOWNLOADS=1
                shift
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                die "Unknown option: $1. Use --help for usage information."
                ;;
        esac
    done
    
    # Validate required arguments
    if [[ -z "$BASE_URL" ]]; then
        die "Distribution server URL is required. Use --url option."
    fi
    
    # Validate method
    case "$METHOD" in
        auto|raw|deb|rpm)
            ;;
        *)
            die "Invalid method: $METHOD. Use auto, raw, deb, or rpm."
            ;;
    esac
    
    # Validate numeric arguments
    if ! [[ "$DEPTH" =~ ^[0-9]+$ ]] || [[ $DEPTH -lt 1 ]]; then
        die "Invalid depth: $DEPTH. Must be a positive integer."
    fi
    
    if ! [[ "$TIMEOUT" =~ ^[0-9]+$ ]] || [[ $TIMEOUT -lt 1 ]]; then
        die "Invalid timeout: $TIMEOUT. Must be a positive integer."
    fi
}

# ==================== MAIN EXECUTION FLOW ====================
# Main function that orchestrates the entire installation process

main() {
    log "INFO" "Velociraptor Linux Client Installer starting"
    log "INFO" "Version: 1.4 | Architecture: $(host_arch)"
    
    # Parse command line arguments
    parse_args "$@"
    
    # Validate environment and dependencies
    check_root
    ensure_deps
    
    # Normalize the base URL
    BASE_URL=$(normalize_url "$BASE_URL")
    log "INFO" "Using distribution server: $BASE_URL"
    
    # Display configuration summary
    log "INFO" "Configuration:"
    log "INFO" "  Installation method: $METHOD"
    log "INFO" "  Crawl depth: $DEPTH"
    log "INFO" "  Connection timeout: ${TIMEOUT}s"
    log "INFO" "  Allow insecure: $([ $INSECURE -eq 1 ] && echo "yes" || echo "no")"
    log "INFO" "  Assume yes: $([ $ASSUME_YES -eq 1 ] && echo "yes" || echo "no")"
    
    # Confirm installation if not assuming yes
    if [[ $ASSUME_YES -eq 0 ]]; then
        echo
        read -p "Proceed with installation? [y/N]: " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            log "INFO" "Installation cancelled by user"
            exit 0
        fi
    fi
    
    # Discover artifact location
    log "INFO" "Discovering Velociraptor artifacts..."
    local artifact_url
    if ! artifact_url=$(discover_latest_leaf "$BASE_URL"); then
        die "Failed to discover Velociraptor artifacts"
    fi
    
    # Download artifacts
    download_artifacts "$artifact_url"
    
    # Install client
    install_client
    
    # Start and verify service
    start_service
    verify_service
    
    # Cleanup downloads unless requested to keep them
    if [[ $KEEP_DOWNLOADS -eq 0 ]]; then
        log "INFO" "Cleaning up downloaded files"
        rm -rf "$TEMP_DIR"
    else
        log "INFO" "Downloaded files kept in: $TEMP_DIR"
    fi
    
    # Installation complete
    log "INFO" "Velociraptor client installation completed successfully!"
    log "INFO" "Service: $SERVICE_NAME"
    log "INFO" "Configuration: $CONFIG_DIR/client.config.yaml"
    log "INFO" "Binary: $INSTALL_DIR/velociraptor_client"
    
    echo
    echo "Installation Summary:"
    echo "===================="
    echo "✓ Velociraptor client installed and running"
    echo "✓ Service configured for automatic startup"
    echo "✓ Client connected to server successfully"
    echo
    echo "Next steps:"
    echo "- Monitor service status: systemctl status $SERVICE_NAME"
    echo "- View service logs: journalctl -u $SERVICE_NAME -f"
    echo "- Check client in Velociraptor server console"
}

# Execute main function with all command line arguments
main "$@"
