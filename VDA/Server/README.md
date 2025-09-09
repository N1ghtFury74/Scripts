# Velociraptor Distribution Server

## Overview
Interactive Python script that automates the creation and distribution of Velociraptor clients for incident response operations. Creates a complete web-based artifact repository with HTTP distribution server.

## What This Script Does
- Downloads latest Velociraptor releases from GitHub API (with HTML scrape fallback)
- Repacks Windows installers (MSI/EXE) with your custom client configuration
- Builds Linux packages (.deb/.rpm) or creates raw binaries with systemd services
- Creates structured web-based artifact repository with manifest.json metadata
- Hosts HTTP server for client downloads with systemd persistence
- Generates browsable web interface for artifact management

## Requirements
- Python 3.6+
- `velociraptor` binary in PATH or current directory
- Your `client.config.yaml` file
- Internet connection for GitHub API access
- Linux system for systemd service installation

## Usage

### Basic Interactive Setup
```bash
python3 Server_Setup.py
```

The script will interactively prompt for:
1. Target OS selection (Windows/Linux/Both)
2. Full path to your `client.config.yaml` file

### Command Line Options
```bash
# Custom port (default: 9999)
python3 Server_Setup.py --port 8080

# With GitHub token for higher API rate limits
python3 Server_Setup.py --token YOUR_GITHUB_TOKEN

# Just restart existing web server
python3 Server_Setup.py --serve-only

# Don't install systemd service
python3 Server_Setup.py --no-httpd

# Remove systemd service
python3 Server_Setup.py --remove-httpd
```

## Directory Structure Created
```
dist/
├── index.html                                    # Main landing page
├── linux/
│   └── v0.74.1-amd64/                           # Version-specific folder
│       ├── client.config.yaml                   # Client configuration
│       ├── velociraptor-linux-amd64             # Raw binary
│       ├── velociraptor_client.service          # Systemd service file
│       ├── install_velociraptor_client.sh       # Installation script
│       ├── manifest.json                        # Metadata for automation
│       └── index.html                           # Folder-specific page
└── windows/
    └── v0.74.1-amd64/                          # Version-specific folder
        ├── Windows_VelociraptorClient_0.74.1_amd64.msi  # Repacked installer
        ├── client.config.yaml                  # Client configuration
        ├── manifest.json                       # Metadata for automation
        └── index.html                          # Folder-specific page
```

## Key Features
- **Persistent Operation**: Creates systemd service `vr_artifacts_http.service` for automatic startup
- **Idempotent**: Can be run multiple times without breaking existing deployments
- **Version Management**: Maintains multiple Velociraptor versions simultaneously
- **Cross-Platform**: Handles both Windows and Linux client generation
- **Web Interface**: Provides browsable artifact repository
- **Automated Discovery**: Generates manifest.json files for client auto-discovery

## Output
After successful execution:
- HTTP server running on specified port (default: 9999)
- Systemd service installed and started
- Web interface accessible at `http://<server-ip>:9999/`
- Clients can auto-discover artifacts via manifest.json or HTML scraping

## Systemd Service
The script automatically creates and installs `vr_artifacts_http.service` for persistent operation:
- Starts automatically on boot
- Serves artifacts from the `dist/` directory
- Logs to systemd journal

## Notes
- Requires `velociraptor` binary for repackaging operations
- GitHub token optional but recommended for higher API rate limits
- Creates SHA256 checksums for all generated artifacts
- Supports both GitHub API and HTML scraping for release discovery
