# Velociraptor Deployment Automation System

## Overview

This system provides automated deployment of Velociraptor clients across enterprise environments for live incident response and threat hunting when traditional dead disk acquisition is not feasible. The automation eliminates manual deployment complexity while maintaining operational security requirements.

## Directory Structure

```
Velociraptor Deployment Automation/
├── README.md                           # This documentation
├── Server/
│   └── Server_Setup.py                 # Distribution server setup
└── Client/
    ├── Linux_Client.sh                 # Linux deployment script
    ├── Windows_Client.ps1              # Windows deployment script
    ├── linux_deployment_success.webp   # Linux deployment success
    └── windows_deployment_success.webp # Windows deployment success
```

## System Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│  SERVER SETUP   │    │   HTTP SERVER    │    │ CLIENT INSTALL  │
│   (Python)      │───▶│   (Port 9999)    │◀───│  (Bash/PS1)     │
│                 │    │                  │    │                 │
│ • GitHub API    │    │ • Artifact Host  │    │ • Auto-discover │
│ • Asset Build   │    │ • Manifest API   │    │ • Multi-method  │
│ • Repackaging   │    │ • Web Interface  │    │ • Service Mgmt  │
│ • Repository    │    │ • File Serving   │    │ • Verification  │
└─────────────────┘    └──────────────────┘    └─────────────────┘
```

## Components

### Server_Setup.py
**Purpose**: Interactive setup tool for Velociraptor client distribution

**Key Functions**:
- Interactive prompts for OS selection (Windows/Linux/Both) and client configuration
- Downloads latest Velociraptor releases from GitHub API (with HTML scrape fallback)
- Repacks Windows MSI/EXE installers with your custom client.config.yaml
- Builds Linux packages (.deb/.rpm) or raw binaries with systemd services
- Creates structured web repository with manifest.json metadata for automation
- Automatically starts HTTP server (default port 9999) and installs systemd service

### Linux_Client.sh
**Purpose**: Automated Linux client deployment

**Key Functions**:
- Auto-discovers appropriate client version for host architecture
- Supports multiple installation methods (auto/deb/rpm/raw)
- Configures systemd service for persistent operation
- Verifies successful connection to Velociraptor server

### Windows_Client.ps1
**Purpose**: Intelligent Windows client deployment

**Key Functions**:
- Breadth-first search artifact discovery with manifest support
- Multiple installation methods (auto/msi/exe/raw)
- Windows service configuration and startup
- Handles both installers and raw binaries intelligently
## Value Proposition

### When Dead Disk Acquisition is Not Available

**Traditional Challenges**:
- Critical systems cannot be taken offline for imaging
- Time-sensitive incidents requiring immediate response
- Geographically distributed environments
- Large-scale enterprise incidents affecting hundreds of systems

**Solution Benefits**:
- **Live Response**: Continuous operation of critical systems during investigation
- **Zero Downtime**: Forensic capabilities without system interruption
- **Rapid Deployment**: Minutes instead of hours for forensic capability
- **Scale**: Simultaneous deployment across entire enterprise
- **Remote Access**: No on-site presence required for deployment

## Quick Start

### Server Setup
```bash
# Run interactive server setup (default port 9999)
python3 Server_Setup.py

# Optional parameters:
python3 Server_Setup.py --port 8080 --token YOUR_GITHUB_TOKEN

# Other options:
python3 Server_Setup.py --serve-only          # Just restart web server
python3 Server_Setup.py --remove-httpd        # Uninstall systemd service
python3 Server_Setup.py --no-httpd           # Don't install systemd service

# The script will interactively prompt you for:
# 1. Target OS (Windows/Linux/Both)
# 2. Path to your client.config.yaml file
# Then automatically downloads latest Velociraptor releases and creates distribution repository
```

### Client Deployment

**Linux**:
```bash
# Install from discovered artifacts (auto-discovery from root)
sudo ./Linux_Client.sh --url http://SERVER:9999/ --method auto --assume-yes

# Install from specific artifact directory
sudo ./Linux_Client.sh --url http://SERVER:9999/linux/v0.74-amd64/ --method auto --assume-yes
```

**Windows**:
```powershell
# Install with auto-discovery and filtering
.\Windows_Client.ps1 -Url http://SERVER:9999/ -Select "windows 0.74 amd64" -AssumeYes

# Install from specific artifact directory
.\Windows_Client.ps1 -Url http://SERVER:9999/windows/v0.74-amd64/ -Method auto -AssumeYes
```

## Deployment Success Examples

### Linux Deployment
![Linux Success](Client/linux_deployment_success.webp)

**Success Indicators**: Architecture detection, service installation, server connection established

### Windows Deployment
![Windows Success](Client/windows_deployment_success.webp)

**Success Indicators**: MSI installation, Windows service running, server enrollment confirmed

## Technical Features

- **Automated Discovery**: Manifest-first approach with HTML scraping fallback
- **Cross-Platform**: Unified interface for Linux and Windows deployment
- **Multi-Method Support**: Native package managers and raw binary installation
- **Enterprise Ready**: Service management, logging, and error handling
- **Security**: TLS encryption, certificate validation, integrity verification

## Use Cases

- **Incident Response**: Rapid forensic capability deployment during active incidents
- **Threat Hunting**: Proactive security operations requiring enterprise visibility
- **Remote Workforce**: Security incidents in distributed environments
- **Critical Infrastructure**: Live response when system downtime is not acceptable

---

This automation system transforms incident response by providing immediate forensic visibility across distributed environments when traditional imaging methods are not feasible, enabling security teams to respond to threats with unprecedented speed and efficiency.
