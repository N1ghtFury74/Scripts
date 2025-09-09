# Velociraptor Client Deployment Scripts

## Overview
Native OS scripting for automated Velociraptor client deployment during incident response. Written in Bash (Linux) and PowerShell (Windows) to leverage each platform's native capabilities and package management systems.

## Why Native Languages?

**Bash for Linux**: Direct integration with systemd, native package managers (dpkg/rpm/yum/dnf), and POSIX utilities. No external dependencies beyond standard Linux tools.

**PowerShell for Windows**: Native Windows service management, MSI installer handling, and .NET integration. Leverages Windows-specific installation methods and error handling.

## Scripts

### Linux_Client.sh (Bash)
**Purpose**: Linux client deployment with native package management integration

**Usage**:
```bash
sudo ./Linux_Client.sh --url http://server:9999/linux/v0.74-amd64/ --assume-yes
sudo ./Linux_Client.sh --url http://server:9999/ --method auto --verbose
```

**Options**:
- `-u, --url URL`: Distribution server URL (required)
- `-m, --method METHOD`: Installation method: auto|raw|deb|rpm (default: auto)
- `-d, --depth DEPTH`: Crawl depth for artifact discovery (default: 3)
- `-t, --timeout SECONDS`: Connection timeout (default: 30)
- `-y, --assume-yes`: Skip confirmation prompts
- `-k, --insecure`: Allow self-signed certificates
- `-v, --verbose`: Enable verbose output
- `--keep-downloads`: Keep downloaded files after installation

### Windows_Client.ps1 (PowerShell)
**Purpose**: Windows client deployment with native installer handling

**Usage**:
```powershell
.\Windows_Client.ps1 -Url http://server:9999/windows/v0.74-amd64/ -AssumeYes
.\Windows_Client.ps1 -Url http://server:9999/ -Select "windows 0.74 amd64" -AssumeYes
```

**Parameters**:
- `-Url <string>`: Distribution server URL (required)
- `-Method <string>`: Installation method: auto|msi|exe|raw (default: auto)
- `-Select <string>`: Filter tokens for artifact selection (space-separated AND filter)
- `-Depth <int>`: BFS crawl depth (default: 4)
- `-Insecure`: Allow self-signed certificates
- `-AssumeYes`: Skip confirmation prompts
- `-List`: List artifacts without installing
- `-Dest <string>`: Installation directory (default: C:\ProgramData\Velociraptor)

## Requirements
- **Linux**: Root privileges, systemd, curl/wget, package managers
- **Windows**: Administrator privileges, PowerShell 5.0+

Both scripts support manifest.json discovery, HTML scraping fallback, and comprehensive error handling with native OS logging.
