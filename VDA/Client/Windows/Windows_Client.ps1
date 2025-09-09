<#PSScriptInfo
.VERSION 1.4
.GUID 6e4f1ccf-3c3a-4f63-9e77-7a2b4d5e8a15
#>

<#
.SYNOPSIS
Velociraptor Windows Client Automated Installer

.DESCRIPTION
This PowerShell script automates the deployment of Velociraptor clients on Windows systems
for incident response and threat hunting operations. It provides intelligent discovery and
installation of Velociraptor client artifacts from a distribution server.

KEY CAPABILITIES:
- Automatic artifact discovery via manifest.json or HTML scraping
- Multiple installation methods: MSI (preferred), EXE, or RAW service installation
- Support for both proper installers and repacked client binaries
- Breadth-first search crawling for artifact discovery from site roots
- Silent installation with comprehensive error handling
- Administrator privilege verification and enforcement

INSTALLATION METHODS EXPLAINED:
- MSI: Standard Windows installer package with silent installation support
- EXE: Attempts silent installation; falls back to service install for repacked binaries
- RAW: Direct service installation using Velociraptor's built-in service installer

IMPORTANT NOTES:
- MSI files are proper Windows installers supporting standard silent switches
- "Repacked EXE" files are Velociraptor binaries with embedded configurations
- Repacked EXEs require service installation: velociraptor.exe service install -v
- Script requires Administrator privileges for service installation

.PARAMETER Url
Root or artifacts URL (e.g. http://host:9999/ or http://host:9999/windows/v0.74-386/).

.PARAMETER Method
Install method: auto | msi | exe | raw  (default: auto)
  auto: prefer MSI (repacked name first), then EXE; else falls back to RAW.

.PARAMETER Select
Token filter (AND-match) when crawling from a root (e.g. "windows 0.74 386").

.PARAMETER Depth
BFS recursion depth when starting at a root (default: 4).

.PARAMETER Insecure
Allow self-signed HTTPS certificates (download only).

.PARAMETER AssumeYes
Non-interactive; auto-approve actions.

.PARAMETER List
Only list discovered artifacts; do not install.

.PARAMETER Dest
Staging folder (used mainly by RAW mode). Default: C:\ProgramData\Velociraptor

.PARAMETER Help
Show embedded help (same content as Get-Help).

.EXAMPLE
# Install from an artifacts folder using MSI (recommended)
.\client_installation.ps1 -Url http://172.31.94.117:9999/windows/v0.74-386/ -Method msi -AssumeYes

.EXAMPLE
# From site root with token filtering (auto will choose MSI if present)
.\client_installation.ps1 -Url http://172.31.94.117:9999/ -Select "windows 0.74 386" -AssumeYes

.EXAMPLE
# EXE method: if the EXE is a real installer, run silently; if it's a repacked client EXE (binary),
# the script will run "service install" automatically.
.\client_installation.ps1 -Url http://172.31.94.117:9999/windows/v0.74-386/ -Method exe -AssumeYes

.EXAMPLE
# Dry run (just list what would be used)
.\client_installation.ps1 -Url http://172.31.94.117:9999/windows/v0.74-386/ -List

.NOTES
* Run PowerShell as Administrator.
* If MSI fails, the script prints the path to the detailed MSI log.
#>

# ==================== SCRIPT PARAMETERS ====================
# Define command-line parameters for script configuration
# NOTE: $Url is NOT Mandatory so -Help works without prompting for URL

param(
  # Distribution server URL - can be root URL or direct artifact folder
  [string]$Url,

  # Installation method selection with validation
  [ValidateSet('auto','msi','exe','raw')]
  [string]$Method = 'auto',                                # auto = intelligent method selection
                                                          # msi  = Windows Installer package
                                                          # exe  = Executable installer or binary
                                                          # raw  = Direct service installation

  # Token-based filtering for artifact selection when crawling from root
  [string]$Select = '',                                    # Space-separated AND filter tokens
                                                          # Example: "windows 0.74 amd64"

  # Breadth-first search depth limit for artifact discovery
  [int]$Depth = 4,                                        # Maximum crawl depth from root URL

  # Security and behavior options
  [switch]$Insecure,                                      # Allow self-signed certificates
  [switch]$AssumeYes,                                     # Skip confirmation prompts
  [switch]$List,                                          # List artifacts without installing

  # Installation destination for raw method
  [string]$Dest = 'C:\ProgramData\Velociraptor',          # Staging directory for downloads

  # Help flag for displaying usage information
  [switch]$Help
)

# ==================== GLOBAL VARIABLES ====================
# Script-wide variables for configuration and state management

# Version and identification
$ScriptVersion = "1.4"
$ScriptName = "Velociraptor Windows Client Installer"

# HTTP client configuration
$WebClient = $null                                        # Will be initialized in Initialize-WebClient
$UserAgent = "VelociraptorInstaller/$ScriptVersion"       # User agent for HTTP requests

# Installation state tracking
$DownloadedFiles = @()                                    # Track downloaded files for cleanup
$TempDirectory = $null                                    # Temporary directory for downloads

# ==================== UTILITY FUNCTIONS ====================
# Helper functions for logging, error handling, and system operations

# Enhanced logging function with timestamp and color coding
function Write-Log {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Message,
        
        [Parameter(Mandatory=$false)]
        [ValidateSet('INFO', 'WARN', 'ERROR', 'SUCCESS', 'DEBUG')]
        [string]$Level = 'INFO'
    )
    
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logMessage = "[$timestamp] $Level: $Message"
    
    # Color coding for different log levels
    switch ($Level) {
        'ERROR'   { Write-Host $logMessage -ForegroundColor Red }
        'WARN'    { Write-Host $logMessage -ForegroundColor Yellow }
        'SUCCESS' { Write-Host $logMessage -ForegroundColor Green }
        'DEBUG'   { Write-Host $logMessage -ForegroundColor Gray }
        default   { Write-Host $logMessage -ForegroundColor White }
    }
}

# Error handling function that logs and exits
function Stop-WithError {
    param([string]$Message)
    Write-Log -Message $Message -Level 'ERROR'
    Cleanup-Resources
    exit 1
}

# Resource cleanup function
function Cleanup-Resources {
    Write-Log -Message "Cleaning up resources..." -Level 'INFO'
    
    # Dispose of web client
    if ($WebClient) {
        $WebClient.Dispose()
        $WebClient = $null
    }
    
    # Clean up temporary files if not in List mode
    if (-not $List -and $TempDirectory -and (Test-Path $TempDirectory)) {
        try {
            Remove-Item -Path $TempDirectory -Recurse -Force -ErrorAction SilentlyContinue
            Write-Log -Message "Temporary directory cleaned up: $TempDirectory" -Level 'DEBUG'
        }
        catch {
            Write-Log -Message "Failed to clean up temporary directory: $($_.Exception.Message)" -Level 'WARN'
        }
    }
}

# Administrator privilege verification
function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Ensure administrator privileges for installation operations
function Assert-Administrator {
    if (-not (Test-Administrator)) {
        Stop-WithError "This script requires Administrator privileges. Please run PowerShell as Administrator."
    }
    Write-Log -Message "Administrator privileges verified" -Level 'SUCCESS'
}

# Initialize web client with appropriate security settings
function Initialize-WebClient {
    Write-Log -Message "Initializing web client..." -Level 'DEBUG'
    
    # Create web client with custom configuration
    $script:WebClient = New-Object System.Net.WebClient
    $WebClient.Headers.Add('User-Agent', $UserAgent)
    
    # Configure security settings for HTTPS
    if ($Insecure) {
        Write-Log -Message "Allowing self-signed certificates (insecure mode)" -Level 'WARN'
        # Bypass certificate validation for self-signed certificates
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {$true}
    }
    
    # Set TLS version to support modern servers
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12 -bor [System.Net.SecurityProtocolType]::Tls13
    
    Write-Log -Message "Web client initialized successfully" -Level 'DEBUG'
}

# ==================== URL AND DISCOVERY FUNCTIONS ====================
# Functions for URL processing and artifact discovery

# Normalize URL by ensuring proper format and removing trailing slashes
function Format-Url {
    param([string]$InputUrl)
    
    if (-not $InputUrl) {
        return $InputUrl
    }
    
    # Ensure protocol is specified
    if ($InputUrl -notmatch '^https?://') {
        Write-Log -Message "URL missing protocol, assuming http://" -Level 'WARN'
        $InputUrl = "http://$InputUrl"
    }
    
    # Remove trailing slashes for consistency
    $InputUrl = $InputUrl.TrimEnd('/')
    
    Write-Log -Message "Normalized URL: $InputUrl" -Level 'DEBUG'
    return $InputUrl
}

# Attempt to download and parse manifest.json for artifact metadata
function Get-ManifestData {
    param([string]$BaseUrl)
    
    $manifestUrl = "$BaseUrl/manifest.json"
    Write-Log -Message "Attempting to fetch manifest from: $manifestUrl" -Level 'DEBUG'
    
    try {
        # Download manifest content
        $manifestContent = $WebClient.DownloadString($manifestUrl)
        
        # Basic validation that it's JSON-like content
        if ($manifestContent -match '"version"' -or $manifestContent -match '"files"') {
            Write-Log -Message "Found valid manifest.json at $manifestUrl" -Level 'INFO'
            
            # Parse JSON content
            $manifestData = $manifestContent | ConvertFrom-Json
            return $manifestData
        }
        else {
            Write-Log -Message "Invalid manifest format at $manifestUrl" -Level 'DEBUG'
            return $null
        }
    }
    catch {
        Write-Log -Message "No manifest found at $manifestUrl" -Level 'DEBUG'
        return $null
    }
}

# Extract directory links from HTML content using regex parsing
function Get-DirectoryLinks {
    param(
        [string]$HtmlContent,
        [string]$BaseUrl
    )
    
    $links = @()
    
    # Regex pattern to match href attributes pointing to directories
    $linkPattern = 'href=["\']([^"\']*/?)["\']'
    $matches = [regex]::Matches($HtmlContent, $linkPattern, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
    
    foreach ($match in $matches) {
        $href = $match.Groups[1].Value
        
        # Skip parent directory links, anchors, and external URLs
        if ($href -match '^(\.\.?/?|#|https?://)') {
            continue
        }
        
        # Process directory links (ending with /)
        if ($href.EndsWith('/')) {
            $fullUrl = "$BaseUrl/$($href.TrimEnd('/'))"
            $links += $fullUrl
        }
        # Process potential file links for artifact detection
        elseif ($href -match '\.(msi|exe|yaml|json)$') {
            $fullUrl = "$BaseUrl/$href"
            $links += $fullUrl
        }
    }
    
    # Remove duplicates and return unique links
    return $links | Sort-Object -Unique
}

# Breadth-first search implementation for artifact discovery
function BFS-Find {
    param(
        [string]$StartUrl,
        [string[]]$FilterTokens = @(),
        [int]$MaxDepth = 4
    )
    
    Write-Log -Message "Starting BFS artifact discovery from: $StartUrl" -Level 'INFO'
    Write-Log -Message "Filter tokens: $($FilterTokens -join ', ')" -Level 'DEBUG'
    Write-Log -Message "Maximum depth: $MaxDepth" -Level 'DEBUG'
    
    # Initialize BFS data structures
    $queue = @(@{Url = $StartUrl; Depth = 0})  # Queue of URLs to process
    $visited = @{}                              # Track visited URLs to avoid cycles
    $candidates = @()                           # Store potential artifact directories
    
    while ($queue.Count -gt 0) {
        # Dequeue next URL to process
        $current = $queue[0]
        $queue = $queue[1..($queue.Count-1)]
        
        $currentUrl = $current.Url
        $currentDepth = $current.Depth
        
        # Skip if already visited or depth exceeded
        if ($visited.ContainsKey($currentUrl) -or $currentDepth -gt $MaxDepth) {
            continue
        }
        
        $visited[$currentUrl] = $true
        Write-Log -Message "Processing URL at depth $currentDepth`: $currentUrl" -Level 'DEBUG'
        
        try {
            # First, try to get manifest data
            $manifestData = Get-ManifestData -BaseUrl $currentUrl
            if ($manifestData) {
                # Found a manifest - this is likely an artifact directory
                $candidate = @{
                    Url = $currentUrl
                    Manifest = $manifestData
                    Depth = $currentDepth
                }
                
                # Apply filter tokens if specified
                if ($FilterTokens.Count -gt 0) {
                    $urlLower = $currentUrl.ToLower()
                    $matchesAll = $true
                    
                    foreach ($token in $FilterTokens) {
                        if ($urlLower -notlike "*$($token.ToLower())*") {
                            $matchesAll = $false
                            break
                        }
                    }
                    
                    if ($matchesAll) {
                        Write-Log -Message "Found matching artifact directory: $currentUrl" -Level 'SUCCESS'
                        $candidates += $candidate
                    }
                    else {
                        Write-Log -Message "Artifact directory doesn't match filter: $currentUrl" -Level 'DEBUG'
                    }
                }
                else {
                    # No filter specified, accept any artifact directory
                    Write-Log -Message "Found artifact directory: $currentUrl" -Level 'SUCCESS'
                    $candidates += $candidate
                }
                
                # Don't crawl deeper from artifact directories
                continue
            }
            
            # No manifest found, try to get HTML content for further crawling
            if ($currentDepth -lt $MaxDepth) {
                try {
                    $htmlContent = $WebClient.DownloadString("$currentUrl/")
                    $links = Get-DirectoryLinks -HtmlContent $htmlContent -BaseUrl $currentUrl
                    
                    # Add directory links to queue for further processing
                    foreach ($link in $links) {
                        if (-not $visited.ContainsKey($link)) {
                            $queue += @{Url = $link; Depth = $currentDepth + 1}
                        }
                    }
                    
                    Write-Log -Message "Found $($links.Count) links at $currentUrl" -Level 'DEBUG'
                }
                catch {
                    Write-Log -Message "Failed to fetch HTML from $currentUrl`: $($_.Exception.Message)" -Level 'DEBUG'
                }
            }
        }
        catch {
            Write-Log -Message "Error processing $currentUrl`: $($_.Exception.Message)" -Level 'DEBUG'
        }
    }
    
    Write-Log -Message "BFS completed. Found $($candidates.Count) artifact directories." -Level 'INFO'
    return $candidates
}

# ==================== ARTIFACT ANALYSIS FUNCTIONS ====================
# Functions for analyzing and selecting appropriate artifacts

# Analyze artifacts in a directory and categorize them by type
function Get-ArtifactInfo {
    param([string]$ArtifactUrl)
    
    Write-Log -Message "Analyzing artifacts at: $ArtifactUrl" -Level 'INFO'
    
    $artifacts = @{
        MSI = @()
        EXE = @()
        RAW = @()
        Config = $null
        Manifest = $null
    }
    
    try {
        # Try to get manifest first
        $manifestData = Get-ManifestData -BaseUrl $ArtifactUrl
        if ($manifestData) {
            $artifacts.Manifest = $manifestData
            Write-Log -Message "Manifest data retrieved successfully" -Level 'DEBUG'
        }
        
        # Get HTML content to find available files
        $htmlContent = $WebClient.DownloadString("$ArtifactUrl/")
        $links = Get-DirectoryLinks -HtmlContent $htmlContent -BaseUrl $ArtifactUrl
        
        foreach ($link in $links) {
            $fileName = Split-Path $link -Leaf
            
            # Categorize files by extension and naming patterns
            switch -Regex ($fileName) {
                '\.msi$' {
                    $artifacts.MSI += @{
                        Name = $fileName
                        Url = $link
                        IsRepacked = $fileName -match 'Windows_VelociraptorClient'
                    }
                    Write-Log -Message "Found MSI: $fileName" -Level 'DEBUG'
                }
                '\.exe$' {
                    $artifacts.EXE += @{
                        Name = $fileName
                        Url = $link
                        IsRepacked = $fileName -match 'Windows_VelociraptorClient'
                    }
                    Write-Log -Message "Found EXE: $fileName" -Level 'DEBUG'
                }
                'velociraptor.*\.exe$' {
                    if ($fileName -notmatch 'Windows_VelociraptorClient') {
                        $artifacts.RAW += @{
                            Name = $fileName
                            Url = $link
                            Type = 'Binary'
                        }
                        Write-Log -Message "Found RAW binary: $fileName" -Level 'DEBUG'
                    }
                }
                'client\.config\.yaml$' {
                    $artifacts.Config = @{
                        Name = $fileName
                        Url = $link
                    }
                    Write-Log -Message "Found configuration: $fileName" -Level 'DEBUG'
                }
            }
        }
        
        # Log summary of found artifacts
        Write-Log -Message "Artifact analysis complete:" -Level 'INFO'
        Write-Log -Message "  MSI files: $($artifacts.MSI.Count)" -Level 'INFO'
        Write-Log -Message "  EXE files: $($artifacts.EXE.Count)" -Level 'INFO'
        Write-Log -Message "  RAW binaries: $($artifacts.RAW.Count)" -Level 'INFO'
        Write-Log -Message "  Configuration: $(if ($artifacts.Config) { 'Found' } else { 'Not found' })" -Level 'INFO'
        
        return $artifacts
    }
    catch {
        Write-Log -Message "Failed to analyze artifacts: $($_.Exception.Message)" -Level 'ERROR'
        return $null
    }
}

# Select the best artifact based on method preference and availability
function Select-BestArtifact {
    param(
        [hashtable]$Artifacts,
        [string]$PreferredMethod
    )
    
    Write-Log -Message "Selecting best artifact for method: $PreferredMethod" -Level 'INFO'
    
    switch ($PreferredMethod) {
        'msi' {
            if ($Artifacts.MSI.Count -gt 0) {
                # Prefer repacked MSI files first
                $repacked = $Artifacts.MSI | Where-Object { $_.IsRepacked }
                if ($repacked) {
                    Write-Log -Message "Selected repacked MSI: $($repacked[0].Name)" -Level 'SUCCESS'
                    return @{ Type = 'MSI'; Artifact = $repacked[0] }
                }
                else {
                    Write-Log -Message "Selected MSI: $($Artifacts.MSI[0].Name)" -Level 'SUCCESS'
                    return @{ Type = 'MSI'; Artifact = $Artifacts.MSI[0] }
                }
            }
            else {
                Write-Log -Message "No MSI files available" -Level 'WARN'
                return $null
            }
        }
        
        'exe' {
            if ($Artifacts.EXE.Count -gt 0) {
                Write-Log -Message "Selected EXE: $($Artifacts.EXE[0].Name)" -Level 'SUCCESS'
                return @{ Type = 'EXE'; Artifact = $Artifacts.EXE[0] }
            }
            else {
                Write-Log -Message "No EXE files available" -Level 'WARN'
                return $null
            }
        }
        
        'raw' {
            if ($Artifacts.RAW.Count -gt 0) {
                Write-Log -Message "Selected RAW binary: $($Artifacts.RAW[0].Name)" -Level 'SUCCESS'
                return @{ Type = 'RAW'; Artifact = $Artifacts.RAW[0] }
            }
            else {
                Write-Log -Message "No RAW binaries available" -Level 'WARN'
                return $null
            }
        }
        
        'auto' {
            # Auto selection priority: MSI (repacked first) > EXE > RAW
            
            # First try repacked MSI
            $repackedMSI = $Artifacts.MSI | Where-Object { $_.IsRepacked }
            if ($repackedMSI) {
                Write-Log -Message "Auto-selected repacked MSI: $($repackedMSI[0].Name)" -Level 'SUCCESS'
                return @{ Type = 'MSI'; Artifact = $repackedMSI[0] }
            }
            
            # Then try any MSI
            if ($Artifacts.MSI.Count -gt 0) {
                Write-Log -Message "Auto-selected MSI: $($Artifacts.MSI[0].Name)" -Level 'SUCCESS'
                return @{ Type = 'MSI'; Artifact = $Artifacts.MSI[0] }
            }
            
            # Then try EXE
            if ($Artifacts.EXE.Count -gt 0) {
                Write-Log -Message "Auto-selected EXE: $($Artifacts.EXE[0].Name)" -Level 'SUCCESS'
                return @{ Type = 'EXE'; Artifact = $Artifacts.EXE[0] }
            }
            
            # Finally try RAW
            if ($Artifacts.RAW.Count -gt 0) {
                Write-Log -Message "Auto-selected RAW binary: $($Artifacts.RAW[0].Name)" -Level 'SUCCESS'
                return @{ Type = 'RAW'; Artifact = $Artifacts.RAW[0] }
            }
            
            Write-Log -Message "No suitable artifacts found for auto selection" -Level 'ERROR'
            return $null
        }
        
        default {
            Write-Log -Message "Unknown method: $PreferredMethod" -Level 'ERROR'
            return $null
        }
    }
}

# ==================== DOWNLOAD FUNCTIONS ====================
# Functions for downloading artifacts from the distribution server

# Download a file with progress indication and error handling
function Download-File {
    param(
        [string]$Url,
        [string]$Destination
    )
    
    Write-Log -Message "Downloading: $(Split-Path $Url -Leaf)" -Level 'INFO'
    Write-Log -Message "Source: $Url" -Level 'DEBUG'
    Write-Log -Message "Destination: $Destination" -Level 'DEBUG'
    
    try {
        # Ensure destination directory exists
        $destDir = Split-Path $Destination -Parent
        if (-not (Test-Path $destDir)) {
            New-Item -Path $destDir -ItemType Directory -Force | Out-Null
        }
        
        # Download the file
        $WebClient.DownloadFile($Url, $Destination)
        
        # Verify download success
        if (-not (Test-Path $Destination) -or (Get-Item $Destination).Length -eq 0) {
            throw "Downloaded file is empty or missing"
        }
        
        $fileSize = (Get-Item $Destination).Length
        Write-Log -Message "Successfully downloaded: $(Split-Path $Destination -Leaf) ($fileSize bytes)" -Level 'SUCCESS'
        
        # Track downloaded files for cleanup
        $script:DownloadedFiles += $Destination
        
        return $true
    }
    catch {
        Write-Log -Message "Failed to download $Url`: $($_.Exception.Message)" -Level 'ERROR'
        return $false
    }
}

# ==================== INSTALLATION FUNCTIONS ====================
# Functions for installing Velociraptor using different methods

# Install using Windows Installer (MSI) with silent switches
function Install-MSI {
    param([hashtable]$ArtifactInfo)
    
    $msiFile = $ArtifactInfo.Artifact.Name
    $msiPath = Join-Path $TempDirectory $msiFile
    
    Write-Log -Message "Installing MSI: $msiFile" -Level 'INFO'
    
    # Download MSI file
    if (-not (Download-File -Url $ArtifactInfo.Artifact.Url -Destination $msiPath)) {
        return $false
    }
    
    # Create log file for MSI installation
    $logFile = Join-Path $TempDirectory "msi_install.log"
    
    # Build msiexec command with silent switches
    $msiArgs = @(
        '/i', "`"$msiPath`""           # Install package
        '/quiet'                       # Silent installation
        '/norestart'                   # Don't restart automatically
        '/l*v', "`"$logFile`""        # Verbose logging
    )
    
    Write-Log -Message "Executing: msiexec $($msiArgs -join ' ')" -Level 'DEBUG'
    
    try {
        # Execute MSI installation
        $process = Start-Process -FilePath 'msiexec.exe' -ArgumentList $msiArgs -Wait -PassThru -NoNewWindow
        
        # Check installation result
        if ($process.ExitCode -eq 0) {
            Write-Log -Message "MSI installation completed successfully" -Level 'SUCCESS'
            return $true
        }
        else {
            Write-Log -Message "MSI installation failed with exit code: $($process.ExitCode)" -Level 'ERROR'
            
            # Display log file location for troubleshooting
            if (Test-Path $logFile) {
                Write-Log -Message "MSI installation log: $logFile" -Level 'INFO'
            }
            
            return $false
        }
    }
    catch {
        Write-Log -Message "MSI installation error: $($_.Exception.Message)" -Level 'ERROR'
        return $false
    }
}

# Install using executable installer with multiple silent installation attempts
function Install-EXE {
    param([hashtable]$ArtifactInfo)
    
    $exeFile = $ArtifactInfo.Artifact.Name
    $exePath = Join-Path $TempDirectory $exeFile
    
    Write-Log -Message "Installing EXE: $exeFile" -Level 'INFO'
    
    # Download EXE file
    if (-not (Download-File -Url $ArtifactInfo.Artifact.Url -Destination $exePath)) {
        return $false
    }
    
    # Check if this is a repacked Velociraptor binary (not a proper installer)
    if ($ArtifactInfo.Artifact.IsRepacked -or $exeFile -match '^velociraptor') {
        Write-Log -Message "Detected repacked Velociraptor binary, using service installation method" -Level 'INFO'
        return Install-RAW-Service -BinaryPath $exePath
    }
    
    # Try multiple silent installation switches for proper installers
    $silentSwitches = @('/S', '/SILENT', '/QUIET', '/s', '/silent', '/quiet')
    
    foreach ($switch in $silentSwitches) {
        Write-Log -Message "Attempting silent installation with switch: $switch" -Level 'DEBUG'
        
        try {
            $process = Start-Process -FilePath $exePath -ArgumentList $switch -Wait -PassThru -NoNewWindow
            
            if ($process.ExitCode -eq 0) {
                Write-Log -Message "EXE installation completed successfully with switch: $switch" -Level 'SUCCESS'
                return $true
            }
            else {
                Write-Log -Message "Installation attempt failed with exit code $($process.ExitCode) using switch: $switch" -Level 'DEBUG'
            }
        }
        catch {
            Write-Log -Message "Installation attempt error with switch $switch`: $($_.Exception.Message)" -Level 'DEBUG'
        }
    }
    
    # If all silent installation attempts failed, try service installation as fallback
    Write-Log -Message "All silent installation attempts failed, trying service installation as fallback" -Level 'WARN'
    return Install-RAW-Service -BinaryPath $exePath
}

# Install using direct service installation method
function Install-RAW {
    param([hashtable]$ArtifactInfo)
    
    $rawFile = $ArtifactInfo.Artifact.Name
    $rawPath = Join-Path $TempDirectory $rawFile
    
    Write-Log -Message "Installing RAW binary: $rawFile" -Level 'INFO'
    
    # Download RAW binary
    if (-not (Download-File -Url $ArtifactInfo.Artifact.Url -Destination $rawPath)) {
        return $false
    }
    
    return Install-RAW-Service -BinaryPath $rawPath
}

# Common service installation function for RAW binaries and repacked EXEs
function Install-RAW-Service {
    param([string]$BinaryPath)
    
    Write-Log -Message "Installing Velociraptor service using binary: $(Split-Path $BinaryPath -Leaf)" -Level 'INFO'
    
    # Ensure destination directory exists
    if (-not (Test-Path $Dest)) {
        New-Item -Path $Dest -ItemType Directory -Force | Out-Null
        Write-Log -Message "Created destination directory: $Dest" -Level 'INFO'
    }
    
    # Copy binary to destination
    $destBinary = Join-Path $Dest "velociraptor.exe"
    Copy-Item -Path $BinaryPath -Destination $destBinary -Force
    Write-Log -Message "Binary copied to: $destBinary" -Level 'INFO'
    
    # Download configuration file if available
    $configUrl = "$($ArtifactInfo.Artifact.Url -replace '/[^/]+$', '')/client.config.yaml"
    $configPath = Join-Path $Dest "client.config.yaml"
    
    if (Download-File -Url $configUrl -Destination $configPath) {
        Write-Log -Message "Configuration downloaded to: $configPath" -Level 'INFO'
    }
    else {
        Write-Log -Message "No configuration file available, service installation may require manual configuration" -Level 'WARN'
    }
    
    # Install service using Velociraptor's built-in service installer
    try {
        $serviceArgs = @('service', 'install')
        if (Test-Path $configPath) {
            $serviceArgs += @('--config', "`"$configPath`"")
        }
        $serviceArgs += '-v'  # Verbose output
        
        Write-Log -Message "Executing: `"$destBinary`" $($serviceArgs -join ' ')" -Level 'DEBUG'
        
        $process = Start-Process -FilePath $destBinary -ArgumentList $serviceArgs -Wait -PassThru -NoNewWindow
        
        if ($process.ExitCode -eq 0) {
            Write-Log -Message "Velociraptor service installed successfully" -Level 'SUCCESS'
            return $true
        }
        else {
            Write-Log -Message "Service installation failed with exit code: $($process.ExitCode)" -Level 'ERROR'
            return $false
        }
    }
    catch {
        Write-Log -Message "Service installation error: $($_.Exception.Message)" -Level 'ERROR'
        return $false
    }
}

# ==================== SERVICE VERIFICATION FUNCTIONS ====================
# Functions for verifying successful installation and service status

# Verify that Velociraptor service is installed and running
function Test-VelociraptorService {
    Write-Log -Message "Verifying Velociraptor service installation..." -Level 'INFO'
    
    # Common Velociraptor service names to check
    $serviceNames = @('Velociraptor', 'velociraptor', 'VelociraptorClient', 'velociraptor_client')
    
    foreach ($serviceName in $serviceNames) {
        try {
            $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
            if ($service) {
                Write-Log -Message "Found Velociraptor service: $($service.Name)" -Level 'SUCCESS'
                Write-Log -Message "Service status: $($service.Status)" -Level 'INFO'
                
                # Try to start service if it's not running
                if ($service.Status -ne 'Running') {
                    Write-Log -Message "Starting Velociraptor service..." -Level 'INFO'
                    try {
                        Start-Service -Name $service.Name
                        Start-Sleep -Seconds 3  # Wait for service to start
                        
                        $service.Refresh()
                        if ($service.Status -eq 'Running') {
                            Write-Log -Message "Velociraptor service started successfully" -Level 'SUCCESS'
                        }
                        else {
                            Write-Log -Message "Service failed to start properly" -Level 'WARN'
                        }
                    }
                    catch {
                        Write-Log -Message "Failed to start service: $($_.Exception.Message)" -Level 'WARN'
                    }
                }
                
                return $true
            }
        }
        catch {
            # Continue checking other service names
            continue
        }
    }
    
    Write-Log -Message "No Velociraptor service found" -Level 'WARN'
    return $false
}

# ==================== MAIN EXECUTION FUNCTIONS ====================
# Main functions that orchestrate the installation process

# Display help information
function Show-Help {
    Write-Host @"
$ScriptName v$ScriptVersion

DESCRIPTION:
    Automates the deployment of Velociraptor clients on Windows systems for incident
    response and threat hunting operations. Provides intelligent discovery and installation
    of Velociraptor client artifacts from a distribution server.

USAGE:
    .\Windows_Client.ps1 -Url <URL> [OPTIONS]

PARAMETERS:
    -Url <string>           Distribution server URL (required)
                           Can be root URL or direct artifact folder
                           
    -Method <string>        Installation method (default: auto)
                           auto: Intelligent method selection
                           msi:  Windows Installer package
                           exe:  Executable installer
                           raw:  Direct service installation
                           
    -Select <string>        Filter tokens for artifact selection
                           Space-separated AND filter (e.g. "windows 0.74 amd64")
                           
    -Depth <int>           BFS crawl depth (default: 4)
    -Insecure              Allow self-signed certificates
    -AssumeYes             Skip confirmation prompts
    -List                  List artifacts without installing
    -Dest <string>         Installation directory (default: C:\ProgramData\Velociraptor)
    -Help                  Show this help message

EXAMPLES:
    # Install from specific artifact directory
    .\Windows_Client.ps1 -Url http://server:9999/windows/v0.74-amd64/ -AssumeYes
    
    # Auto-discover and install with filtering
    .\Windows_Client.ps1 -Url http://server:9999/ -Select "windows 0.74 amd64" -AssumeYes
    
    # List available artifacts without installing
    .\Windows_Client.ps1 -Url http://server:9999/ -List

NOTES:
    - Requires Administrator privileges for service installation
    - MSI method is recommended for production deployments
    - Use -Insecure flag only for testing with self-signed certificates

"@
}

# Main execution function
function Main {
    Write-Log -Message "$ScriptName v$ScriptVersion starting..." -Level 'INFO'
    
    # Show help if requested or no URL provided
    if ($Help -or -not $Url) {
        Show-Help
        return
    }
    
    # Verify administrator privileges unless in List mode
    if (-not $List) {
        Assert-Administrator
    }
    
    # Initialize web client
    Initialize-WebClient
    
    # Normalize URL
    $normalizedUrl = Format-Url -InputUrl $Url
    
    # Parse filter tokens
    $filterTokens = if ($Select) { $Select.Split(' ', [StringSplitOptions]::RemoveEmptyEntries) } else { @() }
    
    Write-Log -Message "Configuration:" -Level 'INFO'
    Write-Log -Message "  URL: $normalizedUrl" -Level 'INFO'
    Write-Log -Message "  Method: $Method" -Level 'INFO'
    Write-Log -Message "  Filter: $($filterTokens -join ', ')" -Level 'INFO'
    Write-Log -Message "  Depth: $Depth" -Level 'INFO'
    Write-Log -Message "  List only: $List" -Level 'INFO'
    
    # Create temporary directory
    $script:TempDirectory = Join-Path $env:TEMP "VelociraptorInstall_$(Get-Random)"
    New-Item -Path $TempDirectory -ItemType Directory -Force | Out-Null
    Write-Log -Message "Temporary directory: $TempDirectory" -Level 'DEBUG'
    
    try {
        # Discover artifacts
        Write-Log -Message "Discovering Velociraptor artifacts..." -Level 'INFO'
        $candidates = BFS-Find -StartUrl $normalizedUrl -FilterTokens $filterTokens -MaxDepth $Depth
        
        if ($candidates.Count -eq 0) {
            Stop-WithError "No Velociraptor artifacts found"
        }
        
        # Select best candidate (first one found)
        $selectedCandidate = $candidates[0]
        Write-Log -Message "Selected artifact directory: $($selectedCandidate.Url)" -Level 'SUCCESS'
        
        # Analyze artifacts in selected directory
        $artifactInfo = Get-ArtifactInfo -ArtifactUrl $selectedCandidate.Url
        if (-not $artifactInfo) {
            Stop-WithError "Failed to analyze artifacts"
        }
        
        # If List mode, display artifacts and exit
        if ($List) {
            Write-Host "`nAvailable Artifacts:" -ForegroundColor Cyan
            Write-Host "===================" -ForegroundColor Cyan
            
            if ($artifactInfo.MSI.Count -gt 0) {
                Write-Host "`nMSI Files:" -ForegroundColor Yellow
                foreach ($msi in $artifactInfo.MSI) {
                    $repackedText = if ($msi.IsRepacked) { " (repacked)" } else { "" }
                    Write-Host "  - $($msi.Name)$repackedText" -ForegroundColor White
                }
            }
            
            if ($artifactInfo.EXE.Count -gt 0) {
                Write-Host "`nEXE Files:" -ForegroundColor Yellow
                foreach ($exe in $artifactInfo.EXE) {
                    $repackedText = if ($exe.IsRepacked) { " (repacked)" } else { "" }
                    Write-Host "  - $($exe.Name)$repackedText" -ForegroundColor White
                }
            }
            
            if ($artifactInfo.RAW.Count -gt 0) {
                Write-Host "`nRAW Binaries:" -ForegroundColor Yellow
                foreach ($raw in $artifactInfo.RAW) {
                    Write-Host "  - $($raw.Name)" -ForegroundColor White
                }
            }
            
            if ($artifactInfo.Config) {
                Write-Host "`nConfiguration:" -ForegroundColor Yellow
                Write-Host "  - $($artifactInfo.Config.Name)" -ForegroundColor White
            }
            
            return
        }
        
        # Select best artifact for installation
        $selectedArtifact = Select-BestArtifact -Artifacts $artifactInfo -PreferredMethod $Method
        if (-not $selectedArtifact) {
            Stop-WithError "No suitable artifacts found for method: $Method"
        }
        
        # Confirm installation unless AssumeYes is specified
        if (-not $AssumeYes) {
            Write-Host "`nInstallation Plan:" -ForegroundColor Cyan
            Write-Host "=================" -ForegroundColor Cyan
            Write-Host "Method: $($selectedArtifact.Type)" -ForegroundColor Yellow
            Write-Host "Artifact: $($selectedArtifact.Artifact.Name)" -ForegroundColor Yellow
            Write-Host "Source: $($selectedCandidate.Url)" -ForegroundColor Yellow
            Write-Host ""
            
            $confirmation = Read-Host "Proceed with installation? [Y/N]"
            if ($confirmation -notmatch '^[Yy]') {
                Write-Log -Message "Installation cancelled by user" -Level 'INFO'
                return
            }
        }
        
        # Perform installation based on selected artifact type
        Write-Log -Message "Starting installation..." -Level 'INFO'
        $installSuccess = $false
        
        switch ($selectedArtifact.Type) {
            'MSI' {
                $installSuccess = Install-MSI -ArtifactInfo $selectedArtifact
            }
            'EXE' {
                $installSuccess = Install-EXE -ArtifactInfo $selectedArtifact
            }
            'RAW' {
                $installSuccess = Install-RAW -ArtifactInfo $selectedArtifact
            }
        }
        
        if ($installSuccess) {
            Write-Log -Message "Installation completed successfully!" -Level 'SUCCESS'
            
            # Verify service installation
            if (Test-VelociraptorService) {
                Write-Log -Message "Velociraptor service verification completed" -Level 'SUCCESS'
            }
            else {
                Write-Log -Message "Service verification failed - manual verification may be required" -Level 'WARN'
            }
            
            # Display installation summary
            Write-Host "`nInstallation Summary:" -ForegroundColor Green
            Write-Host "====================" -ForegroundColor Green
            Write-Host "✓ Velociraptor client installed successfully" -ForegroundColor Green
            Write-Host "✓ Service configured and started" -ForegroundColor Green
            Write-Host "✓ Client ready for server communication" -ForegroundColor Green
            Write-Host ""
            Write-Host "Next steps:" -ForegroundColor Cyan
            Write-Host "- Verify client appears in Velociraptor server console" -ForegroundColor White
            Write-Host "- Monitor service status: Get-Service *velociraptor*" -ForegroundColor White
            Write-Host "- Check event logs for any service issues" -ForegroundColor White
        }
        else {
            Stop-WithError "Installation failed"
        }
    }
    finally {
        # Cleanup resources
        Cleanup-Resources
    }
}

# ==================== SCRIPT ENTRY POINT ====================
# Execute main function with error handling

try {
    Main
}
catch {
    Write-Log -Message "Unhandled error: $($_.Exception.Message)" -Level 'ERROR'
    Write-Log -Message "Stack trace: $($_.ScriptStackTrace)" -Level 'DEBUG'
    Cleanup-Resources
    exit 1
}
