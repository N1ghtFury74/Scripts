<#
.SYNOPSIS
    Velociraptor Windows Client Installer (fixed and Windows PowerShell 5.1 compatible).

.DESCRIPTION
    Discovers Velociraptor MSI/EXE artifacts from a distribution server, strictly applies
    the -Select filter to the artifact filename, downloads the selected artifact, installs
    it, and verifies the Windows service and PE architecture.

    Key fixes:
      - No System.Web.HttpUtility dependency.
      - Correct PowerShell string and regex syntax.
      - Windows PowerShell 5.1 compatible TLS handling.
      - Safe breadth-first crawling without array slicing errors.
      - Strict artifact filtering so amd64 cannot silently fall back to 386.
      - RAW service installation receives the source URL explicitly.
      - MSI logs are preserved outside the temporary download directory.

.EXAMPLE
    .\Windows_Client_Fixed.ps1 -Url "http://44.201.135.251:9999/" `
        -Select "v0.77.1-amd64" -Method msi -AssumeYes

.EXAMPLE
    .\Windows_Client_Fixed.ps1 -Url "http://44.201.135.251:9999/" `
        -Select "v0.77.1-amd64" -Method msi -List
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Url,

    [ValidateSet('auto', 'msi', 'exe', 'raw')]
    [string]$Method = 'auto',

    [string]$Select = '',

    [ValidateRange(0, 10)]
    [int]$Depth = 4,

    [switch]$Insecure,
    [switch]$AssumeYes,
    [switch]$List,

    [string]$Dest = 'C:\ProgramData\Velociraptor'
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

$ScriptVersion = '1.5-fixed'
$ScriptName = 'Velociraptor Windows Client Installer'
$UserAgent = "VelociraptorInstaller/$ScriptVersion"

$script:WebClient = $null
$script:TempDirectory = $null
$script:OriginalCertificateCallback = $null
$script:SelectionParts = @()
$script:LastMsiLog = $null

function Write-Log {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [ValidateSet('INFO', 'WARN', 'ERROR', 'SUCCESS', 'DEBUG')]
        [string]$Level = 'INFO'
    )

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logMessage = "[$timestamp] ${Level}: $Message"

    switch ($Level) {
        'ERROR'   { Write-Host $logMessage -ForegroundColor Red }
        'WARN'    { Write-Host $logMessage -ForegroundColor Yellow }
        'SUCCESS' { Write-Host $logMessage -ForegroundColor Green }
        'DEBUG'   { Write-Host $logMessage -ForegroundColor DarkGray }
        default   { Write-Host $logMessage -ForegroundColor White }
    }
}

function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object -TypeName Security.Principal.WindowsPrincipal -ArgumentList $identity
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Assert-Administrator {
    if (-not (Test-Administrator)) {
        throw 'This script must be run from an Administrator PowerShell window.'
    }
}

function Initialize-WebClient {
    Write-Log -Message 'Initializing web client.' -Level 'DEBUG'

    $script:WebClient = New-Object System.Net.WebClient
    $script:WebClient.Headers.Add('User-Agent', $UserAgent)

    $protocol = [System.Net.SecurityProtocolType]::Tls12
    $availableProtocols = [Enum]::GetNames([System.Net.SecurityProtocolType])
    if ($availableProtocols -contains 'Tls13') {
        $tls13 = [Enum]::Parse([System.Net.SecurityProtocolType], 'Tls13')
        $protocol = $protocol -bor $tls13
    }
    [System.Net.ServicePointManager]::SecurityProtocol = $protocol

    if ($Insecure) {
        Write-Log -Message 'Certificate validation is disabled for this process.' -Level 'WARN'
        $script:OriginalCertificateCallback = [System.Net.ServicePointManager]::ServerCertificateValidationCallback
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
    }
}

function Cleanup-Resources {
    if ($script:WebClient) {
        try {
            $script:WebClient.Dispose()
        }
        catch {
            # Ignore cleanup errors.
        }
        $script:WebClient = $null
    }

    if ($Insecure) {
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $script:OriginalCertificateCallback
    }

    if ($script:TempDirectory -and (Test-Path -LiteralPath $script:TempDirectory)) {
        try {
            Remove-Item -LiteralPath $script:TempDirectory -Recurse -Force -ErrorAction SilentlyContinue
        }
        catch {
            # Ignore cleanup errors.
        }
    }
}

function Format-Url {
    param([Parameter(Mandatory = $true)][string]$InputUrl)

    $result = $InputUrl.Trim()
    if ($result -notmatch '^https?://') {
        $result = "http://$result"
    }

    return $result.TrimEnd('/')
}

function Get-SelectionParts {
    param([string]$Selection)

    if ([string]::IsNullOrWhiteSpace($Selection)) {
        return @()
    }

    $parts = @()
    foreach ($rawPart in ($Selection -split '[\s,_-]+')) {
        $part = $rawPart.Trim().ToLowerInvariant()
        if (-not $part) {
            continue
        }

        if ($part -match '^v\d') {
            $part = $part.Substring(1)
        }

        $parts += $part
    }

    return @($parts | Select-Object -Unique)
}

function Test-SelectionMatch {
    param(
        [Parameter(Mandatory = $true)][string]$Text,
        [string[]]$Parts = @()
    )

    if (-not $Parts -or $Parts.Count -eq 0) {
        return $true
    }

    $target = $Text.ToLowerInvariant()

    foreach ($part in $Parts) {
        switch -Regex ($part) {
            '^(amd64|x64|x86_64)$' {
                if ($target -notmatch '(^|[^a-z0-9])(amd64|x64|x86_64)([^a-z0-9]|$)') {
                    return $false
                }
                continue
            }

            '^(386|i386|x86)$' {
                if ($target -notmatch '(^|[^a-z0-9])(386|i386|x86)([^a-z0-9]|$)') {
                    return $false
                }
                continue
            }

            default {
                if (-not $target.Contains($part)) {
                    return $false
                }
            }
        }
    }

    return $true
}

function Get-FileNameFromUrl {
    param([Parameter(Mandatory = $true)][string]$FileUrl)

    $uri = New-Object -TypeName System.Uri -ArgumentList $FileUrl
    $segment = $uri.Segments[$uri.Segments.Count - 1]
    return [System.Uri]::UnescapeDataString($segment.TrimEnd('/'))
}

function Resolve-LinkUrl {
    param(
        [Parameter(Mandatory = $true)][string]$BaseUrl,
        [Parameter(Mandatory = $true)][string]$Href
    )

    $baseUri = New-Object -TypeName System.Uri -ArgumentList ($BaseUrl.TrimEnd('/') + '/')
    $decodedHref = [System.Net.WebUtility]::HtmlDecode($Href.Trim())
    return (New-Object -TypeName System.Uri -ArgumentList $baseUri, $decodedHref).AbsoluteUri.TrimEnd('/')
}

function Get-HtmlLinks {
    param(
        [Parameter(Mandatory = $true)][string]$HtmlContent,
        [Parameter(Mandatory = $true)][string]$BaseUrl
    )

    $results = @()
    $seen = @{}

    # Single quotes inside a PowerShell single-quoted string are represented by two single quotes.
    $linkPattern = 'href\s*=\s*["''](?<href>[^"'']+)["'']'
    $matches = [regex]::Matches(
        $HtmlContent,
        $linkPattern,
        [System.Text.RegularExpressions.RegexOptions]::IgnoreCase
    )

    $baseUri = New-Object -TypeName System.Uri -ArgumentList ($BaseUrl.TrimEnd('/') + '/')

    foreach ($match in $matches) {
        $href = [System.Net.WebUtility]::HtmlDecode($match.Groups['href'].Value.Trim())

        if (-not $href -or
            $href.StartsWith('#') -or
            $href.StartsWith('?') -or
            $href.StartsWith('mailto:', [System.StringComparison]::OrdinalIgnoreCase) -or
            $href.StartsWith('javascript:', [System.StringComparison]::OrdinalIgnoreCase) -or
            $href -eq '../' -or
            $href -eq './') {
            continue
        }

        try {
            $resolvedUri = New-Object -TypeName System.Uri -ArgumentList $baseUri, $href
        }
        catch {
            continue
        }

        if ($resolvedUri.Scheme -ne 'http' -and $resolvedUri.Scheme -ne 'https') {
            continue
        }

        # Do not crawl external hosts.
        if ($resolvedUri.Authority -ne $baseUri.Authority) {
            continue
        }

        $absoluteUrl = $resolvedUri.AbsoluteUri.TrimEnd('/')
        if ($seen.ContainsKey($absoluteUrl)) {
            continue
        }
        $seen[$absoluteUrl] = $true

        $path = $resolvedUri.AbsolutePath
        $isArtifact = $path -match '(?i)\.(msi|exe)$'
        $isConfig = $path -match '(?i)client\.config\.ya?ml$'
        $isDirectory = $href.EndsWith('/') -or (-not $isArtifact -and -not $isConfig -and -not [IO.Path]::HasExtension($path))

        $results += [pscustomobject]@{
            Url         = $absoluteUrl
            IsArtifact  = $isArtifact
            IsConfig    = $isConfig
            IsDirectory = $isDirectory
        }
    }

    return @($results)
}

function Get-ManifestLinks {
    param([Parameter(Mandatory = $true)][string]$BaseUrl)

    $results = @()
    $manifestUrl = "$($BaseUrl.TrimEnd('/'))/manifest.json"

    try {
        $manifestText = $script:WebClient.DownloadString($manifestUrl)
    }
    catch {
        return @()
    }

    $pattern = '(?i)["''](?<path>[^"'']+\.(?:msi|exe|ya?ml))["'']'
    $matches = [regex]::Matches($manifestText, $pattern)
    $seen = @{}

    foreach ($match in $matches) {
        $path = $match.Groups['path'].Value
        try {
            $resolved = Resolve-LinkUrl -BaseUrl $BaseUrl -Href $path
        }
        catch {
            continue
        }

        if ($seen.ContainsKey($resolved)) {
            continue
        }
        $seen[$resolved] = $true

        $results += [pscustomobject]@{
            Url         = $resolved
            IsArtifact  = $resolved -match '(?i)\.(msi|exe)$'
            IsConfig    = $resolved -match '(?i)client\.config\.ya?ml$'
            IsDirectory = $false
        }
    }

    return @($results)
}

function Get-PageLinks {
    param([Parameter(Mandatory = $true)][string]$PageUrl)

    $allLinks = @()
    $seen = @{}

    try {
        $html = $script:WebClient.DownloadString(($PageUrl.TrimEnd('/') + '/'))
        foreach ($link in (Get-HtmlLinks -HtmlContent $html -BaseUrl $PageUrl)) {
            if (-not $seen.ContainsKey($link.Url)) {
                $seen[$link.Url] = $true
                $allLinks += $link
            }
        }
    }
    catch {
        Write-Log -Message "Could not read directory page $PageUrl. $($_.Exception.Message)" -Level 'DEBUG'
    }

    foreach ($link in (Get-ManifestLinks -BaseUrl $PageUrl)) {
        if (-not $seen.ContainsKey($link.Url)) {
            $seen[$link.Url] = $true
            $allLinks += $link
        }
    }

    return @($allLinks)
}

function New-ArtifactRecord {
    param([Parameter(Mandatory = $true)][string]$ArtifactUrl)

    $name = Get-FileNameFromUrl -FileUrl $ArtifactUrl
    $lower = $name.ToLowerInvariant()

    $type = if ($lower.EndsWith('.msi')) { 'MSI' } else { 'EXE' }
    $isRepacked = $name -match '(?i)Windows_VelociraptorClient'
    $isRaw = $type -eq 'EXE' -and -not $isRepacked -and $name -match '(?i)^velociraptor.*\.exe$'

    return [pscustomobject]@{
        Name       = $name
        Url        = $ArtifactUrl
        Type       = $type
        IsRepacked = $isRepacked
        IsRaw      = $isRaw
    }
}

function Get-ArtifactInfo {
    param([Parameter(Mandatory = $true)][string]$ArtifactUrl)

    $artifacts = @{
        MSI    = @()
        EXE    = @()
        RAW    = @()
        Config = $null
    }

    if ($ArtifactUrl -match '(?i)\.(msi|exe)$') {
        $record = New-ArtifactRecord -ArtifactUrl $ArtifactUrl
        if ($record.Type -eq 'MSI') {
            $artifacts.MSI = @($record)
        }
        elseif ($record.IsRaw) {
            $artifacts.RAW = @($record)
        }
        else {
            $artifacts.EXE = @($record)
        }
        return $artifacts
    }

    $links = Get-PageLinks -PageUrl $ArtifactUrl

    foreach ($link in $links) {
        if ($link.IsConfig) {
            $artifacts.Config = [pscustomobject]@{
                Name = Get-FileNameFromUrl -FileUrl $link.Url
                Url  = $link.Url
            }
            continue
        }

        if (-not $link.IsArtifact) {
            continue
        }

        $record = New-ArtifactRecord -ArtifactUrl $link.Url
        if ($record.Type -eq 'MSI') {
            $artifacts.MSI += $record
        }
        elseif ($record.IsRaw) {
            $artifacts.RAW += $record
        }
        else {
            $artifacts.EXE += $record
        }
    }

    $artifacts.MSI = @($artifacts.MSI | Sort-Object Name -Unique)
    $artifacts.EXE = @($artifacts.EXE | Sort-Object Name -Unique)
    $artifacts.RAW = @($artifacts.RAW | Sort-Object Name -Unique)

    return $artifacts
}

function Find-ArtifactDirectories {
    param(
        [Parameter(Mandatory = $true)][string]$StartUrl,
        [string[]]$FilterParts = @(),
        [int]$MaxDepth = 4
    )

    if ($StartUrl -match '(?i)\.(msi|exe)$') {
        return @([pscustomobject]@{ Url = $StartUrl; Depth = 0 })
    }

    $queue = New-Object System.Collections.ArrayList
    [void]$queue.Add([pscustomobject]@{ Url = $StartUrl; Depth = 0 })

    $visited = @{}
    $candidateUrls = @{}
    $candidates = @()

    while ($queue.Count -gt 0) {
        $current = $queue[0]
        $queue.RemoveAt(0)

        $currentUrl = $current.Url.TrimEnd('/')
        $currentDepth = [int]$current.Depth

        if ($currentDepth -gt $MaxDepth -or $visited.ContainsKey($currentUrl)) {
            continue
        }

        $visited[$currentUrl] = $true
        Write-Log -Message "Scanning depth ${currentDepth}: $currentUrl" -Level 'DEBUG'

        $links = Get-PageLinks -PageUrl $currentUrl
        $artifactLinks = @($links | Where-Object { $_.IsArtifact })

        if ($artifactLinks.Count -gt 0) {
            $directoryMatches = Test-SelectionMatch -Text $currentUrl -Parts $FilterParts
            $artifactMatches = @(
                $artifactLinks | Where-Object {
                    $name = Get-FileNameFromUrl -FileUrl $_.Url
                    Test-SelectionMatch -Text $name -Parts $FilterParts
                }
            )

            if ($FilterParts.Count -eq 0 -or $directoryMatches -or $artifactMatches.Count -gt 0) {
                if (-not $candidateUrls.ContainsKey($currentUrl)) {
                    $candidateUrls[$currentUrl] = $true
                    $candidates += [pscustomobject]@{
                        Url   = $currentUrl
                        Depth = $currentDepth
                    }
                    Write-Log -Message "Found artifact directory: $currentUrl" -Level 'SUCCESS'
                }
            }
        }

        if ($currentDepth -ge $MaxDepth) {
            continue
        }

        foreach ($link in ($links | Where-Object { $_.IsDirectory })) {
            if (-not $visited.ContainsKey($link.Url)) {
                [void]$queue.Add([pscustomobject]@{
                    Url   = $link.Url
                    Depth = $currentDepth + 1
                })
            }
        }
    }

    return @($candidates | Sort-Object Depth, Url)
}

function Show-AvailableArtifacts {
    param([Parameter(Mandatory = $true)][hashtable]$Artifacts)

    Write-Host ''
    Write-Host 'Available artifacts' -ForegroundColor Cyan
    Write-Host '-------------------' -ForegroundColor Cyan

    foreach ($item in @($Artifacts.MSI)) {
        Write-Host "MSI : $($item.Name)" -ForegroundColor White
    }
    foreach ($item in @($Artifacts.EXE)) {
        Write-Host "EXE : $($item.Name)" -ForegroundColor White
    }
    foreach ($item in @($Artifacts.RAW)) {
        Write-Host "RAW : $($item.Name)" -ForegroundColor White
    }
    if ($Artifacts.Config) {
        Write-Host "CFG : $($Artifacts.Config.Name)" -ForegroundColor White
    }
}

function Select-BestArtifact {
    param(
        [Parameter(Mandatory = $true)][hashtable]$Artifacts,
        [Parameter(Mandatory = $true)][string]$PreferredMethod,
        [string[]]$FilterParts = @()
    )

    $msi = @($Artifacts.MSI)
    $exe = @($Artifacts.EXE)
    $raw = @($Artifacts.RAW)

    if ($FilterParts.Count -gt 0) {
        $msi = @($msi | Where-Object { Test-SelectionMatch -Text $_.Name -Parts $FilterParts })
        $exe = @($exe | Where-Object { Test-SelectionMatch -Text $_.Name -Parts $FilterParts })
        $raw = @($raw | Where-Object { Test-SelectionMatch -Text $_.Name -Parts $FilterParts })
    }

    if ($FilterParts.Count -gt 0 -and ($msi.Count + $exe.Count + $raw.Count) -eq 0) {
        Write-Log -Message "No artifact filename matches selection: $Select" -Level 'ERROR'
        Show-AvailableArtifacts -Artifacts $Artifacts
        return $null
    }

    switch ($PreferredMethod) {
        'msi' {
            $repacked = @($msi | Where-Object { $_.IsRepacked })
            $chosen = if ($repacked.Count -gt 0) { $repacked[0] } elseif ($msi.Count -gt 0) { $msi[0] } else { $null }
            if ($chosen) {
                return @{ Type = 'MSI'; Artifact = $chosen }
            }
        }

        'exe' {
            if ($exe.Count -gt 0) {
                return @{ Type = 'EXE'; Artifact = $exe[0] }
            }
        }

        'raw' {
            if ($raw.Count -gt 0) {
                return @{ Type = 'RAW'; Artifact = $raw[0] }
            }
        }

        'auto' {
            $repackedMsi = @($msi | Where-Object { $_.IsRepacked })
            if ($repackedMsi.Count -gt 0) {
                return @{ Type = 'MSI'; Artifact = $repackedMsi[0] }
            }
            if ($msi.Count -gt 0) {
                return @{ Type = 'MSI'; Artifact = $msi[0] }
            }
            if ($exe.Count -gt 0) {
                return @{ Type = 'EXE'; Artifact = $exe[0] }
            }
            if ($raw.Count -gt 0) {
                return @{ Type = 'RAW'; Artifact = $raw[0] }
            }
        }
    }

    return $null
}

function Download-File {
    param(
        [Parameter(Mandatory = $true)][string]$SourceUrl,
        [Parameter(Mandatory = $true)][string]$Destination
    )

    $parent = Split-Path -Path $Destination -Parent
    if (-not (Test-Path -LiteralPath $parent)) {
        New-Item -Path $parent -ItemType Directory -Force | Out-Null
    }

    Write-Log -Message "Downloading $(Get-FileNameFromUrl -FileUrl $SourceUrl)" -Level 'INFO'
    $script:WebClient.DownloadFile($SourceUrl, $Destination)

    if (-not (Test-Path -LiteralPath $Destination)) {
        throw "Download did not create file: $Destination"
    }

    $length = (Get-Item -LiteralPath $Destination).Length
    if ($length -le 0) {
        throw "Downloaded file is empty: $Destination"
    }

    Write-Log -Message "Download complete: $length bytes" -Level 'SUCCESS'
}

function Install-MsiArtifact {
    param([Parameter(Mandatory = $true)][hashtable]$SelectedArtifact)

    $artifact = $SelectedArtifact.Artifact
    $msiPath = Join-Path $script:TempDirectory $artifact.Name
    Download-File -SourceUrl $artifact.Url -Destination $msiPath

    $logRoot = Join-Path $env:ProgramData 'Velociraptor\InstallerLogs'
    New-Item -Path $logRoot -ItemType Directory -Force | Out-Null
    $logName = 'msi_install_{0}.log' -f (Get-Date -Format 'yyyyMMdd_HHmmss')
    $logFile = Join-Path $logRoot $logName
    $script:LastMsiLog = $logFile

    $arguments = @(
        '/i'
        ('"{0}"' -f $msiPath)
        '/quiet'
        '/norestart'
        '/l*v'
        ('"{0}"' -f $logFile)
    )

    Write-Log -Message "Installing MSI: $($artifact.Name)" -Level 'INFO'
    $process = Start-Process -FilePath 'msiexec.exe' -ArgumentList $arguments -Wait -PassThru

    if ($process.ExitCode -eq 0) {
        Write-Log -Message 'MSI installation completed successfully.' -Level 'SUCCESS'
        return $true
    }

    if ($process.ExitCode -eq 3010) {
        Write-Log -Message 'MSI installation succeeded; Windows reports that a reboot is required.' -Level 'WARN'
        return $true
    }

    Write-Log -Message "MSI installation failed with exit code $($process.ExitCode)." -Level 'ERROR'
    Write-Log -Message "MSI log: $logFile" -Level 'ERROR'
    return $false
}

function Install-RawService {
    param(
        [Parameter(Mandatory = $true)][string]$BinaryPath,
        [Parameter(Mandatory = $true)][string]$SourceArtifactUrl
    )

    if (-not (Test-Path -LiteralPath $Dest)) {
        New-Item -Path $Dest -ItemType Directory -Force | Out-Null
    }

    $destinationBinary = Join-Path $Dest 'velociraptor.exe'
    Copy-Item -LiteralPath $BinaryPath -Destination $destinationBinary -Force

    $sourceDirectory = $SourceArtifactUrl -replace '/[^/]+$', ''
    $configUrl = "$sourceDirectory/client.config.yaml"
    $configPath = Join-Path $Dest 'client.config.yaml'
    $hasConfig = $false

    try {
        Download-File -SourceUrl $configUrl -Destination $configPath
        $hasConfig = $true
    }
    catch {
        Write-Log -Message 'No separate client.config.yaml was downloaded; the binary may contain an embedded configuration.' -Level 'WARN'
    }

    if ($hasConfig) {
        $arguments = @(
            '--config'
            ('"{0}"' -f $configPath)
            'service'
            'install'
            '-v'
        )
    }
    else {
        $arguments = @('service', 'install', '-v')
    }

    Write-Log -Message 'Installing Velociraptor service from executable.' -Level 'INFO'
    $process = Start-Process -FilePath $destinationBinary -ArgumentList $arguments -Wait -PassThru

    if ($process.ExitCode -eq 0) {
        Write-Log -Message 'Service installation completed successfully.' -Level 'SUCCESS'
        return $true
    }

    Write-Log -Message "Service installation failed with exit code $($process.ExitCode)." -Level 'ERROR'
    return $false
}

function Install-ExeArtifact {
    param([Parameter(Mandatory = $true)][hashtable]$SelectedArtifact)

    $artifact = $SelectedArtifact.Artifact
    $exePath = Join-Path $script:TempDirectory $artifact.Name
    Download-File -SourceUrl $artifact.Url -Destination $exePath

    if ($artifact.IsRepacked -or $artifact.IsRaw) {
        return Install-RawService -BinaryPath $exePath -SourceArtifactUrl $artifact.Url
    }

    $switchSets = @(
        @('/quiet', '/norestart'),
        @('/S'),
        @('/silent')
    )

    foreach ($switchSet in $switchSets) {
        Write-Log -Message "Trying EXE installer arguments: $($switchSet -join ' ')" -Level 'DEBUG'
        $process = Start-Process -FilePath $exePath -ArgumentList $switchSet -Wait -PassThru
        if ($process.ExitCode -eq 0 -or $process.ExitCode -eq 3010) {
            Write-Log -Message 'EXE installation completed successfully.' -Level 'SUCCESS'
            return $true
        }
    }

    Write-Log -Message 'The EXE did not accept the tested silent switches; trying Velociraptor service installation.' -Level 'WARN'
    return Install-RawService -BinaryPath $exePath -SourceArtifactUrl $artifact.Url
}

function Get-ServiceBinaryPath {
    param([Parameter(Mandatory = $true)][string]$PathName)

    $trimmed = $PathName.Trim()
    if ($trimmed.StartsWith('"')) {
        $closingQuote = $trimmed.IndexOf('"', 1)
        if ($closingQuote -gt 1) {
            return $trimmed.Substring(1, $closingQuote - 1)
        }
    }

    $exeIndex = $trimmed.IndexOf('.exe', [System.StringComparison]::OrdinalIgnoreCase)
    if ($exeIndex -ge 0) {
        return $trimmed.Substring(0, $exeIndex + 4).Trim('"')
    }

    return $trimmed
}

function Get-PeArchitecture {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        return 'Unknown'
    }

    $stream = $null
    $reader = $null
    try {
        $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
        $reader = New-Object -TypeName IO.BinaryReader -ArgumentList $stream

        if ($reader.ReadUInt16() -ne 0x5A4D) {
            return 'Unknown'
        }

        $stream.Position = 0x3C
        $peOffset = $reader.ReadInt32()
        $stream.Position = $peOffset

        if ($reader.ReadUInt32() -ne 0x00004550) {
            return 'Unknown'
        }

        $machine = $reader.ReadUInt16()
        switch ($machine) {
            0x014c { return 'x86' }
            0x8664 { return 'x64' }
            0xAA64 { return 'ARM64' }
            default { return ('Unknown (0x{0:X4})' -f $machine) }
        }
    }
    catch {
        return 'Unknown'
    }
    finally {
        if ($reader) { $reader.Dispose() }
        if ($stream) { $stream.Dispose() }
    }
}

function Test-VelociraptorService {
    param([string[]]$ExpectedSelectionParts = @())

    $service = Get-CimInstance Win32_Service -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -match '(?i)^Velociraptor(Client)?$' } |
        Select-Object -First 1

    if (-not $service) {
        Write-Log -Message 'Velociraptor service was not found.' -Level 'ERROR'
        return $false
    }

    if ($service.State -ne 'Running') {
        try {
            Start-Service -Name $service.Name
            Start-Sleep -Seconds 3
            $service = Get-CimInstance Win32_Service -Filter ("Name='{0}'" -f $service.Name)
        }
        catch {
            Write-Log -Message "Service exists but could not be started: $($_.Exception.Message)" -Level 'ERROR'
            return $false
        }
    }

    $binaryPath = Get-ServiceBinaryPath -PathName $service.PathName
    $architecture = Get-PeArchitecture -Path $binaryPath

    Write-Log -Message "Service name: $($service.Name)" -Level 'SUCCESS'
    Write-Log -Message "Service state: $($service.State)" -Level 'SUCCESS'
    Write-Log -Message "Binary path: $binaryPath" -Level 'INFO'
    Write-Log -Message "Binary architecture: $architecture" -Level 'INFO'

    $expectsAmd64 = @($ExpectedSelectionParts | Where-Object { $_ -match '^(amd64|x64|x86_64)$' }).Count -gt 0
    $expectsX86 = @($ExpectedSelectionParts | Where-Object { $_ -match '^(386|i386|x86)$' }).Count -gt 0

    if ($expectsAmd64 -and $architecture -ne 'x64') {
        Write-Log -Message "Architecture verification failed: amd64 was requested but the service binary is $architecture." -Level 'ERROR'
        return $false
    }

    if ($expectsX86 -and $architecture -ne 'x86') {
        Write-Log -Message "Architecture verification failed: 386/x86 was requested but the service binary is $architecture." -Level 'ERROR'
        return $false
    }

    return $service.State -eq 'Running'
}

function Main {
    if (-not $List) {
        Assert-Administrator
    }

    Initialize-WebClient

    $normalizedUrl = Format-Url -InputUrl $Url
    $script:SelectionParts = @(Get-SelectionParts -Selection $Select)

    Write-Log -Message "$ScriptName $ScriptVersion" -Level 'INFO'
    Write-Log -Message "URL: $normalizedUrl" -Level 'INFO'
    Write-Log -Message "Method: $Method" -Level 'INFO'
    Write-Log -Message "Selection: $(if ($Select) { $Select } else { '<none>' })" -Level 'INFO'
    Write-Log -Message "Selection parts: $($script:SelectionParts -join ', ')" -Level 'DEBUG'

    $script:TempDirectory = Join-Path $env:TEMP ("VelociraptorInstall_{0}" -f [Guid]::NewGuid().ToString('N'))
    New-Item -Path $script:TempDirectory -ItemType Directory -Force | Out-Null

    $candidates = @(Find-ArtifactDirectories -StartUrl $normalizedUrl -FilterParts $script:SelectionParts -MaxDepth $Depth)
    if ($candidates.Count -eq 0) {
        throw "No artifact directory matched '$Select' within depth $Depth."
    }

    $selectedArtifact = $null
    $selectedCandidate = $null
    $lastArtifactInfo = $null

    foreach ($candidate in $candidates) {
        Write-Log -Message "Analyzing: $($candidate.Url)" -Level 'INFO'
        $artifactInfo = Get-ArtifactInfo -ArtifactUrl $candidate.Url
        $lastArtifactInfo = $artifactInfo

        if ($List) {
            Write-Host "`nSource: $($candidate.Url)" -ForegroundColor Yellow
            Show-AvailableArtifacts -Artifacts $artifactInfo
            continue
        }

        $possibleSelection = Select-BestArtifact `
            -Artifacts $artifactInfo `
            -PreferredMethod $Method `
            -FilterParts $script:SelectionParts

        if ($possibleSelection) {
            $selectedArtifact = $possibleSelection
            $selectedCandidate = $candidate
            break
        }
    }

    if ($List) {
        return
    }

    if (-not $selectedArtifact) {
        if ($lastArtifactInfo) {
            Show-AvailableArtifacts -Artifacts $lastArtifactInfo
        }
        throw "No $Method artifact matched selection '$Select'. The script will not fall back to another version or architecture."
    }

    Write-Host ''
    Write-Host 'Installation plan' -ForegroundColor Cyan
    Write-Host '-----------------' -ForegroundColor Cyan
    Write-Host "Source directory : $($selectedCandidate.Url)"
    Write-Host "Method           : $($selectedArtifact.Type)"
    Write-Host "Artifact         : $($selectedArtifact.Artifact.Name)"
    Write-Host "Artifact URL     : $($selectedArtifact.Artifact.Url)"
    Write-Host ''

    if (-not $AssumeYes) {
        $answer = Read-Host 'Proceed? [Y/N]'
        if ($answer -notmatch '^[Yy]$') {
            Write-Log -Message 'Installation cancelled.' -Level 'WARN'
            return
        }
    }

    $success = $false
    switch ($selectedArtifact.Type) {
        'MSI' {
            $success = Install-MsiArtifact -SelectedArtifact $selectedArtifact
        }
        'EXE' {
            $success = Install-ExeArtifact -SelectedArtifact $selectedArtifact
        }
        'RAW' {
            $artifact = $selectedArtifact.Artifact
            $rawPath = Join-Path $script:TempDirectory $artifact.Name
            Download-File -SourceUrl $artifact.Url -Destination $rawPath
            $success = Install-RawService -BinaryPath $rawPath -SourceArtifactUrl $artifact.Url
        }
    }

    if (-not $success) {
        throw 'Installation failed.'
    }

    if (-not (Test-VelociraptorService -ExpectedSelectionParts $script:SelectionParts)) {
        throw 'The installation command completed, but service or architecture verification failed.'
    }

    Write-Host ''
    Write-Host 'Installation completed and verified.' -ForegroundColor Green
    if ($script:LastMsiLog) {
        Write-Host "MSI log: $script:LastMsiLog" -ForegroundColor Gray
    }
}

try {
    Main
}
catch {
    Write-Log -Message $_.Exception.Message -Level 'ERROR'
    if ($script:LastMsiLog) {
        Write-Log -Message "MSI log: $script:LastMsiLog" -Level 'ERROR'
    }
    exit 1
}
finally {
    Cleanup-Resources
}
