#requires -version 5.1
<#
.SYNOPSIS
Completely removes the active Velociraptor client installation and its common leftovers.

.DESCRIPTION
Removes Velociraptor MSI registrations, services, running processes, scheduled tasks,
firewall rules, Microsoft Defender exclusions, certificates, registry entries, files,
temporary installation artifacts, shortcuts, and optionally PowerShell history entries.

This script is intentionally limited to Velociraptor-related items. It does not clear
entire Windows event logs, Amcache, SRUM, the USN journal, restore points, or backups.
For a forensically pristine machine, reimage or reset Windows.

.PARAMETER Force
Skips the REMOVE confirmation prompt.

.PARAMETER IncludeHistory
Removes Velociraptor-related lines from PSReadLine history files and clears the current
PowerShell session history.

.PARAMETER SkipCertificateRemoval
Keeps certificates whose subject, issuer, or friendly name contains Velociraptor.

.EXAMPLE
.\Remove-Velociraptor-Completely.ps1 -Force -IncludeHistory
#>

[CmdletBinding()]
param(
    [switch]$Force,                  # Compatibility only; cleanup is always forced.
    [switch]$IncludeHistory,         # Compatibility only; history cleanup is now default.
    [switch]$SkipHistory,            # Disable Velociraptor-related history cleanup.
    [switch]$SkipCertificateRemoval, # Keep matching certificates.
    [switch]$RestartWhenDone         # Restart automatically after successful cleanup.
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$ScriptVersion = '2.0.0-silent-scale'
$ScriptName = 'VDA Client Cleanup'

$script:RemovedCount = 0
$script:Warnings = @()
$MatchRegex = '(?i)velociraptor'
$HistoryRegex = '(?i)velociraptor|client_installation\.ps1|windows_client\.ps1|44\.201\.135\.251:9999'

function Write-Section {
    param([Parameter(Mandatory = $true)][string]$Text)
    Write-Host "`n=== $Text ===" -ForegroundColor Cyan
}

function Write-Removed {
    param([Parameter(Mandatory = $true)][string]$Text)
    $script:RemovedCount++
    Write-Host "[REMOVED] $Text" -ForegroundColor Green
}

function Write-Skip {
    param([Parameter(Mandatory = $true)][string]$Text)
    Write-Host "[SKIP] $Text" -ForegroundColor DarkGray
}

function Write-WarningRecord {
    param([Parameter(Mandatory = $true)][string]$Text)
    $script:Warnings += $Text
    Write-Warning $Text
}

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Remove-PathPattern {
    param(
        [Parameter(Mandatory = $true)][string]$Pattern,
        [string]$Description = ''
    )

    $items = @(Get-Item -Path $Pattern -Force -ErrorAction SilentlyContinue)
    foreach ($item in $items) {
        if ($PSCommandPath -and $item.FullName -eq $PSCommandPath) {
            Write-Skip "Current cleanup script: $($item.FullName)"
            continue
        }

        $removed = $false
        for ($attempt = 1; $attempt -le 3 -and -not $removed; $attempt++) {
            try {
                if ($item.PSIsContainer) {
                    Get-ChildItem -LiteralPath $item.FullName -Recurse -Force -ErrorAction SilentlyContinue |
                        ForEach-Object { try { $_.Attributes = 'Normal' } catch {} }
                }
                else {
                    try { $item.Attributes = 'Normal' } catch {}
                }

                Remove-Item -LiteralPath $item.FullName -Recurse -Force -ErrorAction Stop
                $removed = $true
            }
            catch {
                if ($attempt -eq 1) {
                    try {
                        & "$env:SystemRoot\System32\takeown.exe" /F $item.FullName /A /R /D Y 2>$null | Out-Null
                        & "$env:SystemRoot\System32\icacls.exe" $item.FullName /grant '*S-1-5-32-544:(OI)(CI)F' /T /C /Q 2>$null | Out-Null
                    }
                    catch {}
                }
                Start-Sleep -Milliseconds 500
            }
        }

        if ($removed) {
            if ($Description) {
                Write-Removed "$Description`: $($item.FullName)"
            }
            else {
                Write-Removed $item.FullName
            }
        }
        else {
            Write-WarningRecord "Could not remove '$($item.FullName)' after three attempts. It may require a restart."
        }
    }
}

function Remove-RegistryKeyIfPresent {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (Test-Path -LiteralPath $Path) {
        try {
            Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction Stop
            Write-Removed "Registry key $Path"
        }
        catch {
            Write-WarningRecord "Could not remove registry key '$Path': $($_.Exception.Message)"
        }
    }
}

function Remove-MatchingRegistryValues {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        return
    }

    try {
        $properties = (Get-ItemProperty -LiteralPath $Path -ErrorAction Stop).PSObject.Properties |
            Where-Object { $_.Name -notmatch '^PS' }

        foreach ($property in $properties) {
            $valueText = [string]$property.Value
            if ($property.Name -match $MatchRegex -or $valueText -match $MatchRegex) {
                try {
                    Remove-ItemProperty -LiteralPath $Path -Name $property.Name -Force -ErrorAction Stop
                    Write-Removed "Registry value $Path\$($property.Name)"
                }
                catch {
                    Write-WarningRecord "Could not remove registry value '$Path\$($property.Name)': $($_.Exception.Message)"
                }
            }
        }
    }
    catch {
        Write-WarningRecord "Could not inspect registry path '$Path': $($_.Exception.Message)"
    }
}

if (-not $PSCommandPath) {
    throw 'Save this content as a .ps1 file and run it with -File. Do not paste the script body into an interactive PowerShell prompt.'
}

if (-not (Test-IsAdministrator)) {
    Write-Host '[INFO] Administrator rights are required. Attempting self-elevation...' -ForegroundColor Yellow

    $powerShellExe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $elevationArgs = @(
        '-NoLogo',
        '-NoProfile',
        '-NonInteractive',
        '-ExecutionPolicy', 'Bypass',
        '-File', ('"{0}"' -f $PSCommandPath)
    )

    if ($Force)                  { $elevationArgs += '-Force' }
    if ($IncludeHistory)         { $elevationArgs += '-IncludeHistory' }
    if ($SkipHistory)            { $elevationArgs += '-SkipHistory' }
    if ($SkipCertificateRemoval) { $elevationArgs += '-SkipCertificateRemoval' }
    if ($RestartWhenDone)        { $elevationArgs += '-RestartWhenDone' }

    try {
        $elevatedProcess = Start-Process -FilePath $powerShellExe `
            -ArgumentList $elevationArgs `
            -Verb RunAs `
            -Wait `
            -PassThru `
            -ErrorAction Stop
        exit $elevatedProcess.ExitCode
    }
    catch {
        Write-Error "Automatic elevation failed: $($_.Exception.Message)"
        exit 5
    }
}

Write-Host "$ScriptName $ScriptVersion" -ForegroundColor Yellow
Write-Host 'Running unattended cleanup. No confirmation is required.' -ForegroundColor Yellow
Write-Host 'Only Velociraptor-related active components and common leftovers are targeted.' -ForegroundColor Yellow

# ---------------------------------------------------------------------------
# 1. Stop Velociraptor processes
# ---------------------------------------------------------------------------
Write-Section 'Stopping processes'

try {
    $processes = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
        Where-Object {
            $_.ProcessId -ne $PID -and
            (
                $_.Name -match '^(?i)velociraptor.*\.exe$' -or
                ([string]$_.ExecutablePath -match '(?i)\\Velociraptor\\')
            )
        })

    foreach ($process in $processes) {
        try {
            Invoke-CimMethod -InputObject $process -MethodName Terminate -ErrorAction Stop | Out-Null
            Write-Removed "Process $($process.Name), PID $($process.ProcessId)"
        }
        catch {
            Write-WarningRecord "Could not terminate process '$($process.Name)' PID $($process.ProcessId): $($_.Exception.Message)"
        }
    }
}
catch {
    Write-WarningRecord "Process inspection failed: $($_.Exception.Message)"
}

# ---------------------------------------------------------------------------
# 2. Uninstall registered MSI packages without using Win32_Product
# ---------------------------------------------------------------------------
Write-Section 'Uninstalling registered packages'

$uninstallRoots = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
)

$uninstallEntries = @()

foreach ($root in $uninstallRoots) {
    if (-not (Test-Path -LiteralPath $root)) {
        continue
    }

    foreach ($key in @(Get-ChildItem -LiteralPath $root -ErrorAction SilentlyContinue)) {
        try {
            $entry = Get-ItemProperty -LiteralPath $key.PSPath -ErrorAction Stop
            if ([string]$entry.DisplayName -match $MatchRegex) {
                $uninstallEntries += [PSCustomObject]@{
                    DisplayName     = [string]$entry.DisplayName
                    KeyPath         = $key.PSPath
                    ChildName       = $key.PSChildName
                    UninstallString = [string]$entry.UninstallString
                }
            }
        }
        catch {
            # Ignore unreadable uninstall entries.
        }
    }
}

foreach ($entry in @($uninstallEntries | Sort-Object KeyPath -Unique)) {
    $productCode = $null

    if ($entry.ChildName -match '^\{[0-9A-Fa-f-]{36}\}$') {
        $productCode = $entry.ChildName
    }
    elseif ($entry.UninstallString -match '\{[0-9A-Fa-f-]{36}\}') {
        $productCode = $Matches[0]
    }

    if ($productCode) {
        try {
            Write-Host "[INFO] Uninstalling $($entry.DisplayName) using product code $productCode"
            $process = Start-Process -FilePath "$env:SystemRoot\System32\msiexec.exe" `
                -ArgumentList @('/x', $productCode, '/qn', '/norestart') `
                -Wait -PassThru -WindowStyle Hidden -ErrorAction Stop

            if ($process.ExitCode -in @(0, 1605, 1614, 3010)) {
                Write-Removed "MSI package $($entry.DisplayName) (exit code $($process.ExitCode))"
            }
            else {
                Write-WarningRecord "MSI uninstall returned exit code $($process.ExitCode) for '$($entry.DisplayName)'."
            }
        }
        catch {
            Write-WarningRecord "Could not uninstall '$($entry.DisplayName)': $($_.Exception.Message)"
        }
    }
    else {
        Write-WarningRecord "No MSI product code found for '$($entry.DisplayName)'; registry and files will still be removed."
    }
}

# ---------------------------------------------------------------------------
# 3. Delete remaining services
# ---------------------------------------------------------------------------
Write-Section 'Removing services'

try {
    $services = @(Get-CimInstance Win32_Service -ErrorAction SilentlyContinue |
        Where-Object {
            $_.Name -match $MatchRegex -or
            $_.DisplayName -match $MatchRegex -or
            ([string]$_.PathName -match $MatchRegex)
        })

    foreach ($service in $services) {
        try {
            Stop-Service -Name $service.Name -Force -ErrorAction SilentlyContinue
        }
        catch {
            # Continue with deletion.
        }

        try {
            & "$env:SystemRoot\System32\sc.exe" delete $service.Name | Out-Null
            Write-Removed "Service $($service.Name)"
        }
        catch {
            Write-WarningRecord "Could not delete service '$($service.Name)': $($_.Exception.Message)"
        }

        Remove-RegistryKeyIfPresent "HKLM:\SYSTEM\CurrentControlSet\Services\$($service.Name)"
    }
}
catch {
    Write-WarningRecord "Service inspection failed: $($_.Exception.Message)"
}

# Explicit common names in case WMI did not return them.
$commonServiceNames = @(
    'Velociraptor',
    'velociraptor',
    'VelociraptorClient',
    'velociraptor_client'
)

foreach ($serviceName in $commonServiceNames) {
    try {
        if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) {
            Stop-Service -Name $serviceName -Force -ErrorAction SilentlyContinue
            & "$env:SystemRoot\System32\sc.exe" delete $serviceName | Out-Null
            Write-Removed "Service $serviceName"
        }
    }
    catch {
        Write-WarningRecord "Could not remove service '$serviceName': $($_.Exception.Message)"
    }

    Remove-RegistryKeyIfPresent "HKLM:\SYSTEM\CurrentControlSet\Services\$serviceName"
}

# ---------------------------------------------------------------------------
# 4. Scheduled tasks
# ---------------------------------------------------------------------------
Write-Section 'Removing scheduled tasks'

if (Get-Command Get-ScheduledTask -ErrorAction SilentlyContinue) {
    try {
        foreach ($task in @(Get-ScheduledTask -ErrorAction SilentlyContinue)) {
            $actionText = [string]($task.Actions | Out-String)
            if (
                $task.TaskName -match $MatchRegex -or
                $task.TaskPath -match $MatchRegex -or
                $actionText -match $MatchRegex
            ) {
                try {
                    Unregister-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath `
                        -Confirm:$false -ErrorAction Stop
                    Write-Removed "Scheduled task $($task.TaskPath)$($task.TaskName)"
                }
                catch {
                    Write-WarningRecord "Could not remove scheduled task '$($task.TaskPath)$($task.TaskName)': $($_.Exception.Message)"
                }
            }
        }
    }
    catch {
        Write-WarningRecord "Scheduled task inspection failed: $($_.Exception.Message)"
    }
}
else {
    Write-Skip 'ScheduledTasks module is unavailable.'
}

# ---------------------------------------------------------------------------
# 5. Windows Firewall rules
# ---------------------------------------------------------------------------
Write-Section 'Removing firewall rules'

if (Get-Command Get-NetFirewallRule -ErrorAction SilentlyContinue) {
    try {
        foreach ($rule in @(Get-NetFirewallRule -ErrorAction SilentlyContinue)) {
            $matched = (
                [string]$rule.DisplayName -match $MatchRegex -or
                [string]$rule.Description -match $MatchRegex -or
                [string]$rule.Group -match $MatchRegex
            )

            if (-not $matched) {
                try {
                    $applicationFilters = @(Get-NetFirewallApplicationFilter `
                        -AssociatedNetFirewallRule $rule -ErrorAction SilentlyContinue)
                    foreach ($filter in $applicationFilters) {
                        if ([string]$filter.Program -match $MatchRegex) {
                            $matched = $true
                            break
                        }
                    }
                }
                catch {
                    # Continue based on rule metadata.
                }
            }

            if ($matched) {
                try {
                    Remove-NetFirewallRule -Name $rule.Name -ErrorAction Stop
                    Write-Removed "Firewall rule $($rule.DisplayName)"
                }
                catch {
                    Write-WarningRecord "Could not remove firewall rule '$($rule.DisplayName)': $($_.Exception.Message)"
                }
            }
        }
    }
    catch {
        Write-WarningRecord "Firewall rule inspection failed: $($_.Exception.Message)"
    }
}
else {
    Write-Skip 'NetSecurity module is unavailable.'
}

# ---------------------------------------------------------------------------
# 6. Microsoft Defender exclusions
# ---------------------------------------------------------------------------
Write-Section 'Removing Microsoft Defender exclusions'

if (
    (Get-Command Get-MpPreference -ErrorAction SilentlyContinue) -and
    (Get-Command Remove-MpPreference -ErrorAction SilentlyContinue)
) {
    try {
        $preferences = Get-MpPreference -ErrorAction Stop

        foreach ($path in @($preferences.ExclusionPath)) {
            if ([string]$path -match $MatchRegex) {
                try {
                    Remove-MpPreference -ExclusionPath $path -ErrorAction Stop
                    Write-Removed "Defender path exclusion $path"
                }
                catch {
                    Write-WarningRecord "Could not remove Defender path exclusion '$path': $($_.Exception.Message)"
                }
            }
        }

        foreach ($processName in @($preferences.ExclusionProcess)) {
            if ([string]$processName -match $MatchRegex) {
                try {
                    Remove-MpPreference -ExclusionProcess $processName -ErrorAction Stop
                    Write-Removed "Defender process exclusion $processName"
                }
                catch {
                    Write-WarningRecord "Could not remove Defender process exclusion '$processName': $($_.Exception.Message)"
                }
            }
        }
    }
    catch {
        Write-WarningRecord "Defender exclusion inspection failed: $($_.Exception.Message)"
    }
}
else {
    Write-Skip 'Microsoft Defender preference cmdlets are unavailable.'
}

# ---------------------------------------------------------------------------
# 7. Certificates
# ---------------------------------------------------------------------------
Write-Section 'Removing matching certificates'

if ($SkipCertificateRemoval) {
    Write-Skip 'Certificate removal disabled by parameter.'
}
else {
    $certificateStores = @(
        'Cert:\LocalMachine\My',
        'Cert:\LocalMachine\Root',
        'Cert:\LocalMachine\CA',
        'Cert:\LocalMachine\TrustedPublisher',
        'Cert:\CurrentUser\My',
        'Cert:\CurrentUser\Root',
        'Cert:\CurrentUser\CA',
        'Cert:\CurrentUser\TrustedPublisher'
    )

    foreach ($store in $certificateStores) {
        if (-not (Test-Path -LiteralPath $store)) {
            continue
        }

        foreach ($certificate in @(Get-ChildItem -LiteralPath $store -ErrorAction SilentlyContinue)) {
            if (
                [string]$certificate.Subject -match $MatchRegex -or
                [string]$certificate.Issuer -match $MatchRegex -or
                [string]$certificate.FriendlyName -match $MatchRegex
            ) {
                try {
                    Remove-Item -LiteralPath $certificate.PSPath -Force -ErrorAction Stop
                    Write-Removed "Certificate $($certificate.Thumbprint) from $store"
                }
                catch {
                    Write-WarningRecord "Could not remove certificate '$($certificate.Thumbprint)' from '$store': $($_.Exception.Message)"
                }
            }
        }
    }
}

# ---------------------------------------------------------------------------
# 8. Environment variables
# ---------------------------------------------------------------------------
Write-Section 'Removing environment variables'

$environmentTargets = @(
    [System.EnvironmentVariableTarget]::Machine,
    [System.EnvironmentVariableTarget]::User
)

foreach ($target in $environmentTargets) {
    try {
        $variables = [System.Environment]::GetEnvironmentVariables($target)
        foreach ($entry in $variables.GetEnumerator()) {
            if ([string]$entry.Key -match $MatchRegex -or [string]$entry.Value -match $MatchRegex) {
                [System.Environment]::SetEnvironmentVariable(
                    [string]$entry.Key,
                    $null,
                    $target
                )
                Write-Removed "$target environment variable $($entry.Key)"
            }
        }
    }
    catch {
        Write-WarningRecord "Could not inspect $target environment variables: $($_.Exception.Message)"
    }
}

# ---------------------------------------------------------------------------
# 9. Registry leftovers
# ---------------------------------------------------------------------------
Write-Section 'Removing registry leftovers'

foreach ($entry in $uninstallEntries) {
    Remove-RegistryKeyIfPresent $entry.KeyPath
}

$knownRegistryKeys = @(
    'HKLM:\SOFTWARE\Velociraptor',
    'HKLM:\SOFTWARE\WOW6432Node\Velociraptor',
    'HKCU:\SOFTWARE\Velociraptor',
    'HKLM:\SOFTWARE\Velocidex\Velociraptor',
    'HKLM:\SOFTWARE\WOW6432Node\Velocidex\Velociraptor',
    'HKCU:\SOFTWARE\Velocidex\Velociraptor',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\velociraptor.exe',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\App Paths\velociraptor.exe'
)

foreach ($keyPath in $knownRegistryKeys) {
    Remove-RegistryKeyIfPresent $keyPath
}

$runKeys = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce'
)

foreach ($runKey in $runKeys) {
    Remove-MatchingRegistryValues $runKey
}

# Remove matching App Paths keys.
$appPathRoots = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths',
    'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\App Paths'
)

foreach ($root in $appPathRoots) {
    if (Test-Path -LiteralPath $root) {
        foreach ($child in @(Get-ChildItem -LiteralPath $root -ErrorAction SilentlyContinue)) {
            try {
                $propertyText = [string](Get-ItemProperty -LiteralPath $child.PSPath -ErrorAction SilentlyContinue | Out-String)
                if ($child.PSChildName -match $MatchRegex -or $propertyText -match $MatchRegex) {
                    Remove-RegistryKeyIfPresent $child.PSPath
                }
            }
            catch {
                Write-WarningRecord "Could not inspect App Paths key '$($child.PSPath)': $($_.Exception.Message)"
            }
        }
    }
}

# Remove Velociraptor event-source/provider registrations without clearing whole logs.
$eventLogRoots = @(
    'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Application',
    'HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\System'
)

foreach ($root in $eventLogRoots) {
    if (Test-Path -LiteralPath $root) {
        foreach ($child in @(Get-ChildItem -LiteralPath $root -ErrorAction SilentlyContinue)) {
            try {
                $propertyText = [string](Get-ItemProperty -LiteralPath $child.PSPath -ErrorAction SilentlyContinue | Out-String)
                if ($child.PSChildName -match $MatchRegex -or $propertyText -match $MatchRegex) {
                    Remove-RegistryKeyIfPresent $child.PSPath
                }
            }
            catch {
                Write-WarningRecord "Could not inspect event source '$($child.PSPath)': $($_.Exception.Message)"
            }
        }
    }
}

# ---------------------------------------------------------------------------
# 10. Custom event logs whose channel name contains Velociraptor
# ---------------------------------------------------------------------------
Write-Section 'Clearing custom Velociraptor event channels'

if (Test-Path "$env:SystemRoot\System32\wevtutil.exe") {
    try {
        $customLogs = @(& "$env:SystemRoot\System32\wevtutil.exe" el 2>$null |
            Where-Object { $_ -match $MatchRegex })

        foreach ($logName in $customLogs) {
            try {
                & "$env:SystemRoot\System32\wevtutil.exe" cl "$logName" 2>$null
                & "$env:SystemRoot\System32\wevtutil.exe" sl "$logName" /e:false 2>$null
                Write-Removed "Custom event channel $logName"
            }
            catch {
                Write-WarningRecord "Could not clear or disable event channel '$logName': $($_.Exception.Message)"
            }
        }
    }
    catch {
        Write-WarningRecord "Could not enumerate custom event channels: $($_.Exception.Message)"
    }
}

# ---------------------------------------------------------------------------
# 11. Files, folders, installers, configs, shortcuts, prefetch, and WER
# ---------------------------------------------------------------------------
Write-Section 'Removing files and folders'

$filePatterns = @(
    "$env:ProgramFiles\Velociraptor",
    "$env:ProgramData\Velociraptor",
    "$env:SystemDrive\Velociraptor",
    "$env:SystemRoot\Temp\Velociraptor*",
    "$env:SystemRoot\Prefetch\VELOCIRAPTOR*.pf",
    "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Velociraptor*",
    "$env:ProgramData\Microsoft\Windows\WER\ReportArchive\*Velociraptor*",
    "$env:ProgramData\Microsoft\Windows\WER\ReportQueue\*Velociraptor*",
    "$env:SystemRoot\System32\config\systemprofile\AppData\Local\Velociraptor",
    "$env:SystemRoot\ServiceProfiles\LocalService\AppData\Local\Velociraptor",
    "$env:SystemRoot\ServiceProfiles\NetworkService\AppData\Local\Velociraptor"
)

if (${env:ProgramFiles(x86)}) {
    $filePatterns += "${env:ProgramFiles(x86)}\Velociraptor"
}

# Current temporary folders used by the uploaded installer family.
$filePatterns += "$env:TEMP\VelociraptorInstall_*"
$filePatterns += "$env:TEMP\Velociraptor*"

try {
    $profiles = @(Get-CimInstance Win32_UserProfile -ErrorAction SilentlyContinue |
        Where-Object { $_.LocalPath -and (Test-Path -LiteralPath $_.LocalPath) })
}
catch {
    $profiles = @()
    Write-WarningRecord "Could not enumerate user profiles: $($_.Exception.Message)"
}

foreach ($profile in $profiles) {
    $base = $profile.LocalPath

    $filePatterns += @(
        "$base\AppData\Local\Velociraptor",
        "$base\AppData\Roaming\Velociraptor",
        "$base\AppData\Local\Temp\VelociraptorInstall_*",
        "$base\AppData\Local\Temp\Velociraptor*",
        "$base\AppData\Local\Microsoft\Windows\WER\ReportArchive\*Velociraptor*",
        "$base\AppData\Local\Microsoft\Windows\WER\ReportQueue\*Velociraptor*",
        "$base\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Velociraptor*",
        "$base\AppData\Roaming\Microsoft\Windows\Recent\*Velociraptor*",
        "$base\Desktop\*Velociraptor*.lnk",
        "$base\Downloads\Windows_VelociraptorClient_*.msi",
        "$base\Downloads\Windows_VelociraptorClient_*.exe",
        "$base\Downloads\velociraptor*.exe",
        "$base\Downloads\velociraptor*.zip",
        "$base\Downloads\client.config.yaml",
        "$base\Downloads\client_installation.ps1",
        "$base\Downloads\Windows_Client.ps1",
        "$base\Desktop\client_installation.ps1",
        "$base\Desktop\Windows_Client.ps1"
    )
}

foreach ($pattern in @($filePatterns | Where-Object { $_ } | Sort-Object -Unique)) {
    Remove-PathPattern -Pattern $pattern
}

# Remove old random Vrw_* installer staging folders only when their content references Velociraptor.
$tempRoots = @("$env:TEMP", "$env:SystemRoot\Temp")
foreach ($profile in $profiles) {
    $tempRoots += "$($profile.LocalPath)\AppData\Local\Temp"
}

foreach ($tempRoot in @($tempRoots | Where-Object { Test-Path -LiteralPath $_ } | Sort-Object -Unique)) {
    foreach ($folder in @(Get-ChildItem -LiteralPath $tempRoot -Directory -Filter 'Vrw_*' -Force -ErrorAction SilentlyContinue)) {
        $isVelociraptorFolder = $false

        try {
            $matchingFiles = @(Get-ChildItem -LiteralPath $folder.FullName -Recurse -Force -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -match $MatchRegex })

            if ($matchingFiles.Count -gt 0) {
                $isVelociraptorFolder = $true
            }
            else {
                foreach ($log in @(Get-ChildItem -LiteralPath $folder.FullName -File -Filter '*.log' -Force -ErrorAction SilentlyContinue)) {
                    if (Select-String -LiteralPath $log.FullName -Pattern 'Velociraptor' -Quiet -ErrorAction SilentlyContinue) {
                        $isVelociraptorFolder = $true
                        break
                    }
                }
            }
        }
        catch {
            # Do not remove an unidentified Vrw_* folder.
        }

        if ($isVelociraptorFolder) {
            Remove-PathPattern -Pattern $folder.FullName -Description 'Installer staging folder'
        }
    }
}

# ---------------------------------------------------------------------------
# 12. Optional PowerShell history cleanup
# ---------------------------------------------------------------------------
Write-Section 'PowerShell history'

if (-not $SkipHistory) {
    try {
        Clear-History -ErrorAction SilentlyContinue
    }
    catch {
        # Current session history may be unavailable.
    }

    foreach ($profile in $profiles) {
        $historyFiles = @(
            "$($profile.LocalPath)\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt",
            "$($profile.LocalPath)\AppData\Roaming\Microsoft\PowerShell\PSReadLine\ConsoleHost_history.txt"
        )

        foreach ($historyFile in $historyFiles) {
            if (-not (Test-Path -LiteralPath $historyFile)) {
                continue
            }

            try {
                $original = @(Get-Content -LiteralPath $historyFile -ErrorAction Stop)
                $filtered = @($original | Where-Object { $_ -notmatch $HistoryRegex })

                if ($filtered.Count -ne $original.Count) {
                    Set-Content -LiteralPath $historyFile -Value $filtered -Encoding UTF8 -Force
                    Write-Removed "Velociraptor-related entries from $historyFile"
                }
            }
            catch {
                Write-WarningRecord "Could not clean history file '$historyFile': $($_.Exception.Message)"
            }
        }
    }
}
else {
    Write-Skip 'History cleanup was disabled with -SkipHistory.'
}

# ---------------------------------------------------------------------------
# 13. Verification
# ---------------------------------------------------------------------------
Write-Section 'Verification'

$remaining = @()

try {
    $remainingServices = @(Get-CimInstance Win32_Service -ErrorAction SilentlyContinue |
        Where-Object {
            $_.Name -match $MatchRegex -or
            $_.DisplayName -match $MatchRegex -or
            ([string]$_.PathName -match $MatchRegex)
        })

    foreach ($service in $remainingServices) {
        $remaining += "Service: $($service.Name)"
    }
}
catch {
    $remaining += "Could not verify services: $($_.Exception.Message)"
}

try {
    $remainingProcesses = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
        Where-Object {
            $_.ProcessId -ne $PID -and
            (
                $_.Name -match '^(?i)velociraptor.*\.exe$' -or
                ([string]$_.ExecutablePath -match '(?i)\\Velociraptor\\')
            )
        })

    foreach ($process in $remainingProcesses) {
        $remaining += "Process: $($process.Name), PID $($process.ProcessId)"
    }
}
catch {
    $remaining += "Could not verify processes: $($_.Exception.Message)"
}

$verificationPaths = @(
    "$env:ProgramFiles\Velociraptor",
    "$env:ProgramData\Velociraptor"
)

if (${env:ProgramFiles(x86)}) {
    $verificationPaths += "${env:ProgramFiles(x86)}\Velociraptor"
}

foreach ($path in $verificationPaths) {
    if (Test-Path -LiteralPath $path) {
        $remaining += "Path: $path"
    }
}

foreach ($registryPath in $knownRegistryKeys) {
    if (Test-Path -LiteralPath $registryPath) {
        $remaining += "Registry key: $registryPath"
    }
}

foreach ($root in $uninstallRoots) {
    if (-not (Test-Path -LiteralPath $root)) {
        continue
    }

    foreach ($key in @(Get-ChildItem -LiteralPath $root -ErrorAction SilentlyContinue)) {
        try {
            $displayName = [string](Get-ItemProperty -LiteralPath $key.PSPath -ErrorAction Stop).DisplayName
            if ($displayName -match $MatchRegex) {
                $remaining += "Installed-product entry: $displayName"
            }
        }
        catch {
            # Ignore unreadable keys.
        }
    }
}

Write-Host "`nRemoved items: $script:RemovedCount" -ForegroundColor Green

if ($script:Warnings.Count -gt 0) {
    Write-Host "Warnings: $($script:Warnings.Count)" -ForegroundColor Yellow
    foreach ($warningText in $script:Warnings) {
        Write-Host " - $warningText" -ForegroundColor Yellow
    }
}

if ($remaining.Count -eq 0) {
    Write-Host "`nNo active Velociraptor installation artifacts were found during final verification." `
        -ForegroundColor Green
}
else {
    Write-Host "`nRemaining items:" -ForegroundColor Red
    foreach ($item in $remaining | Sort-Object -Unique) {
        Write-Host " - $item" -ForegroundColor Red
    }

    Write-Host "`nRestart Windows, run this script again, and review any remaining warnings." `
        -ForegroundColor Yellow
    exit 2
}

Write-Host "`nRestart Windows to release any files that were locked during cleanup." `
    -ForegroundColor Cyan
Write-Host 'For a truly pristine/forensically clean machine, use Reset this PC or reimage Windows.' `
    -ForegroundColor Cyan

if ($RestartWhenDone) {
    Write-Host '[INFO] Restarting Windows in 15 seconds...' -ForegroundColor Cyan
    shutdown.exe /r /t 15 /f /c "Velociraptor cleanup completed"
}

exit 0
