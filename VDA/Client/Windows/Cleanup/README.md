# VDA Client Cleanup

Enterprise-ready PowerShell cleanup utility for completely removing Velociraptor client installations and common local remnants from Windows endpoints.

Designed for unattended deployment through **Intune, SCCM, Group Policy, RMM platforms, or remote administration tools**.

---

## What It Removes

The script detects and removes Velociraptor-related:

- Running processes and Windows services
- Registered MSI installations
- Program files from both 32-bit and 64-bit locations
- Configuration files, installers, temporary files, and cached artifacts
- Registry keys and startup entries
- Scheduled tasks and firewall rules
- Microsoft Defender exclusions
- Matching certificates
- Custom event channels and event-source registrations
- Shortcuts, Prefetch files, and Windows Error Reporting artifacts
- Velociraptor-related PowerShell history entries

It also performs a final verification to identify any remaining active artifacts.

---

## Key Features

- **Fully unattended** — no confirmation or user input required
- **Self-elevation** — requests administrator privileges when launched interactively
- **Large-scale deployment ready**
- **Backward compatible** with previous `-Force` and `-IncludeHistory` commands
- **Resilient cleanup** with retries, ownership recovery, and permission repair
- **Optional automatic restart**
- **Clear exit codes** for deployment and compliance reporting
- **Windows PowerShell 5.1 compatible**

---

## Requirements

- Windows PowerShell 5.1 or later
- Administrator or `SYSTEM` privileges
- The script must be saved and executed as a `.ps1` file

Do not paste the complete script directly into an interactive PowerShell console.

---

## Recommended Execution

```powershell
powershell.exe -NoLogo -NoProfile -NonInteractive `
  -ExecutionPolicy Bypass `
  -File ".\VDA_Client_Cleanup.ps1"
```

### Cleanup and Restart

```powershell
powershell.exe -NoLogo -NoProfile -NonInteractive `
  -ExecutionPolicy Bypass `
  -File ".\VDA_Client_Cleanup.ps1" `
  -RestartWhenDone
```

---

## Optional Parameters

| Parameter | Function |
|---|---|
| `-RestartWhenDone` | Restarts Windows 15 seconds after successful cleanup |
| `-SkipHistory` | Keeps Velociraptor-related PowerShell history entries |
| `-SkipCertificateRemoval` | Keeps certificates matching Velociraptor |
| `-Force` | Retained for compatibility; cleanup is already unattended |
| `-IncludeHistory` | Retained for compatibility; history cleanup is enabled by default |

Example:

```powershell
powershell.exe -NoProfile -NonInteractive `
  -ExecutionPolicy Bypass `
  -File ".\VDA_Client_Cleanup.ps1" `
  -SkipCertificateRemoval `
  -RestartWhenDone
```

---

## Exit Codes

| Code | Meaning |
|---:|---|
| `0` | Cleanup completed and no active Velociraptor artifacts were detected |
| `2` | Cleanup completed, but one or more artifacts remain |
| `5` | Automatic administrator elevation failed |

Deployment tools can use these codes for compliance and remediation reporting.

---

## Validation

Before deployment:

```powershell
$tokens = $null
$errors = $null

[System.Management.Automation.Language.Parser]::ParseFile(
    (Resolve-Path ".\VDA_Client_Cleanup.ps1"),
    [ref]$tokens,
    [ref]$errors
) | Out-Null

$errors
```

No output means the script contains no PowerShell parser errors.

---

## Important Notes

- A restart may still be required to release files locked by Windows or security software.
- The script removes operational components and common remnants; it does not erase forensic records from Amcache, SRUM, USN Journal, restore points, backups, or unrelated Windows event logs.
- For a truly pristine endpoint, reset or reimage Windows.

---

## Suggested Commit

```text
feat(cleanup): add unattended enterprise Velociraptor removal

Provide scalable removal of Velociraptor services, packages, files, registry data, security exclusions, certificates, history, and related endpoint artifacts with verification and optional restart.
```
