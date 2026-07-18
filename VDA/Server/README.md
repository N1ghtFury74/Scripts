# Velociraptor Client Builder and Distribution Server

> Documentation for `Server_Setup.py` version `2.1.0-release-url`

`Server_Setup.py` builds and publishes customized Velociraptor client packages for Windows and Linux. It can use the latest stable GitHub release, a specific package version, a GitHub release-family tag, or a pasted GitHub release URL.

The script can:

- Retrieve Velociraptor release metadata from GitHub.
- Retrieve all release assets through GitHub API pagination.
- Resolve package versions such as `0.74.1` through their release family, such as `v0.74`.
- Preserve a numbered package-selection menu.
- Repack Windows MSI or EXE packages with `client.config.yaml`.
- Build Linux DEB or RPM packages.
- Generate a raw Linux binary bundle with a systemd client service.
- Create SHA-256 hashes and `manifest.json` metadata.
- Generate browsable HTML indexes.
- Serve the generated repository over HTTP.
- Optionally install a persistent systemd service for the artifact repository.

---

## What Changed in Version 2.1.0

The release-selection workflow now supports all of the following inputs:

```text
0.74.1
v0.74.1
0.74
v0.74
v.74
.74.1
latest
https://github.com/velocidex/velociraptor/releases#release-v0.74
https://github.com/velocidex/velociraptor/releases/tag/v0.74
```

Important behavior:

- `v0.74` is a GitHub **release-family tag**.
- A package version such as `v0.74.1` may be stored as an asset under the `v0.74` release.
- When an exact tag such as `v0.74.1` does not exist, the script automatically retries the family tag `v0.74`.
- When a patch version is requested, the script filters the family release assets to filenames matching that patch version.
- GitHub API asset pagination is used, so releases containing more than 100 assets can be fully retrieved.
- The original numbered package-selection menu is preserved.

---

## Prerequisites

### Required

| Requirement | Purpose |
|---|---|
| Linux server | Runs the builder and artifact web server |
| Python 3 | Executes `Server_Setup.py` and serves the HTTP repository |
| Velociraptor binary in `PATH` | Required for Windows repacking and Linux package creation |
| `client.config.yaml` | Embedded into generated clients |
| Internet access | Required to reach GitHub API and download release assets |
| Write access to the working directory | Required to create `dist/` |
| Root or `sudo` privileges | Required to install or remove the HTTP systemd service |

### Optional

| Requirement | Purpose |
|---|---|
| Python `requests` package | Preferred HTTP client; the script attempts to install it automatically |
| GitHub token | Increases GitHub API rate limits |
| systemd | Required only for persistent HTTP-service management |
| `curl` or `git` | Used to download the script itself |

### Confirm the Velociraptor Binary

```bash
command -v velociraptor
velociraptor version
```

The first command must return a valid executable path.

If the binary is not in `PATH`:

```bash
sudo install -m 0755 /path/to/velociraptor /usr/local/bin/velociraptor
velociraptor version
```

---

## Download the Script from GitHub

```bash
cd /opt/velociraptor

curl -fL \
  "https://raw.githubusercontent.com/N1ghtFury74/Scripts/main/VDA/Server/Server_Setup.py" \
  -o Server_Setup.py

chmod +x Server_Setup.py
```

Validate the downloaded script:

```bash
grep 'SCRIPT_VERSION' Server_Setup.py
python3 -m py_compile Server_Setup.py
python3 Server_Setup.py --help
```

Expected version:

```text
SCRIPT_VERSION = "2.1.0-release-url"
```

Run it:

```bash
python3 Server_Setup.py
```

Running with `python3` does not require executable permission, but `chmod +x` also allows:

```bash
./Server_Setup.py
```

---

# Command-Line Reference

```text
usage: Server_Setup.py [-h]
                       [--port PORT]
                       [--token TOKEN]
                       [--version RELEASE_VERSION]
                       [--no-httpd]
                       [--serve-only]
                       [--remove-httpd]
```

| Option | Meaning |
|---|---|
| `-h`, `--help` | Show command help and exit |
| `--port PORT` | HTTP port; default is `9999` |
| `--token TOKEN` | Optional GitHub token |
| `--version VALUE` | Select a package version, release tag, or pasted release URL |
| `--release VALUE` | Alias for `--version` |
| `--no-httpd` | Skip installation of the persistent systemd HTTP service |
| `--serve-only` | Serve an existing `dist/` repository without building new packages |
| `--remove-httpd` | Stop, disable, and remove `vr_artifacts_http.service` |

## Important `--no-httpd` Behavior

In the current implementation, `--no-httpd` skips the **systemd service**, but the script still starts a temporary background Python HTTP server.

Therefore:

```bash
python3 Server_Setup.py --no-httpd
```

means:

- Build the requested artifacts.
- Start a background HTTP server.
- Do **not** create `vr_artifacts_http.service`.

It does not mean “do not start any HTTP server.”

---

# Release Selection

## Interactive Menu

Run:

```bash
python3 Server_Setup.py
```

The script first asks for the target client OS:

```text
Target client OS?
1) Windows
2) Linux
3) Both (Windows + Linux)
Enter number [1-3]:
```

It then displays the latest stable release:

```text
GitHub release information
--------------------------
Latest stable release : v0.77.1
Latest release page   : https://github.com/Velocidex/velociraptor/releases/tag/v0.77.1
Latest release assets : <number>
```

The release menu is:

```text
Choose release source:
1) Use latest stable release (v0.77.1)
2) Enter a package version or paste a GitHub release URL
   Example version: 0.74.1
   Example URL: https://github.com/velocidex/velociraptor/releases#release-v0.74
Enter number [1-2]:
```

Choose `2`, then paste either a version or URL:

```text
Paste version or GitHub release URL:
```

Valid examples:

```text
0.74.1
v0.74.1
v0.74
https://github.com/velocidex/velociraptor/releases#release-v0.74
https://github.com/velocidex/velociraptor/releases/tag/v0.74
```

## Latest Stable Release from the Menu

```bash
python3 Server_Setup.py
```

Selections:

```text
Target client OS: 1, 2, or 3
Release source:   1
```

## Specific Package Version from the Menu

```bash
python3 Server_Setup.py
```

Selections:

```text
Target client OS: 1, 2, or 3
Release source:   2
Version input:    0.74.1
```

The script:

1. Normalizes the input to `v0.74.1`.
2. Attempts the exact GitHub tag.
3. If it receives `404`, retries release family `v0.74`.
4. Retrieves every family-release asset through pagination.
5. Filters assets to filenames matching `0.74.1`.
6. Filters those assets again by the selected operating system.
7. Displays a numbered list.

## Paste a GitHub Release URL from the Menu

Paste:

```text
https://github.com/velocidex/velociraptor/releases#release-v0.74
```

The `#release-v0.74` fragment is converted to release tag `v0.74`.

The normal tag URL is also supported:

```text
https://github.com/velocidex/velociraptor/releases/tag/v0.74
```

---

# Non-Interactive Release Selection

The `--version` and `--release` arguments skip the release-choice menu. They do not skip the OS, package, Linux packaging, or client-config prompts.

## Select a Package Version

```bash
python3 Server_Setup.py --version 0.74.1
```

Equivalent:

```bash
python3 Server_Setup.py --release v0.74.1
```

## Select a Release Family

```bash
python3 Server_Setup.py --version v0.74
```

This displays all compatible assets from release family `v0.74`, after OS filtering.

## Paste a GitHub Release URL on the Command Line

```bash
python3 Server_Setup.py \
  --version "https://github.com/velocidex/velociraptor/releases#release-v0.74"
```

The quotation marks are required because an unquoted `#` begins a shell comment.

Normal tag links are also valid:

```bash
python3 Server_Setup.py \
  --version "https://github.com/velocidex/velociraptor/releases/tag/v0.74"
```

## Use the Latest Release Explicitly

```bash
python3 Server_Setup.py --version latest
```

---

# GitHub Authentication

A token is optional but recommended when many release assets are retrieved.

```bash
python3 Server_Setup.py --token "$GITHUB_TOKEN"
```

With a version:

```bash
python3 Server_Setup.py \
  --token "$GITHUB_TOKEN" \
  --version 0.74.1
```

Set the environment variable without writing the token into the command itself:

```bash
read -s -p "GitHub token: " GITHUB_TOKEN
export GITHUB_TOKEN
echo
python3 Server_Setup.py --token "$GITHUB_TOKEN"
unset GITHUB_TOKEN
```

Do not commit tokens to GitHub or place them in documentation.

---

# Numbered Package Selection

After release and OS filtering, the script displays:

```text
Available assets:
1) <asset-name> : <download-url>
2) <asset-name> : <download-url>
3) <asset-name> : <download-url>

Enter the number to download:
```

Only the entered number is downloaded and processed.

The script displays the selected item again:

```text
[*] Selected GitHub asset: <asset-name>
[*] Download URL:          <download-url>
```

## Windows Asset Filtering

For Windows, an asset must:

- Contain `windows` in its filename.
- End in `.msi` or `.exe`.

Examples that may be shown:

```text
velociraptor-v0.74.1-windows-amd64.msi
velociraptor-v0.74.1-windows-amd64.exe
velociraptor-v0.74.1-windows-386.exe
```

Select the architecture required for the target endpoints.

Architecture mapping:

| Filename pattern | Canonical architecture |
|---|---|
| `amd64`, `x86_64` | `amd64` |
| `arm64`, `aarch64` | `arm64` |
| `armv7`, `armhf` | `armhf` |
| `386`, 32-bit `x86` | `386` |

## Linux Asset Filtering

For Linux, an asset must contain `linux` in its filename.

The script excludes upstream assets ending in:

```text
.deb
.rpm
.pkg
.tar.gz
.tgz
.zip
```

It selects raw Linux binaries because the script builds its own DEB or RPM packages using the supplied client configuration.

Linux results are sorted with `musl` binaries first, because static builds are generally more portable.

---

# Client Configuration

The script prompts:

```text
Enter full path to client.config.yaml:
```

Example:

```text
/etc/velociraptor/client.config.yaml
```

The path must:

- Exist.
- Be a regular file.
- Be readable by the user running the script.

The configuration is copied into the selected destination folder as:

```text
client.config.yaml
```

If a configuration already exists in the destination:

- Its SHA-256 is compared with the provided configuration.
- If both hashes match, the existing file is reused.
- If they differ, the destination copy is replaced.

Use the client configuration generated by the correct Velociraptor server. Do not use `server.config.yaml`.

---

# Windows Build Workflow

When Windows is selected, the script:

1. Filters the release assets to Windows MSI and EXE files.
2. Displays the numbered package menu.
3. Downloads the selected package into its destination folder.
4. Copies `client.config.yaml`.
5. Detects package architecture and version from the filename.
6. Executes Velociraptor repacking.
7. Generates a SHA-256 hash.
8. Creates `manifest.json`.
9. Creates the folder `index.html`.
10. Updates the root `dist/index.html`.

## Windows MSI Repacking Command

Internally:

```bash
velociraptor config repack \
  --msi <downloaded-msi> \
  <client.config.yaml> \
  <output-msi>
```

Generated filename:

```text
Windows_VelociraptorClient_<version>_<architecture>.msi
```

Example:

```text
Windows_VelociraptorClient_0.74.1_amd64.msi
```

## Windows EXE Repacking Command

Internally:

```bash
velociraptor config repack \
  --exe <downloaded-exe> \
  <client.config.yaml> \
  <output-exe>
```

Generated filename:

```text
Windows_VelociraptorClient_<version>_<architecture>.exe
```

A non-zero command return code causes:

```text
[!] Repack failed.
```

The script continues to create the manifest and HTML page, but there may be no generated repacked package in the output list.

---

# Linux Build Workflow

When Linux is selected, the script:

1. Filters and sorts Linux raw binaries.
2. Displays the numbered package menu.
3. Downloads the selected raw binary.
4. Adds executable permission.
5. Copies `client.config.yaml`.
6. Prompts for the Linux delivery format.
7. Builds the selected output.
8. Generates SHA-256 hashes.
9. Creates `manifest.json`.
10. Creates the folder and root HTML indexes.

Linux packaging menu:

```text
Linux packaging options:
  1) Build .deb (Debian/Ubuntu)
  2) Build .rpm (RHEL/CentOS/Alma)
  3) Raw binary + systemd service template (no packaging)
Choose [1/2/3]:
```

## Build a DEB Package

Internal command:

```bash
velociraptor debian client \
  --config <client.config.yaml> \
  --binary <downloaded-linux-binary> \
  --output <output.deb>
```

Generated filename:

```text
Linux_VelociraptorClient_<version>_<architecture>.deb
```

## Build an RPM Package

Internal command:

```bash
velociraptor rpm client \
  --config <client.config.yaml> \
  --binary <downloaded-linux-binary> \
  --output <output.rpm>
```

Generated filename:

```text
Linux_VelociraptorClient_<version>_<architecture>.rpm
```

## Build a Raw Linux Bundle

Option `3` creates:

```text
velociraptor_client.service
install_velociraptor_client.sh
<downloaded-linux-binary>
client.config.yaml
manifest.json
index.html
```

The generated endpoint installer performs:

```bash
sudo install -D -m 0755 "$BIN_SRC" /usr/local/bin/velociraptor
sudo install -D -m 0644 "$CFG_SRC" /etc/velociraptor/client.config.yaml
sudo install -D -m 0644 "$SVC_SRC" /etc/systemd/system/velociraptor_client.service
sudo systemctl daemon-reload
sudo systemctl enable --now velociraptor_client
```

The generated client systemd service runs:

```text
/usr/local/bin/velociraptor \
  --config /etc/velociraptor/client.config.yaml \
  client -v
```

Service behavior:

```text
Restart=always
RestartSec=30
LimitNOFILE=20000
```

---

# Running Common Use Cases

## Use Case 1: Windows, Latest Stable Release

```bash
cd /opt/velociraptor
python3 Server_Setup.py
```

Menu selections:

```text
Target client OS: 1
Release source:   1
```

Then:

1. Enter the full client-config path.
2. Choose the required numbered Windows MSI or EXE asset.

## Use Case 2: Windows Package Version 0.74.1

```bash
python3 Server_Setup.py --version 0.74.1
```

Then choose:

```text
Target client OS: 1
```

The script resolves `v0.74.1` through family release `v0.74` when necessary.

## Use Case 3: Windows from a Pasted Release URL

```bash
python3 Server_Setup.py \
  --version "https://github.com/velocidex/velociraptor/releases#release-v0.74"
```

Then choose:

```text
Target client OS: 1
```

This retrieves the entire `v0.74` release-family asset list and presents compatible Windows packages.

## Use Case 4: Linux DEB from the Latest Release

```bash
python3 Server_Setup.py
```

Selections:

```text
Target client OS: 2
Release source:   1
Linux package:    1
```

## Use Case 5: Linux RPM for a Specific Version

```bash
python3 Server_Setup.py --version 0.74.1
```

Selections:

```text
Target client OS: 2
Linux package:    2
```

## Use Case 6: Raw Linux Binary and Client Service

```bash
python3 Server_Setup.py --version v0.74
```

Selections:

```text
Target client OS: 2
Linux package:    3
```

## Use Case 7: Build Windows and Linux

```bash
python3 Server_Setup.py --version 0.74.1
```

Selections:

```text
Target client OS: 3
```

The script runs the Windows flow first and Linux flow second. A separate numbered package choice is requested for each operating system.

## Use Case 8: Custom HTTP Port

```bash
python3 Server_Setup.py --port 8080
```

Browse:

```text
http://<server-ip>:8080/
```

Ensure the port is allowed by the host firewall and network security controls.

## Use Case 9: Skip Persistent systemd Installation

```bash
python3 Server_Setup.py --no-httpd
```

This still starts a temporary background HTTP server but does not create:

```text
/etc/systemd/system/vr_artifacts_http.service
```

## Use Case 10: Serve an Existing Repository

```bash
python3 Server_Setup.py --serve-only
```

This:

- Rebuilds the root HTML index.
- Starts a temporary background HTTP server.
- Installs and starts the systemd service unless `--no-httpd` is also supplied.

Temporary server only:

```bash
python3 Server_Setup.py --serve-only --no-httpd
```

## Use Case 11: Remove the Persistent HTTP Service

```bash
sudo python3 Server_Setup.py --remove-httpd
```

This runs:

```bash
systemctl disable --now vr_artifacts_http.service
```

It then removes:

```text
/etc/systemd/system/vr_artifacts_http.service
```

and reloads systemd.

It does not remove:

- `dist/`
- Generated client artifacts
- Temporary background HTTP processes
- `dist/http.out`
- `dist/http.err`
- `dist/http.pid`

---

# Directory Structure

The exact folder name is based on the **selected GitHub release tag** and detected architecture.

When package `0.74.1` is resolved through family release `v0.74`, the folder is:

```text
dist/windows/v0.74-amd64/
```

The generated package filename can still contain package version `0.74.1`.

Example:

```text
dist/
├── index.html
├── http.out
├── http.err
├── http.pid
├── linux/
│   └── v0.74-amd64/
│       ├── client.config.yaml
│       ├── velociraptor-v0.74.1-linux-amd64
│       ├── Linux_VelociraptorClient_0.74.1_amd64.deb
│       ├── manifest.json
│       └── index.html
└── windows/
    └── v0.74-amd64/
        ├── velociraptor-v0.74.1-windows-amd64.msi
        ├── Windows_VelociraptorClient_0.74.1_amd64.msi
        ├── client.config.yaml
        ├── manifest.json
        └── index.html
```

Raw Linux mode instead contains:

```text
dist/linux/v0.74-amd64/
├── client.config.yaml
├── velociraptor-v0.74.1-linux-amd64
├── velociraptor_client.service
├── install_velociraptor_client.sh
├── manifest.json
└── index.html
```

Multiple release and architecture directories can coexist.

---

# Manifest Format

Each leaf directory contains `manifest.json`.

Example:

```json
{
  "arch": "amd64",
  "downloaded": {
    "filename": "velociraptor-v0.74.1-windows-amd64.msi",
    "sha256": "<sha256>",
    "url": "https://github.com/..."
  },
  "generated_at": 1784340000,
  "os": "Windows",
  "outputs": [
    {
      "filename": "Windows_VelociraptorClient_0.74.1_amd64.msi",
      "sha256": "<sha256>",
      "type": "windows_repacked"
    }
  ],
  "tag": "v0.74",
  "version": "0.74.1"
}
```

Fields:

| Field | Meaning |
|---|---|
| `tag` | Selected GitHub release or release-family tag |
| `os` | `Windows` or `Linux` |
| `arch` | Detected canonical architecture |
| `version` | Version detected from the selected filename |
| `generated_at` | Unix timestamp |
| `downloaded` | Original GitHub asset details |
| `outputs` | Generated packages or raw-delivery files |

---

# Web Repository

The root page is:

```text
dist/index.html
```

Leaf pages list:

- Generated files.
- SHA-256 hashes.
- Download links.
- The hosted client configuration.

Default URL:

```text
http://<server-ip>:9999/
```

Example Windows leaf URL:

```text
http://<server-ip>:9999/windows/v0.74-amd64/
```

Example manifest URL:

```text
http://<server-ip>:9999/windows/v0.74-amd64/manifest.json
```

---

# HTTP Process and systemd Service

## Temporary Background Server

The script starts:

```bash
python3 -m http.server <port>
```

from the absolute `dist/` directory.

Files:

```text
dist/http.pid
dist/http.out
dist/http.err
```

Check it:

```bash
cat dist/http.pid
ps -fp "$(cat dist/http.pid)"
tail -f dist/http.out
tail -f dist/http.err
```

Stop it:

```bash
kill "$(cat dist/http.pid)"
rm -f dist/http.pid
```

## Persistent Service

Service name:

```text
vr_artifacts_http.service
```

Service file:

```text
/etc/systemd/system/vr_artifacts_http.service
```

Check it:

```bash
systemctl status vr_artifacts_http.service --no-pager
journalctl -u vr_artifacts_http.service -n 100 --no-pager
```

Restart it:

```bash
sudo systemctl restart vr_artifacts_http.service
```

Enable it:

```bash
sudo systemctl enable --now vr_artifacts_http.service
```

Disable it:

```bash
sudo systemctl disable --now vr_artifacts_http.service
```

---

# Important Current HTTP Limitation

The current code starts the temporary background HTTP server **before** attempting to start the persistent systemd service on the same port.

This can cause:

```text
OSError: [Errno 98] Address already in use
```

or a failed systemd service.

Check:

```bash
ss -ltnp | grep ':9999'
systemctl status vr_artifacts_http.service --no-pager
cat dist/http.pid
```

Workaround:

```bash
kill "$(cat dist/http.pid)"
rm -f dist/http.pid
sudo systemctl restart vr_artifacts_http.service
```

Then verify:

```bash
systemctl is-active vr_artifacts_http.service
curl -I http://127.0.0.1:9999/
```

---

# Code Review Reference

## Constants

| Constant | Behavior |
|---|---|
| `SCRIPT_VERSION` | Displays the script build identifier |
| `GITHUB_REPO` | Official Velociraptor repository |
| `API_LATEST` | Retrieves the latest stable release |
| `API_RELEASE_BY_TAG` | Retrieves a specific release tag |
| `API_RELEASE_ASSETS` | Retrieves paginated assets for a release ID |
| `HTML_RELEASES` | HTML fallback base URL |
| `DEFAULT_PORT` | Default artifact-server port, `9999` |
| `DIST_ROOT` | Relative output path, `dist` |
| `PID_FILENAME` | Temporary HTTP PID file |
| `HTTPD_UNIT` | Persistent systemd unit name |
| `NON_REPACKABLE_HINTS` | Linux upstream package types excluded from raw-binary selection |
| `OS_PATTERNS` | Filename OS detection |
| `ARCH_PATTERNS` | Filename architecture normalization |
| `VERSION_RE` | Extracts package version from filenames |

## Dependency and Utility Functions

| Function | Behavior |
|---|---|
| `ensure_requests()` | Imports `requests`, attempts a quiet pip installation, otherwise uses urllib |
| `ensure_velociraptor_on_path()` | Finds and executes `velociraptor version`; exits when unavailable |
| `sha256_file()` | Hashes files in 1 MiB chunks |
| `request_json()` | Sends GitHub requests using `requests` or urllib |

## Release Functions

| Function | Behavior |
|---|---|
| `normalize_release_tag()` | Accepts versions and pasted release URLs; normalizes common variants |
| `release_family_tag()` | Converts a three-part tag such as `v0.74.1` to `v0.74` |
| `filter_assets_for_requested_version()` | Filters a family release to the requested patch-version filenames |
| `_standardize_release_assets()` | Converts GitHub API records to the internal asset format |
| `list_all_release_assets_api()` | Fetches release assets in pages of 100 until complete |
| `get_release_assets_api()` | Retrieves latest or tag metadata and all assets |
| `get_release_assets_scrape()` | Attempts HTML fallback when API access fails |
| `retrieve_release()` | Tries exact tag, then release family, then HTML fallback |
| `select_release()` | Displays latest release and processes menu or CLI input |

## Package Functions

| Function | Behavior |
|---|---|
| `filter_assets_for_os()` | Keeps Windows MSI/EXE or Linux raw binaries |
| `pick_from_numbered()` | Displays numbered assets and validates the operator choice |
| `download()` | Downloads in 512 KiB chunks or reuses any existing non-empty file |
| `detect_os_arch_version()` | Detects OS, architecture, and package version from filename |
| `shlex_quote()` | Prints readable shell-safe command arguments |
| `slugify()` | Converts text to a filename-safe value; currently not used elsewhere |

## Windows and Linux Functions

| Function | Behavior |
|---|---|
| `repack_windows()` | Runs Velociraptor MSI or EXE repacking |
| `build_linux_package()` | Runs Velociraptor DEB or RPM client building |
| `linux_service_template()` | Generates the Linux endpoint systemd client unit |
| `write_text()` | Writes UTF-8 text and creates parent directories |
| `linux_installer_script()` | Generates the raw Linux deployment script |

## Repository and Server Functions

| Function | Behavior |
|---|---|
| `write_manifest()` | Writes sorted, indented JSON metadata |
| `write_leaf_index()` | Creates a package-directory HTML page |
| `write_root_index()` | Discovers existing Linux and Windows folders and creates the root page |
| `start_http_server()` | Starts a detached Python HTTP server and writes PID/log files |
| `install_http_service()` | Writes and enables the persistent HTTP systemd service |
| `uninstall_http_service()` | Disables, removes, and reloads the HTTP service |
| `ensure_cfg_copied()` | Reuses or replaces hosted `client.config.yaml` based on SHA-256 |
| `add_row()` | Adds an output file and SHA-256 to the HTML list |
| `windows_flow()` | Coordinates Windows selection, download, repack, manifest, and HTML |
| `linux_flow()` | Coordinates Linux selection, package mode, manifest, and HTML |
| `main()` | Parses arguments and controls the complete workflow |

---

# Complete Execution Order

A normal build follows this order:

1. Print script version.
2. Parse command-line arguments.
3. Create `dist/`.
4. Process `--remove-httpd` or `--serve-only`, when selected.
5. Verify that `velociraptor` exists in `PATH`.
6. Ask for Windows, Linux, or both.
7. Retrieve the latest GitHub release for display.
8. Process the CLI release value or release menu.
9. Normalize a pasted URL or version.
10. Attempt exact tag lookup.
11. Retry the release family when required.
12. Retrieve all paginated GitHub assets.
13. Filter by a requested patch version when applicable.
14. Display release information and asset counts.
15. Ask for `client.config.yaml`.
16. Run Windows and/or Linux flows.
17. Generate manifests and leaf indexes.
18. Generate the root index.
19. Start a temporary HTTP server.
20. Install the persistent systemd HTTP service unless `--no-httpd`.
21. Print the browse URL.

---

# Idempotency and Repeated Runs

The script is partially idempotent:

- Existing output directories are reused.
- Existing non-empty downloaded assets are reused without downloading again.
- Existing client configuration is reused when SHA-256 matches.
- Generated files are overwritten when the same output filename is built again.
- Existing versions and architectures remain available in separate folders.

Important caveats:

- A cached file is reused based only on non-zero size; its GitHub hash is not revalidated.
- A previously corrupted non-empty download may therefore be reused.
- Delete the cached source file before retrying a suspected corrupt download.
- Every normal run attempts to start another background HTTP process.
- Repeated runs can produce port conflicts or stale `http.pid` files.

Remove a cached asset before rebuilding:

```bash
rm -f dist/windows/v0.74-amd64/<source-package>
```

Inspect current listeners:

```bash
ss -ltnp | grep ':9999'
```

---

# Troubleshooting

## The Old Version Prompt Still Appears

Old prompt:

```text
Enter version (example: 0.77.1 or v0.77.1):
```

The updated prompt is:

```text
Paste version or GitHub release URL:
```

Check the file:

```bash
grep 'SCRIPT_VERSION' Server_Setup.py
grep 'Paste version or GitHub release URL' Server_Setup.py
```

Redownload:

```bash
curl -fL \
  "https://raw.githubusercontent.com/N1ghtFury74/Scripts/main/VDA/Server/Server_Setup.py" \
  -o Server_Setup.py
```

## Python Cannot Find the Script

Error:

```text
python3: can't open file '...': No such file or directory
```

Check:

```bash
pwd
ls -l
```

Run the actual filename:

```bash
python3 Server_Setup.py
```

Do not run `Server_Setup_Updated.py` unless that file exists.

## `--version: command not found`

This occurs when the first command failed or the line continuation was broken.

Correct one-line command:

```bash
python3 Server_Setup.py --version 0.74.1
```

Correct multiline command:

```bash
python3 Server_Setup.py \
  --version 0.74.1
```

The backslash must be the last character on the line.

## GitHub Returns 404 for `v0.74.1`

The script should retry `v0.74` automatically.

Confirm updated code:

```bash
grep -n 'release_family_tag' Server_Setup.py
grep -n 'filter_assets_for_requested_version' Server_Setup.py
```

Direct family input:

```bash
python3 Server_Setup.py --version v0.74
```

## Pasted URL Is Rejected

Use the updated script and quote command-line URLs containing `#`:

```bash
python3 Server_Setup.py \
  --version "https://github.com/velocidex/velociraptor/releases#release-v0.74"
```

In the interactive prompt, paste the URL without additional quotes.

## GitHub API Rate Limit

Use a token:

```bash
python3 Server_Setup.py --token "$GITHUB_TOKEN"
```

Check API access:

```bash
curl -I https://api.github.com/repos/Velocidex/velociraptor/releases/latest
```

## No Suitable Windows Assets

The selected release or patch-version filter returned no filenames containing `windows` and ending in `.msi` or `.exe`.

Try the family tag to see all family assets:

```bash
python3 Server_Setup.py --version v0.74
```

## No Suitable Linux Assets

The script only shows Linux raw binaries and intentionally excludes packaged formats.

Try another release or inspect the GitHub release page.

## Velociraptor Is Not in PATH

Error:

```text
ERROR: 'velociraptor' not found in PATH.
```

Fix:

```bash
sudo install -m 0755 /path/to/velociraptor /usr/local/bin/velociraptor
velociraptor version
```

## Repack or Package Build Fails

Run the displayed Velociraptor command manually and inspect its complete output.

Confirm:

```bash
velociraptor version
test -r /path/to/client.config.yaml
df -h
```

## Port 9999 Is Already in Use

```bash
ss -ltnp | grep ':9999'
```

Stop the temporary process:

```bash
kill "$(cat dist/http.pid)"
rm -f dist/http.pid
```

Or use another port:

```bash
python3 Server_Setup.py --port 10000
```

## systemd Service Fails

```bash
systemctl status vr_artifacts_http.service --no-pager
journalctl -u vr_artifacts_http.service -n 100 --no-pager
```

Check the service file:

```bash
systemctl cat vr_artifacts_http.service
```

---

# Security Considerations

The generated repository uses Python’s basic HTTP server:

- No TLS.
- No authentication.
- No authorization.
- No directory-access controls.
- The hosted `client.config.yaml` is downloadable.

Use this only on a controlled management network, VPN, private subnet, or behind a secured reverse proxy.

Recommended controls:

- Restrict inbound access to trusted administration and endpoint networks.
- Do not expose port `9999` directly to the public internet.
- Place TLS and authentication in front of the repository when required.
- Review `client.config.yaml` before publishing.
- Validate generated SHA-256 hashes.
- Protect the server filesystem and GitHub token.
- Remove old artifacts that should no longer be deployed.

Example UFW restriction:

```bash
sudo ufw allow from <trusted-subnet> to any port 9999 proto tcp
```

---

# Known Limitations

1. `--version` skips only the release menu; the OS, asset, configuration, and packaging prompts remain interactive.
2. The family fallback currently converts only three-part versions, such as `v0.74.1`, to two-part families, such as `v0.74`.
3. HTML scraping is a fallback and may not discover all dynamically rendered assets.
4. Full pagination depends on successful GitHub API access.
5. A cached non-empty file is reused without verifying it against the current GitHub asset.
6. Unknown architectures default to `amd64`.
7. `--no-httpd` skips systemd but still starts a temporary server.
8. `--remove-httpd` does not stop temporary servers or remove generated artifacts.
9. The script does not configure the Linux firewall.
10. The script does not provide HTTPS or repository authentication.
11. systemd command return codes are not enforced by `check=True`; inspect service status after execution.
12. A temporary server and systemd service can compete for the same port.
13. The generated root index lists directories but does not mark a preferred or latest version.
14. The script creates client deployment packages; it does not upgrade the running Velociraptor server binary.

---

# Verification Checklist

After a build:

```bash
find dist -maxdepth 3 -type f -printf '%p\n' | sort
```

Validate JSON:

```bash
python3 -m json.tool dist/windows/<folder>/manifest.json
```

Check SHA-256:

```bash
sha256sum dist/windows/<folder>/*
```

Check the HTTP repository:

```bash
curl -I http://127.0.0.1:9999/
curl http://127.0.0.1:9999/
```

Check service:

```bash
systemctl is-enabled vr_artifacts_http.service
systemctl is-active vr_artifacts_http.service
```

Check logs:

```bash
tail -n 100 dist/http.err
journalctl -u vr_artifacts_http.service -n 100 --no-pager
```

---

# Recommended Git Commit

```text
docs(server-builder): document release selection and distribution workflows

Document interactive and CLI release selection, pasted GitHub URLs, release-family resolution, paginated assets, Windows/Linux build flows, HTTP service management, outputs, security, and troubleshooting.
```

Commands:

```bash
git add VDA/Server/Server.md
git commit -m "docs(server-builder): document release selection and distribution workflows"
git push origin main
```
