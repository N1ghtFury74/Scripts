#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Velociraptor Client Builder and Distribution Server
==================================================

This script automates the creation and distribution of Velociraptor clients for incident response
and threat hunting operations. It serves as the central hub for managing client deployments across
Windows and Linux environments.

WHAT THIS SCRIPT DOES:
- Downloads the latest Velociraptor releases from GitHub
- Repacks Windows installers (MSI/EXE) with custom client configurations
- Builds Linux packages (.deb/.rpm) or creates raw binaries with systemd services
- Creates a structured web-based artifact repository
- Hosts an HTTP server for client downloads
- Generates manifest files for automated client discovery

DIRECTORY STRUCTURE CREATED:
      dist/                                    # Root distribution directory
        index.html                            # Main landing page
        linux/                                # Linux client artifacts
          v0.74.1-amd64/                     # Version-specific folder
            client.config.yaml               # Client configuration
            velociraptor-linux-amd64         # Raw binary
            velociraptor_client.service      # Systemd service file
            install_velociraptor_client.sh   # Installation script
            manifest.json                    # Metadata for automation
            index.html                       # Folder-specific page
        windows/                             # Windows client artifacts
          v0.74.1-amd64/                    # Version-specific folder
            Windows_VelociraptorClient_0.74.1_amd64.msi  # Repacked installer
            client.config.yaml              # Client configuration
            manifest.json                   # Metadata for automation
            index.html                      # Folder-specific page

KEY FEATURES:
- Persistent operation: Creates systemd service for automatic startup
- Idempotent: Can be run multiple times without breaking existing deployments
- Version management: Maintains multiple versions simultaneously
- Cross-platform: Handles both Windows and Linux client generation
- Web interface: Provides browsable artifact repository
"""

# Import required Python libraries for various operations
import argparse          # Command-line argument parsing
import hashlib          # SHA256 hash generation for file integrity
import html             # HTML escaping for web page generation
import json             # JSON handling for manifest files
import platform         # Operating system detection
import re               # Regular expressions for pattern matching
import shutil           # File operations and system command detection
import subprocess       # Running external commands (velociraptor, systemctl, etc.)
import sys              # System-specific parameters and functions
import time             # Time operations for timestamps
from pathlib import Path                    # Modern path handling
from typing import Dict, List, Optional, Tuple  # Type hints for better code clarity

# ==================== CONFIGURATION CONSTANTS ====================
# These constants define the behavior and settings of the script

# GitHub repository information for downloading Velociraptor releases
GITHUB_REPO = "Velocidex/velociraptor"                                    # Official Velociraptor repository
API_LATEST = f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest"  # GitHub API endpoint for latest release
HTML_RELEASES = f"https://github.com/{GITHUB_REPO}/releases"             # Fallback HTML page for releases

# Server configuration
DEFAULT_PORT = 9999                    # Default HTTP server port for serving artifacts
DIST_ROOT = Path("dist")              # Root directory where all artifacts are stored
PID_FILENAME = "http.pid"             # File to store HTTP server process ID
HTTPD_UNIT = "vr_artifacts_http.service"  # Systemd service name for persistent HTTP server

# File extensions that cannot be repacked (already packaged formats)
NON_REPACKABLE_HINTS = (".deb", ".rpm", ".pkg", ".tar.gz", ".tgz", ".zip")

# Regular expressions for identifying operating systems in filenames
OS_PATTERNS = {
    "windows": re.compile(r"windows", re.I),  # Case-insensitive match for "windows"
    "linux": re.compile(r"linux", re.I)       # Case-insensitive match for "linux"
}

# Architecture detection patterns - maps various architecture names to canonical forms
ARCH_PATTERNS = [
    (re.compile(r"(amd64|x86_64)", re.I), "amd64"),      # 64-bit x86 architectures
    (re.compile(r"(arm64|aarch64)", re.I), "arm64"),     # 64-bit ARM architectures
    (re.compile(r"armv?7|armhf", re.I), "armhf"),        # 32-bit ARM architectures
    (re.compile(r"386|x86(?!_64)", re.I), "386"),        # 32-bit x86 architectures
]

# Regular expression to extract version numbers from filenames
VERSION_RE = re.compile(r"v(\d+(?:\.\d+)*(?:[-._][a-z0-9]+)?)", re.I)

# ==================== DEPENDENCY MANAGEMENT ====================
# This section handles the optional 'requests' library installation

def ensure_requests() -> bool:
    """
    Attempts to import the 'requests' library, installing it if not found.

    The requests library provides better HTTP handling than urllib, but we can
    fall back to urllib if requests is not available or cannot be installed.

    Returns:
        bool: True if requests is available, False if we need to use urllib fallback
    """
    try:
        import requests  # noqa: F401  # Try to import requests library
        return True
    except Exception:
        # If requests is not installed, try to install it automatically
        print("[*] 'requests' not found. Attempting to install it now...")
        try:
            # Use pip to install requests quietly
            subprocess.run([sys.executable, "-m", "pip", "install", "--quiet", "requests"], check=True)
            import requests  # noqa: F401  # Try importing again after installation
            print("[*] Installed 'requests'.")
            return True
        except Exception as e:
            # If installation fails, we'll use urllib as fallback
            print(f"[!] Could not install 'requests' automatically ({e}). Falling back to urllib.")
            return False

# Global flag indicating whether we have the requests library available
HAVE_REQUESTS = ensure_requests()

# ==================== UTILITY FUNCTIONS ====================

def ensure_velociraptor_on_path() -> str:
    """
    Verifies that the 'velociraptor' binary is available in the system PATH.

    This is essential because we need the velociraptor binary to:
    - Repack Windows installers with custom configurations
    - Build Linux packages (.deb/.rpm)
    - Generate client configurations

    Returns:
        str: Path to the velociraptor executable

    Exits:
        If velociraptor is not found or not executable
    """
    # Search for velociraptor in system PATH
    exe = shutil.which("velociraptor")
    if not exe:
        sys.exit("ERROR: 'velociraptor' not found in PATH. Install it or add to PATH.")

    # Test that we can actually execute the velociraptor binary
    try:
        subprocess.run([exe, "version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    except Exception as e:
        sys.exit(f"ERROR: Could not execute '{exe}': {e}")

    return exe

def sha256_file(p: Path) -> str:
    """
    Calculates the SHA256 hash of a file for integrity verification.

    This is crucial for incident response to ensure downloaded files haven't been
    tampered with during transit. The hash is also used in manifest files for
    client verification.

    Args:
        p (Path): Path to the file to hash

    Returns:
        str: Hexadecimal SHA256 hash of the file
    """
    h = hashlib.sha256()  # Create SHA256 hash object
    with p.open("rb") as f:  # Open file in binary mode
        # Read file in 1MB chunks to handle large files efficiently
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)  # Update hash with each chunk
    return h.hexdigest()  # Return hexadecimal representation of hash

def request_json(url: str, token: Optional[str] = None) -> Dict:
    """
    Makes an HTTP GET request and returns JSON response.

    This function handles GitHub API requests with optional authentication.
    It uses the 'requests' library if available, otherwise falls back to urllib.

    Args:
        url (str): URL to request
        token (Optional[str]): GitHub API token for authenticated requests

    Returns:
        Dict: Parsed JSON response

    Raises:
        Various HTTP and JSON parsing exceptions
    """
    # Set up headers for GitHub API requests
    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"  # Add authentication if token provided

    if HAVE_REQUESTS:
        # Use requests library if available (preferred method)
        import requests
        r = requests.get(url, headers=headers, timeout=30)
        r.raise_for_status()  # Raise exception for HTTP error codes
        return r.json()
    else:
        # Fall back to urllib if requests is not available
        import urllib.request, json as _json
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=30) as r:
            return _json.loads(r.read().decode("utf-8"))

def get_latest_assets_api(token: Optional[str]) -> Tuple[str, List[Dict]]:
    """
    Retrieves the latest Velociraptor release information using GitHub API.

    This is the preferred method as it provides structured data including file sizes
    and content types. Used for downloading the latest Velociraptor binaries.

    Args:
        token (Optional[str]): GitHub API token for higher rate limits

    Returns:
        Tuple[str, List[Dict]]: (release_tag, list_of_asset_dictionaries)
    """
    # Get latest release data from GitHub API
    data = request_json(API_LATEST, token=token)
    tag = data.get("tag_name") or "latest"  # Extract version tag (e.g., "v0.74.1")
    assets = data.get("assets", []) or []   # Get list of downloadable files

    # Convert GitHub API response to our standardized format
    out = []
    for a in assets:
        out.append({
            "name": a.get("name", ""),                      # Filename (e.g., "velociraptor-v0.74.1-windows-amd64.exe")
            "url": a.get("browser_download_url", ""),       # Direct download URL
            "content_type": a.get("content_type", ""),      # MIME type
            "size": a.get("size", 0),                       # File size in bytes
        })
    return tag, out

def get_latest_assets_scrape() -> Tuple[str, List[Dict]]:
    """
    Fallback method to get release information by scraping GitHub releases page.

    Used when GitHub API is unavailable or rate-limited. Less reliable than API
    but provides basic functionality for downloading releases.

    Returns:
        Tuple[str, List[Dict]]: (release_tag, list_of_asset_dictionaries)
    """
    import urllib.request

    # Download the GitHub releases page HTML
    html_text = urllib.request.urlopen(HTML_RELEASES, timeout=30).read().decode("utf-8", "ignore")

    # Extract the latest release tag from HTML using regex
    tag_match = re.search(r'/releases/tag/([^"\'<> ]+)', html_text, re.I)
    tag = tag_match.group(1) if tag_match else "latest"

    # Find all download links for this release
    assets = []
    for m in re.finditer(rf'/download/{re.escape(tag)}/([^"\'<> ]+)', html_text, re.I):
        name = html.unescape(m.group(1))  # Decode HTML entities in filename
        url = f"https://github.com/{GITHUB_REPO}/releases/download/{tag}/{name}"
        assets.append({
            "name": name,
            "url": url,
            "content_type": "",  # Not available from HTML scraping
            "size": 0           # Not available from HTML scraping
        })
    return tag, assets

def filter_assets_for_os(assets: List[Dict], os_key: str) -> List[Dict]:
    """
    Filters GitHub release assets to find files suitable for a specific operating system.

    This function is critical for incident response as it automatically identifies
    the correct Velociraptor binaries for the target OS, reducing manual selection
    errors during time-sensitive operations.

    Args:
        assets (List[Dict]): List of asset dictionaries from GitHub API
        os_key (str): Either "windows" or "linux"

    Returns:
        List[Dict]: Filtered list of assets suitable for the specified OS
    """
    pat = OS_PATTERNS[os_key]  # Get regex pattern for the OS
    filtered = []

    for a in assets:
        name = a["name"]
        # Skip assets that don't match the OS pattern
        if not pat.search(name):
            continue

        low = name.lower()  # Convert to lowercase for case-insensitive matching

        if os_key == "windows":
            # For Windows, we only want MSI or EXE files (installable formats)
            if low.endswith(".msi") or low.endswith(".exe"):
                filtered.append(a)
            continue

        if os_key == "linux":
            # For Linux, skip pre-packaged formats as we'll create our own packages
            if any(low.endswith(ext) for ext in NON_REPACKABLE_HINTS):
                continue
            # Accept raw binaries that we can repackage
            filtered.append(a)

    # For Linux, prefer musl builds (static linking) over glibc for better compatibility
    if os_key == "linux":
        filtered.sort(key=lambda x: (0 if "musl" in x["name"].lower() else 1, x["name"]))

    return filtered

def pick_from_numbered(items: List[Dict]) -> Dict:
    """
    Presents a numbered list of assets to the user for selection.

    During incident response, this allows operators to quickly select the
    appropriate Velociraptor binary for their target architecture.

    Args:
        items (List[Dict]): List of asset dictionaries to choose from

    Returns:
        Dict: The selected asset dictionary
    """
    print("\nAvailable assets:")
    # Display numbered list of available assets
    for i, a in enumerate(items, 1):
        print(f"{i}) {a['name']} : {a['url']}")

    # Loop until user provides valid input
    while True:
        choice = input("\nEnter the number to download: ").strip()
        if choice.isdigit() and 1 <= int(choice) <= len(items):
            return items[int(choice) - 1]  # Return selected asset (convert to 0-based index)
        print("Invalid choice, try again.")

def download(asset: Dict, outdir: Path) -> Path:
    """
    Downloads a Velociraptor asset from GitHub to the specified directory.

    This function handles the actual file download with caching to avoid
    re-downloading existing files. Critical for building the artifact repository.

    Args:
        asset (Dict): Asset dictionary containing name and URL
        outdir (Path): Directory to save the downloaded file

    Returns:
        Path: Path to the downloaded file
    """
    # Ensure output directory exists
    outdir.mkdir(parents=True, exist_ok=True)
    dst = outdir / asset["name"]  # Destination file path

    # Check if file already exists and has content (caching)
    if dst.exists() and dst.stat().st_size > 0:
        print(f"[*] Reusing cached file: {dst}")
        return dst

    # Download using requests library if available (preferred)
    if HAVE_REQUESTS:
        import requests
        with requests.get(asset["url"], stream=True, timeout=120) as r:
            r.raise_for_status()  # Raise exception for HTTP errors
            with dst.open("wb") as f:
                # Download in chunks to handle large files efficiently
                for chunk in r.iter_content(chunk_size=1024 * 512):  # 512KB chunks
                    if chunk:
                        f.write(chunk)
    else:
        # Fallback to urllib if requests is not available
        import urllib.request
        with urllib.request.urlopen(asset["url"], timeout=120) as r, dst.open("wb") as f:
            shutil.copyfileobj(r, f)  # Copy data from URL to file

    return dst

def detect_os_arch_version(name: str, os_key: str, tag: str) -> Tuple[str, str, str]:
    os_pretty = {"windows": "Windows", "linux": "Linux"}[os_key]
    arch = "amd64"
    for rx, canonical in ARCH_PATTERNS:
        if rx.search(name):
            arch = canonical
            break
    m = VERSION_RE.search(name)
    ver = m.group(1) if m else (tag.lstrip("v") if tag else "latest")
    return os_pretty, arch, ver

def shlex_quote(s: str) -> str:
    if platform.system().lower().startswith("win"):
        return f'"{s}"' if " " in s else s
    import shlex
    return shlex.quote(s)

def slugify(s: str) -> str:
    return re.sub(r'[^A-Za-z0-9._-]+', '-', s).strip('-_')

# -------------------- Windows pipeline --------------------

def repack_windows(vr_bin: str, asset_path: Path, client_cfg: Path,
                   arch: str, version: str, out_dir: Path) -> Optional[Path]:
    name = asset_path.name.lower()
    if name.endswith(".msi"):
        flag, ext = "--msi", ".msi"
    elif name.endswith(".exe"):
        flag, ext = "--exe", ".exe"
    else:
        print(f"[!] Not a repackable Windows asset: {asset_path.name}")
        return None
    out_name = f"Windows_VelociraptorClient_{version}_{arch}{ext}"
    out_path = out_dir / out_name
    cmd = [vr_bin, "config", "repack", flag, str(asset_path), str(client_cfg), str(out_path)]
    print("\n[*] Running repack:")
    print("    " + " ".join(map(shlex_quote, cmd)))
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    print(proc.stdout)
    if proc.returncode != 0:
        print("[!] Repack failed.")
        return None
    print(f"[*] Repacked -> {out_path}")
    return out_path

# -------------------- Linux pipeline --------------------

def build_linux_package(vr_bin: str, kind: str, client_cfg: Path,
                        bin_path: Path, arch: str, version: str, out_dir: Path) -> Optional[Path]:
    kind = kind.lower()
    if kind not in ("deb", "rpm"):
        raise ValueError("kind must be 'deb' or 'rpm'")
    ext = ".deb" if kind == "deb" else ".rpm"
    out_name = f"Linux_VelociraptorClient_{version}_{arch}{ext}"
    out_path = out_dir / out_name
    cmd = [vr_bin, "debian" if kind == "deb" else "rpm", "client",
           "--config", str(client_cfg), "--binary", str(bin_path), "--output", str(out_path)]
    print("\n[*] Building Linux package:")
    print("    " + " ".join(map(shlex_quote, cmd)))
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    print(proc.stdout)
    if proc.returncode != 0:
        print("[!] Package build failed.")
        return None
    print(f"[*] Built -> {out_path}")
    return out_path

def linux_service_template(exec_path="/usr/local/bin/velociraptor",
                           cfg_path="/etc/velociraptor/client.config.yaml") -> str:
    return (
        "[Unit]\n"
        "Description=Velociraptor Client\n"
        "After=network-online.target\n"
        "Wants=network-online.target\n\n"
        "[Service]\n"
        "Type=simple\n"
        f"ExecStart={exec_path} --config {cfg_path} client -v\n"
        "Restart=always\n"
        "RestartSec=30\n"
        "LimitNOFILE=20000\n\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n"
    )

def write_text(path: Path, content: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path

def linux_installer_script(bin_filename: str, cfg_filename: str, svc_filename: str) -> str:
    return (
        "#!/usr/bin/env bash\n"
        "set -euo pipefail\n"
        f'BIN_SRC="{bin_filename}"\n'
        f'CFG_SRC="{cfg_filename}"\n'
        f'SVC_SRC="{svc_filename}"\n\n'
        'sudo install -D -m 0755 "$BIN_SRC" /usr/local/bin/velociraptor\n'
        'sudo install -D -m 0644 "$CFG_SRC" /etc/velociraptor/client.config.yaml\n'
        'sudo install -D -m 0644 "$SVC_SRC" /etc/systemd/system/velociraptor_client.service\n'
        "sudo systemctl daemon-reload\n"
        "sudo systemctl enable --now velociraptor_client\n"
        'echo "Velociraptor client installed and service started."\n'
    )

# -------------------- HTML / indexes / server ---------------------------

def write_manifest(outdir: Path, data: Dict) -> Path:
    p = outdir / "manifest.json"
    p.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
    return p

def write_leaf_index(outdir: Path, cfg_rel: Optional[str],
                     group_label: str, rows: List[Tuple[str, str, str]]) -> Path:
    p = outdir / "index.html"
    parts = []
    if cfg_rel:
        parts.append(
            "<div style='padding:12px;border:1px solid #ddd;background:#fffff0;margin:0 0 16px 0'>"
            "<strong>Client configuration</strong>: "
            f"<a href='{html.escape(cfg_rel)}'>{html.escape(cfg_rel)}</a>"
            "</div>"
        )
    parts.append("<table><thead><tr><th>File</th><th>SHA256</th><th></th></tr></thead><tbody>")
    parts.append(f"<tr><th colspan='3' style='background:#eef'>{html.escape(group_label)}</th></tr>")
    for fn, sh, urlp in rows:
        parts.append(
            f"<tr><td><a href='{html.escape(urlp)}'>{html.escape(fn)}</a></td>"
            f"<td><code>{html.escape(sh)}</code></td>"
            f"<td style='text-align:right'><a href='{html.escape(urlp)}' download>download</a></td></tr>"
        )
    parts.append("</tbody></table>")
    html_content = (
        "<!doctype html><html><head><meta charset='utf-8'>"
        "<title>Velociraptor client artifacts</title>"
        "<style>body{font-family:system-ui,Segoe UI,Arial,sans-serif;margin:24px}"
        "table{border-collapse:collapse}td,th{border:1px solid #ddd;padding:8px}"
        "th{background:#f5f5f5}code{font-family:ui-monospace,Consolas,Monaco,monospace}"
        "a{color:#0366d6;text-decoration:none}a:hover{text-decoration:underline}</style>"
        "</head><body><h1>Velociraptor client artifacts</h1>"
        f"{''.join(parts)}</body></html>"
    )
    p.write_text(html_content, encoding="utf-8")
    return p

def write_root_index(dist_root: Path) -> Path:
    p = dist_root / "index.html"
    sections = []
    for osname in ("linux", "windows"):
        osdir = dist_root / osname
        if not osdir.exists():
            continue
        rows = []
        for sub in sorted(osdir.iterdir()):
            if not sub.is_dir():
                continue
            rel = f"./{osname}/{sub.name}/"
            rows.append(f"<tr><td><a href='{html.escape(rel)}'>{html.escape(sub.name)}</a></td></tr>")
        if rows:
            sections.append(f"<h2>{osname.title()}</h2><table><tbody>{''.join(rows)}</tbody></table>")
    html_content = (
        "<!doctype html><html><head><meta charset='utf-8'>"
        "<title>Velociraptor artifacts</title>"
        "<style>body{font-family:system-ui,Segoe UI,Arial,sans-serif;margin:24px}"
        "table{border-collapse:collapse}td,th{border:1px solid #ddd;padding:8px}"
        "th{background:#f5f5f5}</style></head><body>"
        "<h1>Velociraptor artifacts</h1>"
        f"{''.join(sections) if sections else '<p>No artifacts yet.</p>'}"
        "</body></html>"
    )
    dist_root.mkdir(parents=True, exist_ok=True)
    p.write_text(html_content, encoding="utf-8")
    return p

def start_http_server(serve_dir: Path, port: int, background: bool = True) -> None:
    """Always background by default (we also install systemd by default)."""
    py = shutil.which("python3") or sys.executable
    out = open(serve_dir / "http.out", "ab", buffering=0)
    err = open(serve_dir / "http.err", "ab", buffering=0)
    proc = subprocess.Popen([py, "-m", "http.server", str(port)],
                            cwd=str(serve_dir),
                            stdout=out, stderr=err,
                            start_new_session=True)
    (serve_dir / PID_FILENAME).write_text(str(proc.pid), encoding="utf-8")
    print(f"[*] Hosting {serve_dir} on http://0.0.0.0:{port}/  (background PID {proc.pid})")
    print(f"    PID file: {serve_dir / PID_FILENAME}")
    print(f"    Logs: {serve_dir / 'http.out'} , {serve_dir / 'http.err'}")

def install_http_service(dist_root: Path, port: int) -> None:
    """Install & enable a systemd unit to serve dist/ on boot."""
    unit_path = Path("/etc/systemd/system") / HTTPD_UNIT
    py = shutil.which("python3") or sys.executable
    content = (
        "[Unit]\n"
        "Description=Velociraptor artifacts web server\n"
        "After=network-online.target\n"
        "Wants=network-online.target\n\n"
        "[Service]\n"
        "Type=simple\n"
        f"WorkingDirectory={dist_root.resolve()}\n"
        f"ExecStart={py} -m http.server {port}\n"
        "Restart=always\n"
        "RestartSec=5\n\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n"
    )
    try:
        unit_path.write_text(content, encoding="utf-8")
        subprocess.run(["systemctl", "daemon-reload"], check=False)
        subprocess.run(["systemctl", "enable", "--now", HTTPD_UNIT], check=False)
        print(f"[*] Installed and started systemd service: {HTTPD_UNIT}")
    except PermissionError:
        print("[!] Could not write systemd unit (need sudo). Web server still started in background.")

def uninstall_http_service() -> None:
    subprocess.run(["systemctl", "disable", "--now", HTTPD_UNIT], check=False)
    up = Path("/etc/systemd/system") / HTTPD_UNIT
    if up.exists():
        up.unlink()
        subprocess.run(["systemctl", "daemon-reload"], check=False)
    print(f"[*] Removed systemd service: {HTTPD_UNIT}")

# -------------------- build helpers ------------------------------------

def ensure_cfg_copied(dest_dir: Path, client_cfg: Path) -> str:
    hosted = dest_dir / "client.config.yaml"
    if hosted.exists():
        try:
            if sha256_file(hosted) == sha256_file(client_cfg):
                return hosted.name
        except Exception:
            pass
    shutil.copy2(client_cfg, hosted)
    return hosted.name

def add_row(rows: List[Tuple[str, str, str]], path: Path) -> None:
    rows.append((path.name, sha256_file(path), f"./{path.name}"))

# -------------------- OS flows (write into dist/<os>/<tag>-<arch>/) ----

def windows_flow(vr_bin: str, dist_root: Path, client_cfg: Path,
                 assets: List[Dict], tag: str) -> None:
    chosen = pick_from_numbered(assets)
    os_pretty, arch, version = detect_os_arch_version(chosen["name"], "windows", tag)
    leaf = Path("windows") / f"{tag}-{arch}"
    dest = dist_root / leaf
    dest.mkdir(parents=True, exist_ok=True)

    asset_path = download(chosen, dest)
    cfg_rel = ensure_cfg_copied(dest, client_cfg)

    manifest: Dict = {
        "tag": tag, "os": os_pretty, "arch": arch, "version": version,
        "generated_at": int(time.time()),
        "downloaded": {"filename": asset_path.name, "sha256": sha256_file(asset_path), "url": chosen["url"]},
        "outputs": []
    }

    rows: List[Tuple[str, str, str]] = []
    repacked = repack_windows(vr_bin, asset_path, dest / cfg_rel, arch, version, dest)
    if repacked:
        add_row(rows, repacked)
        manifest["outputs"].append({"type": "windows_repacked", "filename": repacked.name, "sha256": sha256_file(repacked)})

    write_manifest(dest, manifest)
    write_leaf_index(dest, cfg_rel, f"{os_pretty} {version} ({arch})", rows)

def linux_flow(vr_bin: str, dist_root: Path, client_cfg: Path,
               assets: List[Dict], tag: str) -> None:
    chosen = pick_from_numbered(assets)
    os_pretty, arch, version = detect_os_arch_version(chosen["name"], "linux", tag)
    leaf = Path("linux") / f"{tag}-{arch}"
    dest = dist_root / leaf
    dest.mkdir(parents=True, exist_ok=True)

    bin_path = download(chosen, dest)
    try:
        bin_path.chmod(bin_path.stat().st_mode | 0o111)
    except Exception:
        pass

    cfg_rel = ensure_cfg_copied(dest, client_cfg)

    print("\nLinux packaging options:")
    print("  1) Build .deb (Debian/Ubuntu)")
    print("  2) Build .rpm (RHEL/CentOS/Alma)")
    print("  3) Raw binary + systemd service template (no packaging)")
    while True:
        mode = input("Choose [1/2/3]: ").strip()
        if mode in ("1", "2", "3"):
            break
        print("Invalid choice.")

    rows: List[Tuple[str, str, str]] = []
    manifest: Dict = {
        "tag": tag, "os": os_pretty, "arch": arch, "version": version,
        "generated_at": int(time.time()),
        "downloaded": {"filename": bin_path.name, "sha256": sha256_file(bin_path), "url": chosen["url"]},
        "outputs": []
    }

    if mode in ("1", "2"):
        kind = "deb" if mode == "1" else "rpm"
        pkg = build_linux_package(vr_bin, kind, dest / cfg_rel, bin_path, arch, version, dest)
        if pkg:
            add_row(rows, pkg)
            manifest["outputs"].append({"type": f"linux_{kind}", "filename": pkg.name, "sha256": sha256_file(pkg)})
    else:
        svc = dest / "velociraptor_client.service"
        write_text(svc, linux_service_template())
        try: svc.chmod(0o644)
        except Exception: pass
        inst = dest / "install_velociraptor_client.sh"
        write_text(inst, linux_installer_script(bin_path.name, cfg_rel, svc.name))
        try: inst.chmod(0o755)
        except Exception: pass
        add_row(rows, bin_path); add_row(rows, svc); add_row(rows, inst)
        manifest["outputs"].extend([
            {"type": "linux_raw_binary", "filename": bin_path.name, "sha256": sha256_file(bin_path)},
            {"type": "linux_systemd_service", "filename": svc.name, "sha256": sha256_file(svc)},
            {"type": "linux_install_script", "filename": inst.name, "sha256": sha256_file(inst)},
        ])

    write_manifest(dest, manifest)
    write_leaf_index(dest, cfg_rel, f"{os_pretty} {version} ({arch})", rows)

# -------------------- main ----------------------------------------------

def main():
    ap = argparse.ArgumentParser(description="Velociraptor client builder/publisher")
    ap.add_argument("--port", type=int, default=DEFAULT_PORT, help="HTTP server port (default 9999)")
    ap.add_argument("--token", help="GitHub token (optional)")
    ap.add_argument("--no-httpd", action="store_true",
                    help="Do NOT install/start the background web server (override default)")
    ap.add_argument("--serve-only", action="store_true",
                    help="Just (re)start the web server for existing dist/, no building")
    ap.add_argument("--remove-httpd", action="store_true",
                    help="Uninstall the systemd service and stop it")
    args = ap.parse_args()

    DIST_ROOT.mkdir(parents=True, exist_ok=True)

    if args.remove_httpd:
        uninstall_http_service()
        sys.exit(0)

    # Serve-only path
    if args.serve_only:
        write_root_index(DIST_ROOT)
        start_http_server(DIST_ROOT, port=args.port, background=True)
        if not args.no_httpd:
            install_http_service(DIST_ROOT, args.port)
        sys.exit(0)

    # Build artifacts
    vr_bin = ensure_velociraptor_on_path()

    options = [("windows", "Windows"), ("linux", "Linux"), ("both", "Both (Windows + Linux)")]
    print("Target client OS?")
    for i, (_, label) in enumerate(options, 1):
        print(f"{i}) {label}")
    while True:
        s = input("Enter number [1-3]: ").strip()
        if s in ("1", "2", "3"):
            os_key = options[int(s) - 1][0]
            break
        print("Invalid choice.")

    # Get the assets list
    try:
        tag, assets = get_latest_assets_api(token=args.token)
    except Exception as e:
        print(f"[!] GitHub API failed: {e}\n    Falling back to HTML scrape…")
        tag, assets = get_latest_assets_scrape()
    if not assets:
        sys.exit("ERROR: Could not retrieve release assets.")

    # Ask for client.config.yaml
    while True:
        cfg = input("\nEnter full path to client.config.yaml: ").strip()
        client_cfg = Path(cfg).expanduser().resolve()
        if client_cfg.exists() and client_cfg.is_file():
            break
        print("Path does not exist or is not a file. Try again.")

    # Do the builds
    if os_key in ("windows", "both"):
        win_assets = filter_assets_for_os(assets, "windows")
        if win_assets:
            windows_flow(vr_bin, DIST_ROOT, client_cfg, win_assets, tag)
        else:
            print("[!] No suitable Windows assets found.")
    if os_key in ("linux", "both"):
        lin_assets = filter_assets_for_os(assets, "linux")
        if lin_assets:
            linux_flow(vr_bin, DIST_ROOT, client_cfg, lin_assets, tag)
        else:
            print("[!] No suitable Linux assets found.")

    # Root index & web server
    root_idx = write_root_index(DIST_ROOT)
    print(f"[*] Root index: {root_idx}")
    start_http_server(DIST_ROOT, port=args.port, background=True)
    if not args.no_httpd:
        install_http_service(DIST_ROOT, args.port)

    print("\nDONE. Browse:")
    print(f"  http://<this-host>:{args.port}/")

if __name__ == "__main__":
    main()
