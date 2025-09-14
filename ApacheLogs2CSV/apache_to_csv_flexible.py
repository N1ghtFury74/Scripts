#!/usr/bin/env python3
# (Recreated) Apache/Nginx "combined" access log -> CSV with customizable normalization
# See README_ApacheParser.md for full documentation.

import re, sys, csv, glob, argparse, json, os
from datetime import datetime, timezone
from urllib.parse import urlsplit
from ipaddress import ip_address

COMBINED_RE = re.compile(
    r'^(?P<host>\S+)\s+'
    r'(?P<ident>\S+)\s+'
    r'(?P<user>\S+)\s+'
    r'\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<request>[^"]*)"\s+'
    r'(?P<status>\d{3})\s+'
    r'(?P<size>\S+)'
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<agent>[^"]*)")?'
    r'\s*$'
)

DEFAULT_FIELDS = [
    "@timestamp","event.original","source.ip","user.name",
    "http.request.method","url.original","url.path","url.query",
    "http.version","http.response.status_code","http.response.bytes",
    "http.request.referrer","user_agent.original","event.outcome",
    "network.transport","network.protocol",
]

SIEM_PRESETS = {
    "splunk": {
        "@timestamp":"timestamp","event.original":"event_original","source.ip":"source_ip",
        "user.name":"user_name","http.request.method":"http_request_method","url.original":"url_original",
        "url.path":"url_path","url.query":"url_query","http.version":"http_version",
        "http.response.status_code":"status","http.response.bytes":"bytes","http.request.referrer":"referrer",
        "user_agent.original":"user_agent","event.outcome":"outcome","network.transport":"transport",
        "network.protocol":"protocol",
    },
    "cef": {
        "@timestamp":"end","source.ip":"src","http.request.method":"requestMethod",
        "url.path":"request","http.response.status_code":"status","http.request.referrer":"referrer",
        "user_agent.original":"requestClientApplication"
    }
}

def parse_time_to_utc_iso(s: str) -> str:
    dt = datetime.strptime(s, "%d/%b/%Y:%H:%M:%S %z")
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00","Z")

def outcome_from_status(code: int) -> str:
    if 200 <= code < 300: return "success"
    if 300 <= code < 400: return "redirect"
    if 400 <= code < 500: return "client_error"
    if 500 <= code < 600: return "server_error"
    return "unknown"

def infer_protocol(referer: str) -> str:
    if referer and referer.lower().startswith("https://"): return "https"
    return "http"

def split_request(req: str):
    method = pathq = version = ""
    if req and req != "-":
        parts = req.split()
        if len(parts) == 3:
            method, pathq, version = parts
        elif len(parts) == 2:
            method, pathq = parts
        else:
            pathq = req
    return method, pathq, version

def split_path_query(pathq: str):
    if not pathq: return "", ""
    if "://" in pathq:
        try:
            u = urlsplit(pathq)
            return (u.path or "/"), u.query
        except Exception:
            pass
    if "?" in pathq:
        p, q = pathq.split("?", 1)
        return p or "/", q
    return pathq or "/", ""

def normalize_ip(ip: str) -> str:
    try:
        return str(ip_address(ip))
    except Exception:
        return ip

def iter_lines(sources, recursive=False):
    for src in sources:
        if os.path.isdir(src):
            for root, dirs, files in os.walk(src):
                if not recursive and root != src:
                    continue
                for name in files:
                    path = os.path.join(root, name)
                    try:
                        with open(path, "r", errors="replace", encoding="utf-8", newline="") as f:
                            for line in f:
                                yield line.rstrip("\r\n")
                    except Exception:
                        continue
        else:
            for path in glob.glob(src):
                try:
                    with open(path, "r", errors="replace", encoding="utf-8", newline="") as f:
                        for line in f:
                            yield line.rstrip("\r\n")
                except Exception:
                    continue

def interactive_choose_fields(all_fields):
    print("\nInteractive field selection:\n")
    for i, f in enumerate(all_fields, 1):
        print(f"{i:2d}. {f}")
    raw = input("\nEnter numbers to include (comma-separated) or press Enter for ALL: ").strip()
    if not raw:
        chosen = list(all_fields)
    else:
        idx = []
        for tok in raw.split(","):
            t = tok.strip()
            if not t: continue
            try:
                n = int(t)
                if 1 <= n <= len(all_fields):
                    idx.append(n-1)
            except ValueError:
                pass
        chosen = [all_fields[i] for i in idx] if idx else list(all_fields)
    print("\nOptional: rename fields (press Enter to skip). For example: source.ip=src_ip,http.response.status_code=status")
    rn = input("Renames: ").strip()
    ren = {}
    if rn:
        for pair in rn.split(","):
            if "=" in pair:
                k,v = pair.split("=",1)
                ren[k.strip()] = v.strip()
    return chosen, ren

def load_json_mapping(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def main():
    ap = argparse.ArgumentParser(description="Apache combined -> CSV with customizable normalization")
    ap.add_argument("--input", "-i", nargs="+", required=True, help="Input file(s) or directories (globs ok)")
    ap.add_argument("--recursive", "-r", action="store_true", help="Recurse when inputs are directories")
    ap.add_argument("--output", "-o", required=True, help="Output CSV path")
    ap.add_argument("--keep-bad", action="store_true", help="Keep unparsable lines with minimal fields")
    ap.add_argument("--include-fields", help="Comma-separated list of fields to include")
    ap.add_argument("--rename-fields", help="Path to JSON mapping of {normalized_field: custom_name}")
    ap.add_argument("--siem", choices=["splunk","cef"], help="Apply preset field renames for a SIEM")
    ap.add_argument("--interactive", action="store_true", help="Ask which fields to keep and how to rename them")
    args = ap.parse_args()

    normalized_fields = list(DEFAULT_FIELDS)
    chosen_fields = None
    custom_renames = {}

    if args.interactive:
        chosen_fields, renames_from_interactive = interactive_choose_fields(normalized_fields)
        custom_renames.update(renames_from_interactive)

    if args.include_fields:
        cli_fields = [f.strip() for f in args.include_fields.split(",") if f.strip()]
        chosen_fields = cli_fields

    if not chosen_fields:
        chosen_fields = list(normalized_fields)

    if args.siem:
        preset = SIEM_PRESETS.get(args.siem, {})
        custom_renames.update(preset)

    if args.rename_fields:
        mapping = load_json_mapping(args.rename_fields)
        custom_renames.update(mapping)

    header = [(f, custom_renames.get(f, f)) for f in chosen_fields]

    os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)

    written = 0
    bad = 0

    with open(args.output, "w", newline="", encoding="utf-8") as out:
        w = csv.writer(out)
        w.writerow([disp for (norm, disp) in header])

        for raw in iter_lines(args.input, recursive=args.recursive):
            m = COMBINED_RE.match(raw)
            if not m:
                bad += 1
                if args.keep_bad:
                    outvals = []
                    for (norm, disp) in header:
                        outvals.append(raw if norm == "event.original" else "")
                    w.writerow(outvals)
                continue

            gd = m.groupdict()
            try:
                ts_iso = parse_time_to_utc_iso(gd["time"])
            except Exception:
                ts_iso = ""

            host = normalize_ip(gd.get("host",""))
            user = gd.get("user","")
            user = "" if user == "-" else user

            try:
                status_i = int(gd.get("status","0"))
            except Exception:
                status_i = 0

            size = gd.get("size","-")
            try:
                size_i = 0 if size == "-" else int(size)
            except Exception:
                size_i = 0

            request = gd.get("request","") or ""
            method, pathq, version = split_request(request)
            path, query = split_path_query(pathq)
            referer = gd.get("referer") or ""
            agent = gd.get("agent") or ""
            proto = infer_protocol(referer)

            norm = {
                "@timestamp": ts_iso,
                "event.original": raw,
                "source.ip": host,
                "user.name": user,
                "http.request.method": method,
                "url.original": pathq,
                "url.path": path,
                "url.query": query,
                "http.version": version.replace("HTTP/","") if version else "",
                "http.response.status_code": status_i,
                "http.response.bytes": size_i,
                "http.request.referrer": "" if referer == "-" else referer,
                "user_agent.original": agent,
                "event.outcome": outcome_from_status(status_i),
                "network.transport": "tcp",
                "network.protocol": proto,
            }

            outvals = []
            for (norm_name, disp_name) in header:
                outvals.append(norm.get(norm_name, ""))
            w.writerow(outvals)
            written += 1

    print(f"Wrote {written} records to {args.output} (skipped {bad} bad lines)", file=sys.stderr)

if __name__ == "__main__":
    main()
