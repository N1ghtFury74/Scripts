#!/usr/bin/env python3
# Parse Apache/Nginx *combined* access logs into a normalized CSV (ECS-inspired fields).
# Fields:
#   @timestamp (UTC ISO8601), event.original, source.ip, user.name,
#   http.request.method, url.original, url.path, url.query, http.version,
#   http.response.status_code, http.response.bytes, http.request.referrer,
#   user_agent.original, event.outcome, network.transport, network.protocol
#
# Usage:
#   python apache_to_csv.py --input access.log --output out.csv
#   python apache_to_csv.py --input /var/log/apache2/*.log --output out.csv
#   python apache_to_csv.py --input /logs --recursive --output out.csv

import re, sys, csv, glob, argparse
from datetime import datetime, timezone
from urllib.parse import urlsplit
from ipaddress import ip_address
import os

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
    if referer and referer.lower().startswith("https://"):
        return "https"
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
    if not pathq:
        return "", ""
    if "://" in pathq:
        try:
            u = urlsplit(pathq)
            p, q = u.path, u.query
            return p or "/", q
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
            pattern = "**/*" if recursive else "*"
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
            import glob
            for path in glob.glob(src):
                try:
                    with open(path, "r", errors="replace", encoding="utf-8", newline="") as f:
                        for line in f:
                            yield line.rstrip("\r\n")
                except Exception:
                    continue

def main():
    ap = argparse.ArgumentParser(description="Parse Apache combined logs to normalized CSV")
    ap.add_argument("--input", "-i", nargs="+", required=True, help="Input file(s) or directories (globs ok)")
    ap.add_argument("--recursive", "-r", action="store_true", help="Recurse when inputs are directories")
    ap.add_argument("--output", "-o", required=True, help="Output CSV path")
    ap.add_argument("--keep-bad", action="store_true", help="Keep unparsable lines with minimal fields")
    args = ap.parse_args()

    fields = [
        "@timestamp",
        "event.original",
        "source.ip",
        "user.name",
        "http.request.method",
        "url.original",
        "url.path",
        "url.query",
        "http.version",
        "http.response.status_code",
        "http.response.bytes",
        "http.request.referrer",
        "user_agent.original",
        "event.outcome",
        "network.transport",
        "network.protocol",
    ]

    written = 0
    bad = 0

    os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)

    with open(args.output, "w", newline="", encoding="utf-8") as out:
        w = csv.DictWriter(out, fieldnames=fields)
        w.writeheader()

        for raw in iter_lines(args.input, recursive=args.recursive):
            m = COMBINED_RE.match(raw)
            if not m:
                bad += 1
                if args.keep-bad:
                    w.writerow({
                        "@timestamp": "",
                        "event.original": raw,
                        "source.ip": "",
                        "user.name": "",
                        "http.request.method": "",
                        "url.original": "",
                        "url.path": "",
                        "url.query": "",
                        "http.version": "",
                        "http.response.status_code": "",
                        "http.response.bytes": "",
                        "http.request.referrer": "",
                        "user_agent.original": "",
                        "event.outcome": "unknown",
                        "network.transport": "tcp",
                        "network.protocol": "",
                    })
                continue

            gd = m.groupdict()
            host = normalize_ip(gd.get("host",""))
            user = gd.get("user","") if gd.get("user") != "-" else ""
            try:
                ts_iso = parse_time_to_utc_iso(gd["time"])
            except Exception:
                ts_iso = ""

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

            row = {
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
            w.writerow(row)
            written += 1

    print(f"Wrote {written} records to {args.output} (skipped {bad} bad lines)", file=sys.stderr)

if __name__ == "__main__":
    main()
