
# Apache Combined Log -> Normalized CSV (SIEM-ready)

This toolkit contains two Python scripts for parsing Apache/Nginx "combined" access logs into a single CSV with normalized fields:

- apache_to_csv.py - opinionated ECS-style output (fixed columns).
- apache_to_csv_flexible.py - configurable/interactive output; pick fields and rename for any SIEM.

Both convert timestamps to UTC ISO8601, normalize IPv4/IPv6, and categorize HTTP status codes into an event.outcome bucket.

---

## 1) Supported input

- Log format: Apache/Nginx combined ("%h %l %u [%t] "%r" %>s %b "%{Referer}i" "%{User-Agent}i"").
- Works with IPv4/IPv6 (e.g., ::1).
- Handles zero-byte responses (%b = "-").

## 2) Normalized fields (ECS-inspired)

- @timestamp - UTC ISO8601 timestamp derived from "[23/Aug/2015:14:46:24 -0700]".
- event.original - raw log line.
- source.ip - client IP.
- user.name - HTTP auth user ("-" becomes empty).
- http.request.method - GET, POST, ...
- url.original - raw request target (path or absolute URL).
- url.path - path-only (e.g., /dashboard/stylesheets/all.css).
- url.query - query-string (without ?).
- http.version - 1.1, 2.0, etc.
- http.response.status_code - integer.
- http.response.bytes - integer ("-" -> 0).
- http.request.referrer - "-" normalized to empty.
- user_agent.original - user agent string.
- event.outcome - one of: success (2xx), redirect (3xx), client_error (4xx), server_error (5xx), unknown.
- network.transport - tcp (constant).
- network.protocol - https if the referrer starts with https://, else http.

## 3) Usage

### Fixed output
```
python apache_to_csv.py --input access.log --output out.csv
python apache_to_csv.py --input "/var/log/apache2/*.log" --output out.csv
python apache_to_csv.py --input "/logs" --recursive --output out.csv
```

### Flexible output (choose fields/renames)

Interactive:
```
python apache_to_csv_flexible.py --input access.log --output out.csv --interactive
```

Select fields via CLI and apply SIEM preset:
```
python apache_to_csv_flexible.py   --input access.log   --output out.csv   --include-fields "@timestamp,source.ip,http.request.method,url.path,http.response.status_code,user_agent.original"   --siem splunk
```

Custom renames via JSON file:
```
# map.json: {"source.ip":"src_ip","http.response.status_code":"status"}
python apache_to_csv_flexible.py --input access.log --output out.csv --rename-fields map.json
```

Combine directory + recursion + keep bad lines:
```
python apache_to_csv_flexible.py --input /logs --recursive --output out.csv --keep-bad
```

## 4) SIEM presets

- --siem splunk - renames dotted ECS-ish headers to snake_case (e.g., source.ip -> source_ip).
- --siem cef - minimal, CEF-like keys (src, requestMethod, request, status, referrer, requestClientApplication).

You can mix a preset with your own --rename-fields JSON; your explicit mappings win.

## 5) Error handling

- Lines that don't match the combined format are skipped. Add --keep-bad to include them with event.original filled and other columns empty.
- The parser uses UTF-8 with replacement for decoding to survive stray bytes.

## 6) Performance tips

- Run on SSD; use globbing to limit files (access.log, access.log.1, etc.).
- Pipe the output CSV straight into your shipper/ingest tool.

## 7) Extending the schema

To add more fields (e.g., virtual host, server name), either:
- Adjust your Apache LogFormat to include fields you need, then update the regex, or
- Keep combined and enrich later downstream (e.g., join on source.ip to GeoIP).

## 8) Limitations

- Only parses combined format (not W3C or custom formats). If your logs differ, the regex must be adapted.
- network.protocol is inferred from the referrer; if you log scheme in %r or via a custom header, you can extend the logic easily.

## 9) Example

Input:
```
::1 - - [23/Aug/2015:14:46:24 -0700] "GET /dashboard/ HTTP/1.1" 200 7327 "-" "Mozilla/4.0 (...)"
```

Output (CSV row):
```
2015-08-23T21:46:24Z,"::1 - - [23/Aug/2015:14:46:24 -0700] ""GET /dashboard/ HTTP/1.1"" 200 7327 ""-"" ""Mozilla/4.0 (...)"",::1,,GET,/dashboard/,,1.1,200,7327,,Mozilla/4.0 (...),success,tcp,http
```

---

Files in this package:
- apache_to_csv.py - fixed ECS-like columns.
- apache_to_csv_flexible.py - configurable/interactive.
- README_ApacheParser.md - this document.
