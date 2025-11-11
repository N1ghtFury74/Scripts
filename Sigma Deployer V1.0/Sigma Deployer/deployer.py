#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""deployer.py - Deploy Elastic Security (Kibana Detection Engine) rules."""

from __future__ import annotations

import argparse
import base64
import getpass
import json
import os
import sys
import textwrap
import time
from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional, Tuple

import requests
from requests import exceptions as req_exc

SAVED_OBJECT_TYPES = {"search", "dashboard", "visualization"}

MODE_DESCRIPTIONS = {
    "bulk-import": "Single API call that uploads the entire NDJSON file for maximum throughput.",
    "per-rule": "Merge/update each NDJSON object individually with required-field validation.",
    "delete-by-id": "Delete one or more rule_ids supplied via --ids.",
    "enable-by-id": "Set enabled=true on the provided --ids after fetching current definitions.",
    "disable-by-id": "Set enabled=false on the provided --ids after fetching current definitions.",
    "test-connection": "Perform only the auth + connectivity check; no rule changes.",
}

READ_ONLY_FIELDS = {
    "id",
    "updated_at",
    "updated_by",
    "created_at",
    "created_by",
    "immutable",
    "rule_source",
    "status",
    "execution_summary",
    "last_success_at",
    "last_success_message",
    "last_failure_at",
    "last_failure_message",
    "next_run",
    "running",
    "referenced_by_count",
}

REQUIRED_RULE_FIELDS = (
    "rule_id",
    "name",
    "description",
    "severity",
    "risk_score",
    "type",
    "language",
    "query",
    "from",
    "interval",
)


@dataclass
class DeployResult:
    rule_id: str
    name: str
    action: str
    http_code: Optional[int]
    message: str


def log(msg: str, level: str = "INFO") -> None:
    print(f"[{level}] {msg}")


def hr(title: str) -> None:
    line = "-" * 72
    print(f"\n{line}\n{title}\n{line}")


def prompt_bool(question: str, default: bool = True) -> bool:
    suffix = "[Y/n]" if default else "[y/N]"
    while True:
        value = input(f"{question} {suffix} ").strip().lower()
        if not value:
            return default
        if value in {"y", "yes"}:
            return True
        if value in {"n", "no"}:
            return False
        print("Please respond with y or n.")


def prompt_input(
    question: str,
    *,
    default: Optional[str] = None,
    required: bool = False,
    validator: Optional[Any] = None,
) -> str:
    while True:
        prompt = question
        if default:
            prompt += f" [{default}]"
        prompt += ": "
        value = input(prompt).strip()
        if not value and default is not None:
            value = default
        if not value and required:
            print("This value is required.")
            continue
        if validator:
            try:
                validator(value)
            except Exception as exc:  # pylint: disable=broad-except
                print(f"Invalid value: {exc}")
                continue
        return value or ""


def prompt_choice(
    question: str,
    choices: Dict[str, str],
    default: Optional[str] = None,
) -> str:
    items = list(choices.items())
    print(f"\n{question}")
    for idx, (value, desc) in enumerate(items, start=1):
        marker = " (default)" if default and value == default else ""
        print(f"[{idx}] {value:<15} {desc}{marker}")
    while True:
        raw = input("Select option by number or value: ").strip()
        if not raw and default:
            return default
        if raw.isdigit():
            selected = int(raw)
            if 1 <= selected <= len(items):
                return items[selected - 1][0]
        for value, _desc in items:
            if raw.lower() == value.lower():
                return value
        print("Invalid selection, try again.")


def normalize_user_path(value: str) -> str:
    """Normalize user-entered paths (strip quotes, support Windows-style separators)."""
    if value is None:
        return ""
    trimmed = value.strip().strip("\"'")
    replaced = trimmed.replace("\\", os.sep)
    expanded = os.path.expanduser(replaced)
    return os.path.abspath(expanded)


def ensure_path_exists(value: str) -> None:
    normalized = normalize_user_path(value)
    if not normalized:
        raise ValueError("Path cannot be empty")
    if not os.path.exists(normalized):
        raise ValueError("File not found")


def ensure_non_empty(value: Optional[str], label: str) -> str:
    if value is None:
        raise ValueError(f"{label} cannot be empty")
    cleaned = value.strip()
    if not cleaned:
        raise ValueError(f"{label} cannot be empty")
    return cleaned


def str_to_bool(value: Optional[str]) -> bool:
    if value is None:
        return True
    if isinstance(value, bool):
        return value
    lowered = value.strip().lower()
    if lowered in {"1", "true", "yes", "y", "on"}:
        return True
    if lowered in {"0", "false", "no", "n", "off"}:
        return False
    raise argparse.ArgumentTypeError("Expected a boolean value (true/false).")


def sanitize_for_write(data: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    if not data:
        return {}
    return {k: v for k, v in data.items() if k not in READ_ONLY_FIELDS}


def is_detection_rule(obj: Dict[str, Any]) -> bool:
    if not isinstance(obj, dict):
        return False
    if obj.get("type") in SAVED_OBJECT_TYPES:
        return False
    return bool(obj.get("rule_id")) and bool(obj.get("type"))


def has_value(data: Dict[str, Any], key: str) -> bool:
    if key not in data:
        return False
    value = data[key]
    if value is None:
        return False
    if isinstance(value, str):
        return bool(value.strip())
    if isinstance(value, (list, tuple, set)):
        return bool(value)
    return True


def missing_required_fields(payload: Dict[str, Any]) -> List[str]:
    missing: List[str] = []
    for field in REQUIRED_RULE_FIELDS:
        if not has_value(payload, field):
            missing.append(field)
    if not has_value(payload, "index") and not has_value(payload, "data_view_id"):
        missing.append("index|data_view_id")
    return missing


def merge_rule_payload(
    incoming: Dict[str, Any],
    existing: Optional[Dict[str, Any]],
    override_enabled: Optional[bool],
) -> Dict[str, Any]:
    base: Dict[str, Any] = {}
    if existing:
        base.update(existing)
    base.update(incoming)
    if override_enabled is not None:
        base["enabled"] = override_enabled
    payload = sanitize_for_write(base)
    missing = missing_required_fields(payload)
    if missing:
        rid = payload.get("rule_id") or incoming.get("rule_id") or "<missing rule_id>"
        raise ValueError(f"Rule {rid} missing required fields: {', '.join(missing)}")
    return payload


def load_ndjson(path: str) -> List[Dict[str, Any]]:
    if not os.path.exists(path):
        raise FileNotFoundError(path)
    rules: List[Dict[str, Any]] = []
    first_non_ws_checked = False
    with open(path, "r", encoding="utf-8") as fh:
        for line_no, raw in enumerate(fh, start=1):
            stripped = raw.strip()
            if not stripped:
                continue
            if not first_non_ws_checked:
                first_non_ws_checked = True
                if stripped.startswith("["):
                    raise ValueError("NDJSON must be newline-delimited JSON (file appears to start with '[').")
            try:
                obj = json.loads(stripped)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid NDJSON line {line_no}: {exc}") from exc
            if obj.get("type") in SAVED_OBJECT_TYPES or "attributes" in obj:
                raise ValueError(
                    f"Line {line_no} looks like a Saved-Object export (found '{obj.get('type')}'/attributes wrapper). "
                    "Use Stack Management → Saved Objects importer for these."
                )
            if not is_detection_rule(obj):
                raise ValueError(f"Line {line_no} is not a detection rule (missing rule_id/type).")
            rules.append(obj)
    if not rules:
        raise ValueError("NDJSON file contained no detection rules")
    return rules


def parse_rule_ids(ids: Optional[str]) -> List[str]:
    if not ids:
        return []
    return [rid.strip() for rid in ids.split(",") if rid.strip()]


def interactive_session(parser: argparse.ArgumentParser, args: argparse.Namespace) -> argparse.Namespace:
    hr("INTERACTIVE DEPLOYER")
    log("Press Enter to accept defaults shown in brackets.", "INFO")

    url = prompt_input(
        "Kibana base URL (e.g., https://localhost:5601)",
        default=args.url,
        required=True,
    )
    space = prompt_input("Kibana space name", default=args.space or "default")
    verify_tls = prompt_bool(
        "Verify TLS certificates?",
        default=args.verify_tls if isinstance(args.verify_tls, bool) else True,
    )
    local_kibana = prompt_bool(
        "Is the script running on the Kibana host (allows temporary API key creation)?",
        default=getattr(args, "local_kibana", False),
    )

    api_key = args.api_key or None
    username = args.username or None
    password = args.password or None

    if local_kibana:
        auth_choice = prompt_choice(
            "Choose authentication method",
            {
                "api-key": "Use an existing API key (recommended)",
                "username/password": "Use basic auth; script can auto-create an API key",
            },
            default="api-key" if api_key else "username/password",
        )
    else:
        auth_choice = "api-key"
        if not api_key:
            print("\nRemote deployments require an API key.")
    if auth_choice == "api-key":
        while True:
            try:
                api_key_value = prompt_input("API key (base64)", default=api_key, required=True)
                api_key = ensure_non_empty(api_key_value, "API key")
                break
            except ValueError as exc:
                print(exc)
        username = None
        password = None
    else:
        while True:
            try:
                username = ensure_non_empty(prompt_input("Username", default=username, required=True), "Username")
                break
            except ValueError as exc:
                print(exc)
        while True:
            try:
                password_plain = getpass.getpass("Password: ")
                password = ensure_non_empty(password_plain, "Password")
                break
            except ValueError as exc:
                print(exc)
        api_key = None

    mode = prompt_choice("Choose deployment mode", MODE_DESCRIPTIONS, default=args.mode or "bulk-import")

    ndjson_path = args.ndjson or ""
    ids_value = args.ids or ""
    overwrite = args.overwrite if isinstance(args.overwrite, bool) else True
    deploy_disabled = args.deploy_disabled

    if mode in {"bulk-import", "per-rule"}:
        ndjson_input = prompt_input(
            "Path to NDJSON file",
            default=ndjson_path,
            required=True,
            validator=ensure_path_exists,
        )
        ndjson_path = normalize_user_path(ndjson_input)
    if mode == "bulk-import":
        overwrite = prompt_bool("Overwrite existing rules when IDs already exist?", default=bool(overwrite))
    if mode == "per-rule":
        deploy_disabled = prompt_bool(
            "Force rules to stay disabled after creation/update?",
            default=bool(deploy_disabled),
        )
    if mode in {"delete-by-id", "enable-by-id", "disable-by-id"}:
        ids_value = prompt_input(
            "Comma-separated rule_ids",
            default=ids_value,
            required=True,
        )

    report_path = prompt_input("JSON report output path (leave blank to skip)", default=args.report or "")

    args.url = url
    args.space = space or "default"
    args.verify_tls = verify_tls
    args.local_kibana = local_kibana
    args.api_key = api_key
    args.username = username
    args.password = password
    args.mode = mode
    args.ndjson = ndjson_path or None
    args.ids = ids_value or None
    args.overwrite = overwrite
    args.deploy_disabled = deploy_disabled
    args.report = report_path or None
    return args


def ensure_connection_ready(client: "ElasticClient") -> None:
    try:
        client.check_connection()
    except RuntimeError as exc:
        raise RuntimeError(
            "Connection check failed. Verify the Kibana URL is reachable, the API key or credentials are valid, "
            "TLS settings (--verify-tls) are correct, and Elastic Security's detection engine is enabled. "
            f"Underlying error: {exc}"
        ) from exc

def summarize_results(results: List[DeployResult]) -> Dict[str, int]:
    summary = {
        "total": len(results),
        "create": 0,
        "update": 0,
        "skip": 0,
        "delete": 0,
        "enable": 0,
        "disable": 0,
        "import": 0,
        "errors": 0,
    }
    for res in results:
        if res.action in summary:
            summary[res.action] += 1
        if res.action == "error":
            summary["errors"] += 1
    return summary


def render_report(results: List[DeployResult]) -> None:
    if not results:
        log("No rule operations executed.")
        return
    hr("DEPLOYMENT REPORT")
    headers = ("Rule ID", "Name", "Action", "HTTP", "Message")
    rows = []
    for res in results:
        http_value = str(res.http_code) if res.http_code is not None else "-"
        rows.append(
            (
                res.rule_id,
                res.name,
                res.action,
                http_value,
                textwrap.shorten(res.message, width=80, placeholder="..."),
            )
        )
    widths = [len(h) for h in headers]
    for row in rows:
        widths = [max(widths[i], len(row[i])) for i in range(len(headers))]
    fmt = " | ".join(f"{{:{w}}}" for w in widths)
    print(fmt.format(*headers))
    print("-+-".join("-" * w for w in widths))
    for row in rows:
        print(fmt.format(*row))
    summary = summarize_results(results)
    print(
        f"\nSummary: total={summary['total']} create={summary['create']} update={summary['update']} "
        f"skip={summary['skip']} delete={summary['delete']} enable={summary['enable']} "
        f"disable={summary['disable']} import={summary['import']} errors={summary['errors']}"
    )


def write_report(
    path: str,
    args: argparse.Namespace,
    results: List[DeployResult],
    extra: Optional[Dict[str, Any]] = None,
) -> None:
    if not path:
        return
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    payload: Dict[str, Any] = {
        "url": args.url,
        "space": args.space,
        "mode": args.mode,
        "overwrite": args.overwrite,
        "counts": summarize_results(results),
        "results": [asdict(r) for r in results],
    }
    if extra:
        payload.update(extra)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2)
    log(f"Report written to {path}")


class ElasticClient:
    def __init__(
        self,
        url: str,
        api_key: Optional[str],
        username: Optional[str],
        password: Optional[str],
        space: str,
        verify_tls: bool,
    ) -> None:
        if not api_key and not (username and password):
            raise ValueError("Provide --api-key or both --username and --password")
        self.base = url.rstrip("/")
        self.space = space or "default"
        self.verify = verify_tls
        self.session = requests.Session()
        self.session.headers.update({"kbn-xsrf": "true"})
        self._downgraded = False
        if api_key:
            self.session.headers["Authorization"] = f"ApiKey {api_key}"
        else:
            token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
            self.session.headers["Authorization"] = f"Basic {token}"

    def _sp(self) -> str:
        return f"/s/{self.space}" if self.space and self.space != "default" else ""

    def _url(self, path: str, space_aware: bool = True) -> str:
        prefix = self._sp() if space_aware else ""
        return f"{self.base}{prefix}{path}"

    def _request(
        self,
        method: str,
        path: str,
        *,
        space_aware: bool = True,
        **kwargs: Any,
    ) -> requests.Response:
        url = self._url(path, space_aware)
        try:
            return self.session.request(method, url, verify=self.verify, **kwargs)
        except req_exc.SSLError as exc:
            msg = str(exc).lower()
            if (
                not self._downgraded
                and self.base.startswith("https://")
                and ("wrong version number" in msg or "unknown protocol" in msg)
            ):
                log("SSL handshake failed (server likely HTTP). Retrying over http://", "WARNING")
                self.base = "http://" + self.base.split("://", 1)[1]
                self._downgraded = True
                return self._request(method, path, space_aware=space_aware, **kwargs)
            raise RuntimeError(f"{method} {url} failed: {exc}") from exc
        except req_exc.RequestException as exc:
            raise RuntimeError(f"{method} {url} failed: {exc}") from exc

    @staticmethod
    def _raise_for_status(resp: requests.Response, endpoint: str) -> None:
        if resp.status_code < 300:
            return
        body = resp.text or ""
        if resp.status_code == 409:
            body = (
                "duplicate rule_id. "
                f"{body.strip()} (use --overwrite for bulk import or merge/PUT in per-rule mode)."
            )
        raise RuntimeError(f"HTTP {resp.status_code} for {endpoint}: {body}")

    def check_connection(self) -> bool:
        resp = self._request(
            "GET",
            "/api/detection_engine/rules/_find",
            params={"page": 1, "per_page": 1},
            timeout=30,
        )
        if resp.status_code == 200:
            return True
        self._raise_for_status(resp, "GET /api/detection_engine/rules/_find")
        return False

    def get_rule(self, rule_id: str) -> Optional[Dict[str, Any]]:
        resp = self._request(
            "GET",
            "/api/detection_engine/rules",
            params={"rule_id": rule_id},
            timeout=30,
        )
        if resp.status_code == 404:
            return None
        self._raise_for_status(resp, "GET /api/detection_engine/rules")
        return resp.json()

    def create_rule(self, payload: Dict[str, Any]) -> Tuple[Dict[str, Any], int]:
        resp = self._request(
            "POST",
            "/api/detection_engine/rules",
            json=payload,
            timeout=60,
        )
        self._raise_for_status(resp, "POST /api/detection_engine/rules")
        return resp.json(), resp.status_code

    def update_rule(self, payload: Dict[str, Any]) -> Tuple[Dict[str, Any], int]:
        resp = self._request(
            "PUT",
            "/api/detection_engine/rules",
            json=payload,
            timeout=60,
        )
        self._raise_for_status(resp, "PUT /api/detection_engine/rules")
        return resp.json(), resp.status_code

    def delete_rule(self, rule_id: str) -> Tuple[Optional[Dict[str, Any]], int]:
        resp = self._request(
            "DELETE",
            "/api/detection_engine/rules",
            params={"rule_id": rule_id},
            timeout=60,
        )
        if resp.status_code == 404:
            return None, 404
        self._raise_for_status(resp, "DELETE /api/detection_engine/rules")
        data = resp.json() if resp.content else None
        return data, resp.status_code

    def import_rules_bulk(self, ndjson_path: str, overwrite: bool) -> Tuple[Dict[str, Any], int]:
        params = {"overwrite": str(bool(overwrite)).lower()}
        with open(ndjson_path, "rb") as fh:
            files = {"file": (os.path.basename(ndjson_path), fh, "application/ndjson")}
            resp = self._request(
                "POST",
                "/api/detection_engine/rules/_import",
                params=params,
                files=files,
                timeout=120,
            )
        self._raise_for_status(resp, "POST /api/detection_engine/rules/_import")
        return resp.json(), resp.status_code

    def create_api_key(self, name: str = "sigma-deployer") -> str:
        payload = {"name": f"{name}-{int(time.time())}"}
        resp = self._request(
            "POST",
            "/api/security/api_key",
            space_aware=False,
            json=payload,
            timeout=30,
        )
        if resp.status_code in {403, 404}:
            raise RuntimeError(
                "API key endpoint unavailable (requires Elastic Security with API-key privileges)."
            )
        self._raise_for_status(resp, "POST /api/security/api_key")
        data = resp.json()
        encoded = data.get("encoded")
        if not encoded:
            raise RuntimeError("API key response missing 'encoded'")
        return encoded


def perform_bulk_import(
    client: ElasticClient,
    ndjson_path: str,
    overwrite: bool,
    rules: List[Dict[str, Any]],
) -> Tuple[List[DeployResult], Dict[str, Any]]:
    summary, status_code = client.import_rules_bulk(ndjson_path, overwrite=overwrite)
    errors = summary.get("errors") or []
    errors_by_rule: Dict[str, List[Dict[str, Any]]] = {}
    unmatched_errors: List[Dict[str, Any]] = []
    for err in errors:
        rid = err.get("rule_id")
        if rid:
            errors_by_rule.setdefault(str(rid), []).append(err)
        else:
            unmatched_errors.append(err)
    rule_name_map = {
        str(rule.get("rule_id") or "<missing rule_id>"): rule.get("name", "<untitled>")
        for rule in rules
    }
    results: List[DeployResult] = []
    for rule in rules:
        rid = str(rule.get("rule_id") or "<missing rule_id>")
        name = rule.get("name", "<untitled>")
        err_list = errors_by_rule.get(rid)
        if err_list:
            err = err_list.pop(0)
            message = err.get("message") or json.dumps(err)
            results.append(DeployResult(rid, name, "error", err.get("status_code"), message))
        else:
            results.append(DeployResult(rid, name, "import", status_code, "Imported via bulk API"))
    for rid, err_list in errors_by_rule.items():
        for err in err_list:
            message = err.get("message") or json.dumps(err)
            results.append(
                DeployResult(rid, rule_name_map.get(rid, "<unknown>"), "error", err.get("status_code"), message)
            )
    for err in unmatched_errors:
        rid = str(err.get("rule_id") or "<unknown>")
        message = err.get("message") or json.dumps(err)
        results.append(DeployResult(rid, "<unknown>", "error", err.get("status_code"), message))
    return results, summary


def perform_per_rule(
    client: ElasticClient,
    rules: List[Dict[str, Any]],
    deploy_disabled: bool,
) -> List[DeployResult]:
    results: List[DeployResult] = []
    override_enabled = False if deploy_disabled else None
    for rule in rules:
        rid_value = rule.get("rule_id")
        rid = str(rid_value or "<missing rule_id>")
        name = rule.get("name", "<untitled>")
        if not rid_value:
            results.append(DeployResult(rid, name, "error", None, "Missing rule_id in NDJSON entry"))
            continue
        try:
            existing = client.get_rule(rid_value)
        except Exception as exc:
            results.append(DeployResult(rid, name, "error", None, str(exc)))
            continue
        try:
            payload = merge_rule_payload(rule, existing, override_enabled=override_enabled)
        except Exception as exc:
            results.append(DeployResult(rid, name, "error", None, str(exc)))
            continue
        existing_clean = sanitize_for_write(existing)
        if existing and existing_clean == payload:
            results.append(DeployResult(rid, name, "skip", 200, "No differences detected"))
            continue
        try:
            if existing:
                data, status = client.update_rule(payload)
                results.append(DeployResult(rid, name, "update", status, f"version {data.get('version')}"))
            else:
                data, status = client.create_rule(payload)
                results.append(DeployResult(rid, name, "create", status, f"version {data.get('version')}"))
        except Exception as exc:
            results.append(DeployResult(rid, name, "error", None, str(exc)))
    return results


def perform_delete_by_id(client: ElasticClient, ids: List[str]) -> List[DeployResult]:
    results: List[DeployResult] = []
    for rid in ids:
        rid_value = rid.strip()
        if not rid_value:
            continue
        try:
            existing = client.get_rule(rid_value)
        except Exception as exc:
            results.append(DeployResult(rid_value, "<unknown>", "error", None, str(exc)))
            continue
        name = existing.get("name", "<untitled>") if existing else "<unknown>"
        if not existing:
            results.append(DeployResult(rid_value, name, "error", 404, "Rule not found"))
            continue
        try:
            _, status = client.delete_rule(rid_value)
            results.append(DeployResult(rid_value, name, "delete", status, "Deleted"))
        except Exception as exc:
            results.append(DeployResult(rid_value, name, "error", None, str(exc)))
    return results


def perform_toggle_by_id(
    client: ElasticClient,
    ids: List[str],
    enabled: bool,
) -> List[DeployResult]:
    action = "enable" if enabled else "disable"
    results: List[DeployResult] = []
    for rid in ids:
        rid_value = rid.strip()
        if not rid_value:
            continue
        try:
            existing = client.get_rule(rid_value)
        except Exception as exc:
            results.append(DeployResult(rid_value, "<unknown>", "error", None, str(exc)))
            continue
        if not existing:
            results.append(DeployResult(rid_value, "<unknown>", "error", 404, "Rule not found"))
            continue
        name = existing.get("name", "<untitled>")
        try:
            payload = merge_rule_payload({"rule_id": rid_value}, existing, override_enabled=enabled)
            data, status = client.update_rule(payload)
            results.append(
                DeployResult(rid_value, name, action, status, f"enabled={enabled} version {data.get('version')}")
            )
        except Exception as exc:
            results.append(DeployResult(rid_value, name, "error", None, str(exc)))
    return results


def build_parser() -> argparse.ArgumentParser:
    description = textwrap.dedent(
        """\
        Deploy Elastic Security (Kibana Detection Engine) rules using the official REST APIs.
        Modes:
          • bulk-import   – upload a full NDJSON file via a single _import call (fast CI/CD seeding).
          • per-rule      – fetch, merge, and upsert each rule_id individually with diff detection.
          • delete/enable/disable-by-id – target specific rule_ids supplied via --ids.
          • test-connection – only verify connectivity & auth; no rules are changed.

        All requests send kbn-xsrf headers, support ApiKey or Basic auth, respect Kibana spaces,
        and honor TLS verification flags.
        """
    )
    epilog = "\n".join(
        [
            "Examples:",
            "  # Bulk import with overwrite (preferred for CI)",
            "  python deployer.py --mode bulk-import --ndjson detections.ndjson --url https://kibana:5601 "
            "--api-key ENC --overwrite true",
            "",
            "  # Per-rule deploy but keep everything disabled for shadow testing",
            "  python deployer.py --mode per-rule --ndjson detections.ndjson --url https://kibana:5601 "
            "--api-key ENC --deploy-disabled",
            "",
            "  # Delete two rules by ID",
            "  python deployer.py --mode delete-by-id --ids rule-a,rule-b --url https://kibana:5601 --api-key ENC",
            "",
            "  # Interactive wizard (no CLI args required)",
            "  python deployer.py --interactive",
            "",
            "Option notes:",
            "  --overwrite        Controls whether bulk import replaces conflicting rule_ids.",
            "  --deploy-disabled  Sets enabled=false when per-rule mode writes rules (great for dry runs).",
            "  --local-kibana     When using username/password directly on the Kibana host, auto-create a temp API key.",
            "  --verify-tls false Skip TLS verification (only do this in labs).",
        ]
    )
    parser = argparse.ArgumentParser(
        description=description,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=epilog,
    )
    parser.add_argument("--url", help="Kibana base URL, e.g., https://host:5601")
    parser.add_argument("--space", default="default", help="Kibana space name")
    parser.add_argument("--ndjson", help="Path to Kibana detection rule NDJSON")
    parser.add_argument("--api-key", help="Elastic API key (base64 encoded)")
    parser.add_argument("--username", help="Elastic username (basic auth)")
    parser.add_argument("--password", help="Elastic password (basic auth)")
    parser.add_argument(
        "--mode",
        choices=(
            "bulk-import",
            "per-rule",
            "delete-by-id",
            "enable-by-id",
            "disable-by-id",
            "test-connection",
        ),
        help="Execution mode",
    )
    parser.add_argument(
        "--overwrite",
        type=str_to_bool,
        nargs="?",
        const=True,
        default=True,
        metavar="BOOL",
        help="Bulk import: overwrite existing rules when IDs match",
    )
    parser.add_argument(
        "--verify-tls",
        type=str_to_bool,
        nargs="?",
        const=True,
        default=True,
        metavar="BOOL",
        help="Verify TLS certificates",
    )
    parser.add_argument("--report", help="Optional JSON report output path")
    parser.add_argument(
        "--ids",
        help="Comma-separated rule_ids for delete/enable/disable modes",
    )
    parser.add_argument(
        "--deploy-disabled",
        action="store_true",
        help="Per-rule mode: force created/updated rules to remain disabled",
    )
    parser.add_argument(
        "--local-kibana",
        action="store_true",
        help="Indicate the script runs on the Kibana host so it can auto-create a temporary API key "
        "(requires Elastic user with manage_api_key)",
    )
    parser.add_argument(
        "--interactive",
        action="store_true",
        help="Launch an interactive wizard that walks through every option",
    )
    return parser


def run(args: argparse.Namespace, parser: argparse.ArgumentParser) -> None:
    if not args.url:
        parser.error("--url is required (use --interactive for prompts)")
    if not args.mode:
        parser.error("--mode is required (use --interactive for prompts)")

    modes_requiring_ndjson = {"bulk-import", "per-rule"}
    modes_requiring_ids = {"delete-by-id", "enable-by-id", "disable-by-id"}
    if args.mode in modes_requiring_ndjson and not args.ndjson:
        parser.error("--ndjson is required for bulk-import and per-rule modes")
    if args.mode in modes_requiring_ids:
        rule_ids = parse_rule_ids(args.ids)
        if not rule_ids:
            parser.error("--ids is required for delete-by-id/enable-by-id/disable-by-id")
    else:
        rule_ids = []
    if args.ndjson and args.mode in modes_requiring_ndjson and not os.path.exists(args.ndjson):
        parser.error(f"NDJSON file not found: {args.ndjson}")
    if not args.api_key and not (args.username and args.password):
        parser.error("Provide --api-key or both --username and --password")
    if args.deploy_disabled and args.mode != "per-rule":
        log("--deploy-disabled is ignored outside of per-rule mode", "WARNING")

    rules: List[Dict[str, Any]] = []
    if args.mode in modes_requiring_ndjson:
        rules = load_ndjson(args.ndjson)

    try:
        api_key = ensure_non_empty(args.api_key, "API key") if args.api_key else None
        username = ensure_non_empty(args.username, "Username") if args.username else None
        password = ensure_non_empty(args.password, "Password") if args.password else None
    except ValueError as exc:
        parser.error(str(exc))

    if args.local_kibana and not api_key:
        if not (username and password):
            parser.error("--local-kibana requires --username and --password when --api-key is absent")
        temp_client = ElasticClient(
            args.url,
            api_key=None,
            username=username,
            password=password,
            space=args.space,
            verify_tls=args.verify_tls,
        )
        try:
            api_key = temp_client.create_api_key()
            username = None
            password = None
            log("Created API key via Kibana host; switching to ApiKey authentication.")
        except Exception as exc:
            raise RuntimeError(
                "Automatic API key creation failed while --local-kibana is set. "
                "Ensure Elastic Security is enabled, the Kibana user has 'manage_api_key' privileges, "
                "and the API key service is turned on (xpack.security.authc.api_key.enabled). "
                "Alternatively, supply --api-key directly or rerun without --local-kibana. "
                f"Underlying error: {exc}"
            ) from exc

    try:
        client = ElasticClient(
            args.url,
            api_key=api_key,
            username=username,
            password=password,
            space=args.space,
            verify_tls=args.verify_tls,
        )
    except ValueError as exc:
        parser.error(str(exc))

    ensure_connection_ready(client)
    log("Connection check succeeded.")

    if args.mode == "test-connection":
        return

    results: List[DeployResult] = []
    report_extra: Dict[str, Any] = {}

    if args.mode == "bulk-import":
        results, summary = perform_bulk_import(client, args.ndjson, args.overwrite, rules)
        report_extra["bulk_summary"] = summary
    elif args.mode == "per-rule":
        results = perform_per_rule(client, rules, args.deploy_disabled)
    elif args.mode == "delete-by-id":
        results = perform_delete_by_id(client, rule_ids)
    elif args.mode == "enable-by-id":
        results = perform_toggle_by_id(client, rule_ids, enabled=True)
    elif args.mode == "disable-by-id":
        results = perform_toggle_by_id(client, rule_ids, enabled=False)
    else:
        parser.error(f"Unsupported mode {args.mode}")

    render_report(results)
    if args.report:
        write_report(args.report, args, results, extra=report_extra)


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    if getattr(args, "interactive", False):
        args = interactive_session(parser, args)
    try:
        run(args, parser)
    except KeyboardInterrupt:
        log("Interrupted", "ERROR")
        sys.exit(130)
    except Exception as exc:
        log(str(exc), "ERROR")
        sys.exit(1)


if __name__ == "__main__":
    main()
