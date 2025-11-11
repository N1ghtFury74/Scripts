# Sigma Deployer (`deployer.py`) Documentation

This document explains how `Sigma Deployer V1.0/Sigma Deployer/deployer.py` automates Elastic Security (Kibana Detection Engine) rule management. Use it as an operational playbook and a detailed reference for every option the script exposes.

---

## 1. What the script does

`deployer.py` wraps the official Kibana Detection Engine REST APIs (`/api/detection_engine/...`) and provides:

- **Bulk ingestion** of Sigma- or Kibana-formatted NDJSON rule bundles.
- **Per-rule upserts** with diff detection and strict schema validation.
- **Selective actions** (`delete`, `enable`, `disable`) by `rule_id`.
- **Connectivity checks** and optional JSON reporting.
- **Interactive wizarding** for users who prefer prompts over flags.

Under the hood, `ElasticClient` (lines 479–638) manages authentication headers, TLS handling, Kibana spaces, retries, and the downgrade-from-HTTPS logic that kicks in when the target only offers HTTP.

---

## 2. High-level flow

1. **Argument parsing** – `build_parser()` (lines 778–878) defines every CLI option and baked-in usage examples.
2. **Interactive fallback** – `main()` (lines 980–996) swaps `args` with wizard input when `--interactive` is set.
3. **Input validation** – `run()` (lines 881–978) enforces required arguments per mode and loads NDJSON when needed.
4. **Authentication setup** – `ElasticClient` is created with ApiKey or Basic auth. With `--local-kibana`, the script can call `/api/security/api_key` to mint a temporary key and immediately switch to ApiKey auth.
5. **Connectivity gate** – `ensure_connection_ready()` (lines 389–397) performs a `_find` query before any mutations.
6. **Mode execution** – One of the `perform_*` helpers (lines 640–775) runs depending on `--mode`.
7. **Reporting** – `render_report()` prints a table, and `write_report()` optionally persists the JSON payload.

---

## 3. Authentication, TLS, and spaces

| Feature | How it works | When to use it |
| --- | --- | --- |
| **ApiKey auth** | Pass `--api-key <base64>`; the script adds `Authorization: ApiKey ...`. | Preferred for CI/CD and remote deployments. |
| **Basic auth** | Use `--username` + `--password`. Headers are built once and reused by the shared `requests.Session`. | Only when ApiKeys are unavailable. |
| **`--local-kibana`** | Runs only when Basic auth is provided and the script is executed on the Kibana host. It calls `ElasticClient.create_api_key()`, stores the encoded key, then drops the username/password. | Creates short-lived keys for on-box admin work without exposing long-term ApiKeys. Requires `manage_api_key`. |
| **TLS verification** | Controlled by `--verify-tls [true/false]`. Defaults to `true`. | Use `false` only in air‑gapped labs with self-signed certs. |
| **Space awareness** | Every space-aware API call prefixes `/s/<space>` via `_sp()`. Passing `--space foo` scopes operations to that space. | Needed when Security rules live outside the default space. |

If the target Kibana URL is misconfigured (`https://` when the server only speaks HTTP), `_request()` auto-downgrades exactly once and logs a warning.

---

## 4. NDJSON input expectations

`load_ndjson()` (lines 243–271) enforces several contracts before any deployment begins:

- **File format** – Each line must be a complete JSON object (NDJSON). Arrays (`[ ... ]`) or Saved-Object exports with `"attributes"` wrappers are rejected.
- **Rule-only content** – Objects whose `"type"` is `"search"`, `"dashboard"`, or `"visualization"` (see `SAVED_OBJECT_TYPES`) are flagged because those belong in the Saved Objects import UI, not the Detection Engine API.
- **Required fields** – Every rule must include `rule_id`, `name`, `description`, `severity`, `risk_score`, `type`, `language`, `query`, `from`, and `interval`. Either `index` or `data_view_id` must also be present (see `missing_required_fields()`).
- **Sanitization** – When rules are merged, `sanitize_for_write()` strips read-only properties (`updated_at`, `execution_summary`, etc.) to avoid 400 responses.

If any line fails validation, the entire run halts with a descriptive error (line number included), protecting Kibana from half-applied datasets.

---

## 5. Deployment modes

### 5.1 `bulk-import`

- **Purpose** – Highest-throughput ingestion (single `_import` HTTP call).
- **Key flags** – `--ndjson <file>` (required), `--overwrite [bool]` (default `true`).
- **Behavior** – Uploads the entire file, then the script correlates the Kibana response to each `rule_id`, generating per-rule `DeployResult` entries. Any errors from Kibana’s response are surfaced and included in the optional JSON report (`bulk_summary` key).
- **When to choose** – CI pipelines or initial seeding where you want Kibana to evaluate conflicts server-side.

### 5.2 `per-rule`

- **Purpose** – Idempotent upserts with fine-grained feedback.
- **Process**:
  1. Fetch each rule via `/api/detection_engine/rules?rule_id=...`.
  2. Merge incoming NDJSON fields into the server copy via `merge_rule_payload()`.
  3. Skip writes when the sanitized payload matches the current server state.
  4. Decide between `create_rule()` (POST) and `update_rule()` (PUT) based on existence.
- **`--deploy-disabled`** – Forces `enabled=false` regardless of the NDJSON contents, ideal for “dark launch” testing.
- **When to choose** – When you need schema enforcement, partial updates, or want to ensure no rule is touched unnecessarily.

### 5.3 `delete-by-id`

- **Purpose** – Remove one or more rules supplied via `--ids ruleA,ruleB`.
- **Behavior** – Confirms existence, then calls `DELETE /api/detection_engine/rules`. Missing rules return an error result with `404`.
- **Use cases** – Controlled cleanup between test cycles or removing deprecated Sigma content.

### 5.4 `enable-by-id` / `disable-by-id`

- **Purpose** – Flip the `enabled` flag without touching the rest of the rule definition.
- **Mechanics** – Retrieves the latest rule JSON, merges only `rule_id` plus the overridden `enabled` state, then updates it. The response’s version is echoed in the report (`enabled=True version X`).
- **Use cases** – Scheduled toggling, quick mitigation, or turning on a curated subset of rules.

### 5.5 `test-connection`

- **Purpose** – Verify API reachability and credentials (`GET /api/detection_engine/rules/_find?page=1&per_page=1`) without reading the NDJSON file or mutating any rule.
- **Use cases** – Health checks, troubleshooting TLS/auth before running a real mode.

---

## 6. Command-line options

| Option | Required? | Default | Applies to | Notes |
| --- | --- | --- | --- | --- |
| `--url` | Yes | – | All modes | Base Kibana URL such as `https://kibana:5601`. |
| `--space` | No | `default` | All modes | Targets another Kibana space when needed. |
| `--ndjson` | Modes: `bulk-import`, `per-rule` | – | Bulk/per rule | Path to the detection-rule NDJSON. Validated before use. |
| `--api-key` | One of auth options must be supplied | – | All modes | Base64-encoded ApiKey; mutually exclusive with username/password once `ElasticClient` is created. |
| `--username`, `--password` | Only if `--api-key` missing | – | All modes | Used for Basic auth and for temporary key creation with `--local-kibana`. |
| `--mode` | Yes | – | All modes | One of `bulk-import`, `per-rule`, `delete-by-id`, `enable-by-id`, `disable-by-id`, `test-connection`. |
| `--overwrite [BOOL]` | No | `true` | Bulk-import | When `false`, `_import` keeps existing rules that share `rule_id`. |
| `--verify-tls [BOOL]` | No | `true` | All modes | Set `false` to skip TLS verification. |
| `--report <path>` | No | – | All modes | Writes a JSON summary containing CLI args, action counts, and per-rule results. Creates intermediate directories if missing. |
| `--ids <csv>` | Required for delete/enable/disable modes | – | Targeted modes | Comma-separated `rule_id` list. Parsed and trimmed via `parse_rule_ids()`. |
| `--deploy-disabled` | No | `False` | Per-rule | Forces newly created/updated rules to stay disabled. Ignored—and warned about—when the active mode is not `per-rule`. |
| `--local-kibana` | No | `False` | All modes | Attempts to create an ApiKey using the provided Basic credentials. Only works when the script runs on the Kibana node. |
| `--interactive` | No | `False` | All modes | Launches the wizard that prompts for every option (with defaults pulled from whatever flags were supplied). |

Boolean flags that accept optional explicit values (e.g., `--overwrite false`) use the helper `str_to_bool()`, so inputs like `0`, `false`, `no`, `off` are accepted.

---

## 7. Outputs and reporting

- **Console log** – `log()` prefixes messages with `[INFO]`/`[ERROR]`. Separators from `hr()` make the deployment report easy to spot.
- **Deployment table** – `render_report()` prints columns (`Rule ID`, `Name`, `Action`, `HTTP`, `Message`) with width auto-sizing and ellipsized messages.
- **Action summary** – After the table, action counts (create/update/skip/delete/enable/disable/import/errors) are displayed, courtesy of `summarize_results()`.
- **Structured report** – When `--report` is provided, `write_report()` serializes:
  ```json
  {
    "url": "...",
    "space": "...",
    "mode": "...",
    "overwrite": true,
    "counts": { ... },
    "results": [
      {"rule_id": "...", "name": "...", "action": "...", "http_code": 200, "message": "..."}
    ],
    "bulk_summary": {...}  // only for bulk-import
  }
  ```
  This is ideal for auditing, dashboards, or CI artifacts.

---

## 8. Interactive wizard

Calling `python deployer.py --interactive` launches `interactive_session()` (lines 280–388). Highlights:

- **Input validation** – Path prompts run `ensure_path_exists()`. Auth prompts loop until non-empty values are entered.
- **Mode-specific follow-ups** – Only prompts for `ndjson` in modes that need it, only asks about `--ids` when relevant, etc.
- **Defaults** – Every prompt surfaces the current argument default (either CLI-provided or internal).
- **Secure password entry** – `getpass.getpass()` masks `--password`.

The wizard mutates the parsed `args` namespace and hands it back to `run()`, so the rest of the flow stays exactly the same as the non-interactive path.

---

## 9. Error handling and safeguards

- **Connection guard** – Any authentication, TLS, or Detection Engine availability issue surfaces before writes.
- **Rule validation** – Missing required fields, absent `rule_id`s, or invalid NDJSON lines stop the deployment early with actionable messages.
- **Read-only field stripping** – Prevents `400 Bad Request` responses by removing server-managed properties before POST/PUT operations.
- **Skip logic** – In per-rule mode, unchanged rules are skipped, keeping the Kibana rule version untouched.
- **Graceful exits** – Keyboard interrupts return exit code `130`, while other unhandled exceptions exit with `1` after logging the message.

---

## 10. Usage examples

```bash
# 1. CI bulk import that overwrites conflicting IDs
python deployer.py --mode bulk-import --ndjson detections.ndjson \
  --url https://kibana:5601 --api-key ENC_API_KEY --overwrite true --report reports/bulk.json

# 2. Safe per-rule rollout where everything stays disabled for shadow testing
python deployer.py --mode per-rule --ndjson detections.ndjson \
  --url https://kibana:5601 --api-key ENC_API_KEY --deploy-disabled

# 3. Delete and then disable specific rules by ID (comma-separated list)
python deployer.py --mode delete-by-id --ids sigma_proc_spike,sigma_file_drop \
  --url https://kibana:5601 --api-key ENC_API_KEY

python deployer.py --mode disable-by-id --ids sigma_proc_spike \
  --url https://kibana:5601 --api-key ENC_API_KEY

# 4. Wizard-driven session (no flags needed; great for manual operators)
python deployer.py --interactive
```

---

## 11. Practical tips

- Keep NDJSON exports limited to detection rules. Saved-object exports (with dashboards, searches, etc.) belong in Kibana’s “Saved Objects” importer.
- Store ApiKeys securely; the script never prints them but they may live in your shell history if you type them inline. Prefer environment variables or `pass`/`keyring` wrappers.
- When using `--report`, add the resulting JSON file to your CI artifacts to audit which rules changed.
- Combine `--test-connection` with your monitoring stack to continuously verify that the Detection Engine API is reachable.
- If you see TLS downgrade warnings, double-check whether load balancers terminate HTTPS or if your URL is mis-specified.

With this reference, you should be able to read, operate, and extend `deployer.py` confidently. Happy shipping!
