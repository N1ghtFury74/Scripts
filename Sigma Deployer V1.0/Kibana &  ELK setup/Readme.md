## Kibana & ELK Setup Playbook

This folder contains the operational scripts we use to spin up, reset, and harden a single-node Elastic Stack that is suitable for Sigma/Kibana detection-rule testing. The centerpiece is `Kibana_Rules_Reday.sh`, which turns a freshly installed stack into a “rule-ready” environment: Kibana listens on all interfaces, encrypted saved-object support is enabled, Elasticsearch credentials are normalized, and an API key is minted for CI-driven imports via `deployer.py`.

### Repository Contents

| Script | Purpose | When to Run |
| --- | --- | --- |
| `ELK_Deploy.sh` | Installs Elasticsearch + Kibana from the official Elastic APT repository (defaults to current 9.x), applies kernel prerequisites, and performs the one-time enrollment handshake between the services. | Use on a clean Ubuntu/Debian host (or right after `ELK_FullDeletion.sh`) to provision the stack. |
| `Kibana_Rules_Reday.sh` | Configures Kibana for rule automation (bind, ES TLS CA, encrypted saved-object key), stabilizes service startups, resets the `elastic` password to a known value, issues a superuser API key, and runs sanity checks against the Detection Engine API. | Run immediately after `ELK_Deploy.sh` whenever you need a deterministic test sandbox or when Kibana settings drift. |
| `ELK_FullDeletion.sh` | Stops services, purges packages, deletes data/config/logs, removes repo entries and sysctl tweaks, and (optionally) deletes system users/firewall rules. | Use when you want to **completely** reset the host before redeploying or repurposing it. |

### Requirements for Rule Testing

To make Kibana ready for deployer-driven rule tests you need the following in place:

1. **Supported OS & Privileges**  
   - Ubuntu/Debian host with sudo/root access and outbound internet (for the Elastic APT repo).  
   - Ability to open TCP 5601 (Kibana) and 9200 (Elasticsearch) from your workstation/lab.

2. **Base Stack Installation** (`ELK_Deploy.sh`)  
   - Ensures `vm.max_map_count` meets bootstrap needs.  
   - Performs Kibana enrollment against Elasticsearch TLS using the generated CA.  
   - Provides the initial `elastic` password printed during installation (keep it handy until the “Rules Ready” script resets it).

3. **Kibana Rule Readiness** (`Kibana_Rules_Reday.sh`) – Highlights:  
   - **Configuration hygiene**: injects `server.host: "0.0.0.0"`, `elasticsearch.hosts`, and points Kibana at the ES HTTP CA so all Elastic traffic remains encrypted.  
   - **Encrypted Saved Objects**: enforces a 32-character `xpack.encryptedSavedObjects.encryptionKey` (required for Detection Engine, actions, and connectors).  
   - **Service health gates**: restarts Kibana, waits for `/api/status` to report `available`, and verifies Elasticsearch HTTPS responsiveness using the CA bundle.  
   - **Credential normalization**: programmatically resets the built-in `elastic` password to the literal string `elastic`, ensuring all local docs and scripts match.  
   - **API key provisioning**: uses the normalized credentials to call `_security/api_key`, capturing the `encoded` value needed by `deployer.py`.  
   - **Detection Engine probe**: performs `GET /api/detection_engine/rules/_find?page=1&per_page=1` with `kbn-xsrf: true` to prove Kibana’s rule APIs are accessible.  
   - **Operational hand-off**: stores all resulting secrets in `/root/elastic-credentials.txt` and prints a ready-to-run deployer command with the host’s IP.

4. **Automation Client** (`deployer.py`)  
   - Requires Python 3 with `requests`.  
   - Needs the Kibana base URL (`http://<host>:5601`), target space, and a valid API key (generated above) or username/password that can create API keys when `--local-kibana` is used.  
   - Before importing rules it checks the Detection Engine connectivity, so Kibana must already be configured by `Kibana_Rules_Reday.sh`.

### Recommended Workflow

1. **Reset (optional)**  
   ```bash
   sudo ./ELK_FullDeletion.sh
   ```
2. **Deploy the stack**  
   ```bash
   sudo ./ELK_Deploy.sh
   ```
3. **Harden & prep Kibana for rules**  
   ```bash
   sudo ./Kibana_Rules_Reday.sh
   ```
   Capture the output `encoded_api_key` and `http://<host>:5601` URL.
4. **Import rules**  
   ```bash
   python3 deployer.py --mode bulk-import \
       --ndjson ./detections.ndjson \
       --url http://<host>:5601 --api-key <encoded_key> --overwrite true
   ```
   For iterative testing, the interactive wizard (`python3 deployer.py --interactive`) will walk you through the same inputs.

### Troubleshooting & Tips

- If `Kibana_Rules_Reday.sh` reports “CA not found,” re-run `ELK_Deploy.sh` or verify `/etc/elasticsearch/certs/http_ca.crt` exists.  
- API key creation requires `xpack.security.authc.api_key.enabled: true` (default) and a user with `manage_api_key`. If the script fails at that stage, fix privileges before running deployer.  
- Always wait for `“Connection check succeeded.”` from `deployer.py`; if it fails, re-run the readiness script or inspect Kibana logs (`/var/log/kibana/kibana.log`).  
- Keep `/root/elastic-credentials.txt` secure—anyone with that file can log into your lab stack.

With these steps, your Kibana instance will consistently start in a known-good state where detection rules can be imported, updated, and tested using the accompanying deployer tooling.
