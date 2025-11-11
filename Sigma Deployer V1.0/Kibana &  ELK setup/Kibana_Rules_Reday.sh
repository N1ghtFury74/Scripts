#!/usr/bin/env bash
set -euo pipefail

# --- CONSTANTS (your exact key as requested) ---
KBN_KEY='fhjskloppd678ehkdfdlliverpoolfcr'   # 32 chars
ES_CA='/etc/elasticsearch/certs/http_ca.crt'

# --- PRECHECKS ---
command -v jq >/dev/null 2>&1 || apt-get update -y && apt-get install -y jq
if [[ ! -f "$ES_CA" ]]; then
  echo "ERROR: CA not found at $ES_CA. Ensure Elasticsearch DEB package created certs." >&2
  exit 1
fi

echo "== 1) Ensure Kibana config is complete (bind, ES URL/CA, encryption key) =="
# Bind Kibana on all interfaces (browser access)
grep -qE '^server\.host:' /etc/kibana/kibana.yml \
  || echo 'server.host: "0.0.0.0"' >> /etc/kibana/kibana.yml

# ES URL + CA (talk HTTPS to ES using the package CA)
grep -qE '^elasticsearch\.hosts:' /etc/kibana/kibana.yml \
  || echo 'elasticsearch.hosts: ["https://localhost:9200"]' >> /etc/kibana/kibana.yml
grep -qE '^elasticsearch\.ssl\.certificateAuthorities:' /etc/kibana/kibana.yml \
  || echo "elasticsearch.ssl.certificateAuthorities: [\"${ES_CA}\"]" >> /etc/kibana/kibana.yml

# REQUIRED for detections/actions (prevents 'hapi/undefined' style errors and disabled features)
if grep -qE '^xpack\.encryptedSavedObjects\.encryptionKey:' /etc/kibana/kibana.yml; then
  sed -i 's|^xpack\.encryptedSavedObjects\.encryptionKey:.*|xpack.encryptedSavedObjects.encryptionKey: "'"$KBN_KEY"'"|' /etc/kibana/kibana.yml
else
  echo "xpack.encryptedSavedObjects.encryptionKey: \"${KBN_KEY}\"" >> /etc/kibana/kibana.yml
fi

echo "== 2) Restart Kibana and wait for readiness =="
systemctl restart kibana
# Wait for Kibana API (no auth needed just to read /api/status)
until curl -s http://localhost:5601/api/status | jq -e '.status.overall.level=="available"' >/dev/null 2>&1; do
  echo "  waiting for Kibana..."
  sleep 2
done
echo "Kibana is up."

echo "== 3) Ensure Elasticsearch is up (HTTPS with CA) =="
until curl -s --cacert "$ES_CA" https://localhost:9200 >/dev/null; do
  echo "  waiting for Elasticsearch..."
  sleep 2
done
echo "Elasticsearch is up."

echo "== 4) Force built-in 'elastic' password to the exact value 'elastic' =="
# Step A: Generate a temporary password (non-interactive) to guarantee access
TMP_PASS="$(
  /usr/share/elasticsearch/bin/elasticsearch-reset-password -u elastic -b | awk '/New value/ {print $NF}'
)"
if [[ -z "${TMP_PASS}" ]]; then
  echo "ERROR: could not bootstrap a temporary elastic password." >&2
  exit 1
fi

# Step B: Immediately set password to the exact string 'elastic'
CHANGE_RESP="$(
  curl -sS --fail --cacert "$ES_CA" -u "elastic:${TMP_PASS}" \
       -H 'Content-Type: application/json' \
       -X POST 'https://localhost:9200/_security/user/elastic/_password' \
       -d '{"password":"elastic"}'
)" || { echo "ERROR: password change request failed"; exit 1; }

# If empty body, that’s OK; on success ES returns 200 with no JSON.
echo "Password for user 'elastic' is now: elastic"

echo "== 5) Create a superuser API key for automation (encoded form) =="
APIKEY_JSON="$(curl -sS --fail --cacert "$ES_CA" -u 'elastic:elastic' \
  -H 'Content-Type: application/json' \
  -X POST 'https://localhost:9200/_security/api_key' \
  -d '{"name":"sigma-deployer-'"$(date +%s)"'"}')"
ENCODED_KEY="$(jq -r '.encoded' <<<"$APIKEY_JSON")"
if [[ -z "$ENCODED_KEY" || "$ENCODED_KEY" == "null" ]]; then
  echo "ERROR: API key creation failed: $APIKEY_JSON" >&2
  exit 1
fi

echo "== 6) Quick Kibana API sanity checks (space: default) =="
# Detection Engine 'find' in default space (no /s/<space> prefix for default)
curl -sS --fail -H 'kbn-xsrf: true' -H "Authorization: ApiKey ${ENCODED_KEY}" \
  "http://localhost:5601/api/detection_engine/rules/_find?page=1&per_page=1" \
  | jq '{http:"ok",page:.page,total:.total}' || { echo "ERROR: Kibana rule API check failed"; exit 1; }

echo "== 7) Save credentials for your deployer and print ready-to-run command =="
install -m 600 -o root -g root /dev/null /root/elastic-credentials.txt
cat >/root/elastic-credentials.txt <<CREDS
elastic_username=elastic
elastic_password=elastic
encoded_api_key=${ENCODED_KEY}
kibana_encryptedSavedObjectsKey=${KBN_KEY}
es_ca=${ES_CA}
CREDS

IP="$(hostname -I | awk '{print $1}')"
echo
echo "Ready to deploy (bulk import, overwrite):"
echo "python3 deployer.py --ndjson ./detections.ndjson \\"
echo "  --url http://${IP}:5601 --api-key ${ENCODED_KEY} --mode deploy \\"
echo "  --import-mode bulk --overwrite"
echo
echo "Kibana URL:  http://${IP}:5601"
echo "Elasticsearch: https://${IP}:9200  (CA: ${ES_CA})"
echo "Saved:        /root/elastic-credentials.txt"
