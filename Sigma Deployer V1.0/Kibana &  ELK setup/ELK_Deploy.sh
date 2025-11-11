set -euo pipefail

echo "== 0. Stop & purge any existing Elasticsearch/Kibana =="
systemctl stop kibana elasticsearch 2>/dev/null || true

# Remove packages (ignore errors if not present)
apt-get purge -y elasticsearch kibana || true

# Remove leftover dirs & unit overrides
rm -rf /etc/elasticsearch /etc/kibana \
       /var/lib/elasticsearch /var/log/elasticsearch \
       /var/lib/kibana /var/log/kibana \
       /usr/share/elasticsearch /usr/share/kibana \
       /etc/systemd/system/elasticsearch.service.d 2>/dev/null || true

# Remove old repo entries/keys you might have
rm -f /etc/apt/sources.list.d/elastic-8.x.list \
      /etc/apt/sources.list.d/elastic-9.x.list \
      /usr/share/keyrings/elasticsearch-keyring.gpg

echo "== 1. Add Elastic APT repo (official) =="
apt-get update -y
apt-get install -y curl gnupg apt-transport-https

curl -fsSL https://artifacts.elastic.co/GPG-KEY-elasticsearch \
 | gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg

# Track the current 9.x series (adjust to 8.x if you truly want 8.x)
cat >/etc/apt/sources.list.d/elastic-9.x.list <<'EOF'
deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/9.x/apt stable main
EOF

apt-get update -y

echo "== 2. Install Elasticsearch & Kibana (DEB packages) =="
apt-get install -y elasticsearch kibana jq

echo "== 3. Satisfy ES bootstrap check: vm.max_map_count =="
sysctl -w vm.max_map_count=262144
echo "vm.max_map_count=262144" >/etc/sysctl.d/99-elasticsearch.conf
sysctl --system >/dev/null

echo "== 4. Start Elasticsearch on boot and right now =="
systemctl daemon-reload
systemctl enable --now elasticsearch

echo "   Waiting for Elasticsearch HTTPS on 9200..."
# ES 8/9 enable security+TLS by default. 200/401 both mean the API is up.
until curl -sk -o /dev/null -w "%{http_code}" https://localhost:9200 | grep -qE '^(200|401)$'; do
  sleep 2
done

# If you didn't save the auto-generated elastic password from dpkg output,
# you can reset it interactively with:
#   /usr/share/elasticsearch/bin/elasticsearch-reset-password -u elastic
# (Keep that password; you'll need it to log into Kibana and for rule imports.)

echo "== 5. Create Kibana enrollment token (official way) =="
ENROLL_TOKEN=$(/usr/share/elasticsearch/bin/elasticsearch-create-enrollment-token -s kibana)

echo "== 6. Run kibana-setup once with the token =="
# This prepares Kibana to talk to ES over TLS and stores credentials in the keystore.
# It only needs to be done once after install or reconfigure.
/usr/share/kibana/bin/kibana-setup --enrollment-token "$ENROLL_TOKEN"

echo "== 7. Start Kibana on boot and right now =="
systemctl enable --now kibana

echo "   Waiting for Kibana API to respond..."
# Kibana /api/status needs the kbn-xsrf header for write-ish calls; but simple GET is fine
until curl -s http://localhost:5601/api/status >/dev/null 2>&1; do
  sleep 2
done

echo "== 8. Show quick status =="
echo "Elasticsearch:"
curl -sk https://localhost:9200 | jq .
echo "Kibana:"
curl -s http://localhost:5601/api/status | jq .status

echo
echo "All set."
echo "Open Kibana in your browser:  http://<this-host>:5601"
echo "Login user: elastic   (use the password printed during 'dpkg -i' or the one you reset)"
