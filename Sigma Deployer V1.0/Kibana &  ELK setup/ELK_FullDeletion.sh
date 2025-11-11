# --- 0) Stop/disable anything running (ignore errors if not present)
sudo systemctl stop kibana elasticsearch 2>/dev/null || true
sudo systemctl disable kibana elasticsearch 2>/dev/null || true

# --- 1) Purge Debian/Ubuntu packages
sudo apt-get purge -y 'elasticsearch*' 'kibana*'
sudo apt-get autoremove -y
sudo apt-get autoclean -y

# --- 2) Remove leftover dirs/files from both packages
# Elasticsearch dirs (config, data, logs, home)
sudo rm -rf /etc/elasticsearch /var/lib/elasticsearch /var/log/elasticsearch /usr/share/elasticsearch
# Kibana dirs (config, data, logs, home)
sudo rm -rf /etc/kibana /var/lib/kibana /var/log/kibana /usr/share/kibana

# If you previously tried tar/manual installs, nuke common leftovers (safe if absent)
sudo rm -rf ~/elastic* ~/kibana* /opt/elastic* /opt/kibana* /root/elastic* 2>/dev/null || true

# --- 3) Remove Elastic APT repo + keyring (these are the official paths)
sudo rm -f /etc/apt/sources.list.d/elastic-*.list
sudo rm -f /usr/share/keyrings/elasticsearch-keyring.gpg
sudo apt-get update -y

# --- 4) Remove the sysctl file we created for ES (optional if you want a totally clean host)
sudo rm -f /etc/sysctl.d/99-elasticsearch.conf
sudo sysctl --system >/dev/null 2>&1 || true

# --- 5) Clear systemd state and any failed units
sudo systemctl daemon-reload
sudo systemctl reset-failed

# --- 6) OPTIONAL: remove system users/groups if you want zero traces (safe to skip)
sudo deluser --system --quiet elasticsearch 2>/dev/null || true
sudo deluser --system --quiet kibana 2>/dev/null || true
sudo groupdel elasticsearch 2>/dev/null || true
sudo groupdel kibana 2>/dev/null || true

# --- 7) OPTIONAL: close firewall holes if you opened them earlier
if command -v ufw >/dev/null 2>&1; then
  sudo ufw delete allow 9200/tcp 2>/dev/null || true
  sudo ufw delete allow 5601/tcp 2>/dev/null || true
fi

# --- 8) Verify it’s gone
echo "== dpkg check (no lines expected) ==" && dpkg -l | egrep -i '(^ii\s+)?(elastic|kibana)' || echo "OK: no Elastic/Kibana packages"
echo "== port check (no lines expected) ==" && ss -lntp | egrep ':9200|:5601' || echo "OK: nothing listening on 9200/5601"
