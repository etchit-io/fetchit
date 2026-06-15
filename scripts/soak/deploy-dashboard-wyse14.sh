#!/usr/bin/env bash
# One-time privileged setup to light up the LIT Soak dashboard on the wyse14
# Grafana (the prod-relay monitoring host). RUN ON `one` (holds the fleet SSH
# keys + the dashboard json). The agent's safety guard blocks it because it
# sudo-edits wyse14's Prometheus, so run it yourself:
#
#     ! bash scripts/soak/deploy-dashboard-wyse14.sh
#
# Idempotent. Adds a Prometheus `node` scrape job, seeds soak.prom into the
# node_exporter textfile dir (chowned to the login user so the ongoing feeder
# ships with a plain scp -- no recurring sudo), and drops the Grafana dashboard.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=/dev/null
source "${FLEET_ENV:-$HERE/fleet.env}"
COLLECTOR="${COLLECTOR:-/tmp/soak/collector.py}"
WORK="${WORK:-/tmp/soak}"; LOGS="$WORK/logs"; PROM="$WORK/soak.prom"
W14="${W14:-wyse14@192.168.1.41}"
TEXTFILE_DIR="/var/lib/prometheus/node-exporter"
mkdir -p "$LOGS"

echo "[deploy] refreshing soak.prom from the live fleet..."
for row in "${FLEET[@]}"; do set -- $row; scp $SSH_OPTS -P "$3" "$2:soak/$1.log" "$LOGS/$1.log" >/dev/null 2>&1 || true; done
python3 "$COLLECTOR" --once --prometheus "$PROM" "$LOGS"/*.log >/dev/null
echo "[deploy] soak.prom: $(grep -c '^soak_' "$PROM") metrics"

echo "[deploy] shipping soak.prom + dashboard json to wyse14..."
scp $SSH_OPTS "$PROM" "$W14:soak.prom" >/dev/null
scp $SSH_OPTS "$HERE/grafana-soak-dashboard.json" "$W14:lit-soak.json" >/dev/null

echo "[deploy] privileged setup on wyse14..."
ssh $SSH_OPTS "$W14" "bash -s -- $TEXTFILE_DIR" <<'REMOTE'
set -e
TEXTFILE_DIR="$1"
LOGIN_USER="$(id -un)"
if ! grep -q "job_name: node" /etc/prometheus/prometheus.yml; then
  sudo tee -a /etc/prometheus/prometheus.yml >/dev/null <<'YML'

  - job_name: node
    # local prometheus-node-exporter (:9100): host metrics + textfile collector,
    # where the LIT soak feeder ships soak.prom (soak_* gauges).
    scrape_interval: 30s
    static_configs:
      - targets:
          - 127.0.0.1:9100
YML
  echo "  node scrape job appended"
else echo "  node scrape job already present"; fi
sudo promtool check config /etc/prometheus/prometheus.yml >/dev/null && echo "  promtool OK"
sudo systemctl kill -s HUP prometheus && echo "  prometheus reloaded (SIGHUP, in-place, no scrape gap)" || { sudo systemctl restart prometheus && echo "  prometheus restarted"; }
sudo mv ~/soak.prom "$TEXTFILE_DIR/soak.prom"
sudo chown "$LOGIN_USER":"$LOGIN_USER" "$TEXTFILE_DIR/soak.prom"
sudo chmod 0644 "$TEXTFILE_DIR/soak.prom"
echo "  soak.prom placed + chowned to $LOGIN_USER (feeder ships without sudo)"
sudo mkdir -p /var/lib/grafana/dashboards
sudo mv ~/lit-soak.json /var/lib/grafana/dashboards/lit-soak.json
sudo chown grafana:grafana /var/lib/grafana/dashboards/lit-soak.json 2>/dev/null || true
echo "  dashboard placed (Grafana auto-loads within 30s)"
sleep 6
echo "  up{job=node}       = $(curl -s 'http://127.0.0.1:9090/api/v1/query?query=up%7Bjob%3D%22node%22%7D' | grep -o '"value":\[[^]]*\]' | head -1)"
echo "  soak_delivery_rate = $(curl -s 'http://127.0.0.1:9090/api/v1/query?query=soak_delivery_rate' | grep -o '"value":\[[^]]*\]' | head -1)"
echo "  soak_sent_total    = $(curl -s 'http://127.0.0.1:9090/api/v1/query?query=soak_sent_total' | grep -o '"value":\[[^]]*\]' | head -1)"
REMOTE
echo "[deploy] done. Grafana dashboard uid: lit-soak. Next: Bob flips the feeder to SHIP=1."
