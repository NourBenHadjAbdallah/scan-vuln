#!/usr/bin/env bash
# Usage: TARGET=juice-shop TARGET_URL=http://localhost:3000 scripts/scan.sh sast|sonar|sca|dast|custom
set -uo pipefail
T=${TARGET:-juice-shop}; ROOT=$PWD; SRC=$ROOT/targets/$T; RAW=$ROOT/results/raw; mkdir -p "$RAW"; chmod 777 "$RAW"
URL=${TARGET_URL:-http://localhost:3000}
case "$1" in
  sast)
    semgrep scan --config p/owasp-top-ten --config p/javascript --config rules/semgrep --sarif --output "$RAW/semgrep.sarif" "$SRC" ;;
  sonar)   # nécessite SONAR_TOKEN + profil compose "sonar"
    docker run --rm --network host -v "$SRC:/usr/src" -e SONAR_HOST_URL="${SONAR_HOST_URL:-http://localhost:9000}" -e SONAR_TOKEN \
      sonarsource/sonar-scanner-cli -Dsonar.projectKey="$T"
    curl -s -u "$SONAR_TOKEN:" "${SONAR_HOST_URL:-http://localhost:9000}/api/issues/search?componentKeys=$T&ps=500" > "$RAW/sonarqube.json" ;;
  sca)
    docker run --rm -v "$SRC:/src" aquasec/trivy:latest fs --scanners vuln --format json /src > "$RAW/trivy.json"
    (cd "$SRC" && npm audit --json > "$RAW/npm-audit.json") ;;
  dast)
    MODE=${ZAP_MODE:-baseline}   # baseline (passif, rapide) | full (actif)
    docker run --rm --network host -v "$RAW:/zap/wrk:rw" ghcr.io/zaproxy/zaproxy:stable \
      $( [ "$MODE" = full ] && echo "zap-full-scan.py -T 15" || echo "zap-baseline.py" ) -t "$URL" -J zap.json -r zap.html -I ;;
  custom)
    python3 scripts/custom_checks.py "$URL" "$RAW/custom.json" ;;
  *) echo "usage: $0 sast|sonar|sca|dast|custom"; exit 2 ;;
esac
exit 0
