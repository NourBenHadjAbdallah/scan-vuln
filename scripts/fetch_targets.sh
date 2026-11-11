#!/usr/bin/env bash
# Clone les sources des cibles (SAST/SCA) et enregistre le commit exact (reproductibilité).
set -e; mkdir -p targets results/raw
clone(){ [ -d "targets/$1" ] || git clone --depth 1 ${3:+--branch $3} "$2" "targets/$1"; echo "$1 $(git -C targets/$1 rev-parse HEAD)" >> results/raw/targets.txt; }
: > results/raw/targets.txt
clone juice-shop https://github.com/juice-shop/juice-shop "${JUICE_REF:-}"
clone roundcube  https://github.com/roundcube/roundcubemail "${ROUNDCUBE_REF:-}"
clone crapi      https://github.com/OWASP/crAPI "${CRAPI_REF:-}"
