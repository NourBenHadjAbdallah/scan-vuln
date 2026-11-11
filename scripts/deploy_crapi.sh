#!/usr/bin/env bash
set -e; bash "$(dirname "$0")/fetch_targets.sh"
docker compose -f targets/crapi/deploy/docker/docker-compose.yml --compatibility up -d   # UI: :8888, MailHog: :8025
