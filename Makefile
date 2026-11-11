up:      ; docker compose up -d juice-shop roundcube && bash scripts/deploy_crapi.sh
fetch:   ; bash scripts/fetch_targets.sh
scan:    ; bash scripts/scan.sh sast && bash scripts/scan.sh sca && bash scripts/scan.sh dast && bash scripts/scan.sh custom
report:  ; python3 scripts/aggregate.py && python3 scripts/metrics.py results/normalized/findings.json ground_truth/juice-shop.json
# make compare BEFORE=results/normalized/before.json AFTER=results/normalized/findings.json
compare: ; python3 scripts/compare.py $(BEFORE) $(AFTER)
