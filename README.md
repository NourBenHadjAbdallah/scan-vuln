# Plateforme de détection de vulnérabilités (SAST + DAST + SCA)
Démarrage : `make fetch up scan report` → `results/normalized/{findings,metrics}.json`.
Avant/après : copier `findings.json` en `before.json`, modifier le code/règles, relancer, puis `make compare`.
Cibles : `TARGET=roundcube TARGET_URL=http://localhost:8081 make scan` (ajouter `ground_truth/roundcube.json`).
SonarQube : `docker compose --profile sonar up -d`, créer un token, `SONAR_TOKEN=... scripts/scan.sh sonar`.
Limite des métriques : un finding hors vérité terrain est compté FP (borne haute) ; enrichir `ground_truth/`.
