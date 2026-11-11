# Usage (PowerShell, from the project folder):
#   powershell -ExecutionPolicy Bypass -File .\run.ps1 all
# Steps: fetch | up | sast | sca | dast | custom | report | dashboard | all | down
param([string]$Step = "all")
$ErrorActionPreference = "Continue"
$env:PYTHONUTF8 = "1"
$Root = $PSScriptRoot; Set-Location $Root
$Raw = Join-Path $Root "results\raw"; New-Item -ItemType Directory -Force $Raw, "results\normalized", "targets" | Out-Null
$Target = if ($env:TARGET) { $env:TARGET } else { "juice-shop" }
$Url = if ($env:TARGET_URL) { $env:TARGET_URL } else { "http://localhost:3000" }

function Fetch {
  $log = Join-Path $Raw "targets.txt"; "" | Set-Content $log
  foreach ($t in @(@("juice-shop","https://github.com/juice-shop/juice-shop"), @("roundcube","https://github.com/roundcube/roundcubemail"), @("crapi","https://github.com/OWASP/crAPI"))) {
    if (-not (Test-Path "targets\$($t[0])")) { git clone --depth 1 $t[1] "targets\$($t[0])" }
    "$($t[0]) $(git -C "targets\$($t[0])" rev-parse HEAD)" | Add-Content $log
  }
}
function Up {
  docker compose up -d juice-shop roundcube
  Write-Host "Waiting for Juice Shop..."
  1..40 | ForEach-Object { try { Invoke-WebRequest $Url -UseBasicParsing -TimeoutSec 3 | Out-Null; return } catch { Start-Sleep 3 } }
}
function Sast {
  docker run --rm -v "${Root}:/src" -w /src semgrep/semgrep semgrep scan `
    --config p/owasp-top-ten --config p/javascript --config rules/semgrep `
    --sarif --output results/raw/semgrep.sarif "targets/$Target"
}
function Sca {
  docker run --rm -v "${Root}\targets\${Target}:/src" -v "${Raw}:/out" aquasec/trivy:latest fs --scanners vuln --format json --output /out/trivy.json /src
  docker run --rm -v "${Root}\targets\${Target}:/src" -v "${Raw}:/out" -w /src node:20 sh -c "npm audit --json > /out/npm-audit.json; exit 0"
}
function Dast {
  $mode = if ($env:ZAP_MODE) { $env:ZAP_MODE } else { "baseline" }
  $script = if ($mode -eq "full") { "zap-full-scan.py -T 15" } else { "zap-baseline.py" }
  # ZAP joins the compose network and reaches the app by service name
  docker run --rm --network vulnnet -v "${Raw}:/zap/wrk:rw" ghcr.io/zaproxy/zaproxy:stable `
    sh -c "$script -t http://juice-shop:3000 -J zap.json -r zap.html -I; exit 0"
}
function Custom { python scripts\custom_checks.py $Url (Join-Path $Raw "custom.json") }
function Report {
  python scripts\aggregate.py results\raw results\normalized\findings.json
  python scripts\metrics.py results\normalized\findings.json "ground_truth\$Target.json"
}
function Dashboard { python scripts\dashboard.py results\normalized\findings.json results\normalized\metrics.json results\normalized\dashboard.html }

switch ($Step) {
  "fetch"  { Fetch }  "up" { Up }  "sast" { Sast }  "sca" { Sca }
  "dast"   { Dast }   "custom" { Custom }  "report" { Report }
  "dashboard" { Dashboard }
  "down"   { docker compose down }
  "all"    { Fetch; Up; Sast; Sca; Dast; Custom; Report; Dashboard }
  default  { Write-Host "Unknown step: $Step" }
}
