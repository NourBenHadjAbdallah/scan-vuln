#!/usr/bin/env python3
"""Normalise les sorties brutes (Semgrep SARIF, SonarQube, ZAP, Trivy, npm audit, custom) en un JSON unique."""
import json, sys, re, hashlib, pathlib
RAW = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "results/raw")
OUT = pathlib.Path(sys.argv[2] if len(sys.argv) > 2 else "results/normalized/findings.json")
SEV = {"blocker": "critical", "critical": "critical", "high": "high", "error": "high", "major": "medium", "medium": "medium",
       "warning": "medium", "moderate": "medium", "minor": "low", "low": "low", "note": "low"}
sev = lambda s: SEV.get(str(s).lower(), "info")
def cwe_of(x):
    m = re.search(r"CWE-(\d+)", str(x), re.I); return f"CWE-{m.group(1)}" if m else None
def mk(tool, cat, rule, title, severity, cwe, loc):
    return dict(tool=tool, category=cat, rule=str(rule), title=str(title)[:140], severity=sev(severity), cwe=cwe, location=loc)

def semgrep(p):
    for run in json.load(open(p)).get("runs", []):
        rules = {r["id"]: r for r in run["tool"]["driver"].get("rules", [])}
        for r in run.get("results", []):
            tags = rules.get(r["ruleId"], {}).get("properties", {}).get("tags", [])
            l = r["locations"][0]["physicalLocation"]
            yield mk("semgrep", "sast", r["ruleId"], r["message"]["text"], r.get("level", "warning"),
                     next((cwe_of(t) for t in tags if cwe_of(t)), None),
                     f"{l['artifactLocation']['uri']}:{l.get('region', {}).get('startLine', 0)}")
def sonar(p):
    for i in json.load(open(p)).get("issues", []):
        yield mk("sonarqube", "sast", i["rule"], i["message"], i.get("severity"), None, f"{i['component'].split(':',1)[-1]}:{i.get('line', 0)}")
def trivy(p):
    for res in json.load(open(p)).get("Results", []):
        for v in res.get("Vulnerabilities") or []:
            yield mk("trivy", "sca", v["VulnerabilityID"], f"{v['PkgName']}@{v['InstalledVersion']}: {v.get('Title','')}",
                     v.get("Severity"), (v.get("CweIDs") or [None])[0], f"{res['Target']}::{v['PkgName']}")
def npm(p):
    for name, v in json.load(open(p)).get("vulnerabilities", {}).items():
        for via in v.get("via", []):
            if isinstance(via, dict):
                yield mk("npm-audit", "sca", via.get("source"), f"{name}: {via.get('title','')}", via.get("severity"),
                         (via.get("cwe") or [None])[0], f"package.json::{name}")
def zap(p):
    for s in json.load(open(p)).get("site", []):
        for a in s.get("alerts", []):
            c = a.get("cweid"); c = f"CWE-{c}" if c not in (None, "", "-1", "0") else None
            for i in (a.get("instances") or [{}])[:25]:
                yield mk("zap", "dast", a["pluginid"], a["alert"], ["info", "low", "medium", "high"][int(a.get("riskcode", 0))], c, i.get("uri", s["@name"]))
def custom(p):
    for f in json.load(open(p)): yield f

PARSERS = {"semgrep.sarif": semgrep, "sonarqube.json": sonar, "trivy.json": trivy, "npm-audit.json": npm, "zap.json": zap, "custom.json": custom}
out = []
for name, fn in PARSERS.items():
    if (RAW / name).exists():
        try: out += list(fn(RAW / name))
        except Exception as e: print(f"! {name}: {e}", file=sys.stderr)
for f in out:  # empreinte stable (sans numéro de ligne) pour la comparaison avant/après
    f["fingerprint"] = hashlib.sha1(f"{f['tool']}|{f['rule']}|{re.sub(r':\\d+$','',f['location'])}".encode()).hexdigest()[:12]
OUT.parent.mkdir(parents=True, exist_ok=True)
json.dump(out, open(OUT, "w"), indent=2, ensure_ascii=False)
by = {}
for f in out: by[f["tool"]] = by.get(f["tool"], 0) + 1
print(len(out), "findings:", by)
