#!/usr/bin/env python3
"""Détecteur complémentaire (DAST léger) : endpoints exposés, en-têtes manquants, CORS permissif, erreurs SQL."""
import sys, json, urllib.request, urllib.error
base, out = sys.argv[1].rstrip("/"), sys.argv[2]
F = []
def add(rule, title, sev, cwe, loc):
    F.append(dict(tool="custom", category="dast", rule=rule, title=title, severity=sev, cwe=cwe, location=loc))
def get(path, headers=None):
    try:
        r = urllib.request.urlopen(urllib.request.Request(base + path, headers=headers or {}), timeout=10)
        return r.status, {k.lower(): v for k, v in r.headers.items()}, r.read(3000).decode("utf-8", "ignore")
    except urllib.error.HTTPError as e:
        return e.code, {k.lower(): v for k, v in e.headers.items()}, e.read(3000).decode("utf-8", "ignore")
    except Exception:
        return 0, {}, ""
EXPOSED = {"/ftp": "CWE-548", "/metrics": "CWE-200", "/api-docs": "CWE-200", "/.git/HEAD": "CWE-527",
           "/.env": "CWE-538", "/rest/admin/application-version": "CWE-200",
           "/rest/admin/application-configuration": "CWE-200", "/server-status": "CWE-200"}
for p, cwe in EXPOSED.items():
    s, _, _ = get(p)
    if s == 200: add("custom-exposed-endpoint", f"Endpoint sensible accessible: {p}", "medium", cwe, p)
s, h, _ = get("/")
for hd, cwe in {"content-security-policy": "CWE-693", "x-content-type-options": "CWE-693",
                "strict-transport-security": "CWE-319", "x-frame-options": "CWE-1021"}.items():
    if s and hd not in h: add("custom-missing-header", f"En-tête manquant: {hd}", "low", cwe, "/")
_, h, _ = get("/", {"Origin": "https://evil.example"})
if h.get("access-control-allow-origin") in ("*", "https://evil.example"):
    add("custom-cors", "CORS permissif (origine arbitraire acceptée)", "medium", "CWE-942", "/")
_, _, b = get("/rest/products/search?q=%27")
if any(k in b for k in ("SQLITE_ERROR", "SQLSTATE", "syntax error")):
    add("custom-sqli-error", "Erreur SQL exposée (injection probable)", "high", "CWE-89", "/rest/products/search")
json.dump(F, open(out, "w"), indent=2, ensure_ascii=False); print(f"{len(F)} findings -> {out}")
