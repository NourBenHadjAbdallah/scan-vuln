#!/usr/bin/env python3
"""Tableau de bord HTML autonome (aucun serveur, aucune dépendance).
Usage: dashboard.py [findings.json] [metrics.json] [dashboard.html]"""
import json, sys, pathlib, datetime

F = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "results/normalized/findings.json")
M = pathlib.Path(sys.argv[2] if len(sys.argv) > 2 else "results/normalized/metrics.json")
OUT = pathlib.Path(sys.argv[3] if len(sys.argv) > 3 else "results/normalized/dashboard.html")

findings = json.load(open(F, encoding="utf-8"))
metrics = json.load(open(M, encoding="utf-8")) if M.exists() else {}
data = dict(findings=findings, metrics=metrics,
            generated=datetime.datetime.now().strftime("%d/%m/%Y %H:%M"),
            source=str(F).replace("\\", "/"))
blob = json.dumps(data, ensure_ascii=False).replace("</", "<\\/")

HTML = r"""<!doctype html>
<html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Tableau de bord — détection de vulnérabilités</title>
<style>
:root{--navy:#0d1b2a;--ink:#1f2933;--muted:#5f6c7b;--pale:#eef3f6;--line:#dbe3e9;--teal:#1b9aaa;
--critical:#7b1e2b;--high:#d7263d;--medium:#f4a300;--low:#1b9aaa;--info:#a9b4be}
*{box-sizing:border-box}body{margin:0;font:15px/1.45 "Segoe UI",Calibri,Arial,sans-serif;color:var(--ink);background:#f6f8fa}
header{background:var(--navy);color:#fff;padding:22px 32px}header h1{margin:0;font-size:24px}header p{margin:4px 0 0;color:#b9c6d2;font-size:13px}
main{max-width:1280px;margin:0 auto;padding:24px 32px 48px}
h2{font-size:17px;margin:0 0 14px;color:var(--navy)}
.grid{display:grid;gap:16px}.kpis{grid-template-columns:repeat(auto-fit,minmax(170px,1fr));margin-bottom:16px}
.two{grid-template-columns:repeat(auto-fit,minmax(420px,1fr));margin-bottom:16px}
.card{background:#fff;border:1px solid var(--line);border-radius:10px;padding:18px 20px}
.kpi .v{font-size:38px;font-weight:700;line-height:1.1;color:var(--navy)}.kpi .l{color:var(--muted);font-size:13px;margin-top:4px}
.kpi.crit .v{color:var(--critical)}.kpi.high .v{color:var(--high)}
table{width:100%;border-collapse:collapse;font-size:14px}th{text-align:left;color:var(--muted);font-weight:600;font-size:12px;text-transform:uppercase;letter-spacing:.04em;padding:6px 8px;border-bottom:2px solid var(--line)}
td{padding:8px;border-bottom:1px solid var(--line);vertical-align:top}td.n,th.n{text-align:right;font-variant-numeric:tabular-nums}
.bar{height:12px;background:var(--pale);border-radius:6px;overflow:hidden;min-width:120px}.bar i{display:block;height:100%;background:var(--teal)}
.stack{display:flex;height:26px;border-radius:6px;overflow:hidden;background:var(--pale)}.stack span{display:block;height:100%}
.row{display:grid;grid-template-columns:70px 1fr 44px;gap:12px;align-items:center;margin-bottom:12px;font-weight:600}
.row b{text-align:right;font-variant-numeric:tabular-nums}
.legend{display:flex;flex-wrap:wrap;gap:14px;font-size:13px;color:var(--muted);margin-top:6px}.legend i{display:inline-block;width:11px;height:11px;border-radius:3px;margin-right:6px;vertical-align:-1px}
.pill{display:inline-block;padding:2px 9px;border-radius:999px;font-size:12px;font-weight:700;color:#fff;white-space:nowrap}
.pill.medium{color:#3b2a00}.pill.info{color:#1f2933}
.chip{display:inline-block;background:var(--pale);border-radius:6px;padding:3px 9px;margin:0 6px 6px 0;font:13px Consolas,monospace}
.filters{display:flex;flex-wrap:wrap;gap:10px;margin-bottom:12px}
select,input{font:inherit;padding:7px 10px;border:1px solid var(--line);border-radius:6px;background:#fff;color:var(--ink)}input{flex:1;min-width:220px}
.loc{font:12.5px Consolas,monospace;color:var(--muted);word-break:break-all}.muted{color:var(--muted);font-size:13px}
#metrics td:first-child,#rows td:nth-child(2),#rows td:nth-child(3){white-space:nowrap}
.scroll{max-height:560px;overflow:auto}thead th{position:sticky;top:0;background:#fff}
</style></head><body>
<header><h1>Tableau de bord — détection de vulnérabilités</h1><p id="sub"></p></header>
<main>
<section class="grid kpis" id="kpis"></section>
<section class="grid two">
  <div class="card"><h2>Qualité de chaque outil face à la vérité terrain</h2><div id="metrics"></div></div>
  <div class="card"><h2>Constats par famille et sévérité</h2><div id="sev"></div><div class="legend" id="legend"></div></div>
</section>
<section class="grid two">
  <div class="card"><h2>Types de faiblesses les plus fréquents (CWE)</h2><div id="cwe"></div></div>
  <div class="card"><h2>Vulnérabilités connues non détectées</h2><div id="missed"></div></div>
</section>
<section class="card"><h2>Tous les constats</h2>
  <div class="filters"><select id="fTool"></select><select id="fSev"></select><select id="fCat"></select><input id="fText" placeholder="Rechercher dans le titre, la règle, la localisation…"></div>
  <div class="muted" id="count"></div>
  <div class="scroll"><table><thead><tr><th>Sévérité</th><th>Outil</th><th>CWE</th><th>Titre</th><th>Localisation</th></tr></thead><tbody id="rows"></tbody></table></div>
</section>
</main>
<script id="data" type="application/json">__DATA__</script>
<script>
const D = JSON.parse(document.getElementById("data").textContent), F = D.findings, M = D.metrics;
const SEV = ["critical","high","medium","low","info"], SEVFR = {critical:"Critique",high:"Élevée",medium:"Moyenne",low:"Faible",info:"Info"};
const CAT = ["sast","sca","dast"], col = s => getComputedStyle(document.documentElement).getPropertyValue("--"+s).trim();
const el = (t, c, txt) => { const e = document.createElement(t); if (c) e.className = c; if (txt !== undefined) e.textContent = txt; return e; };
const count = (arr, key) => arr.reduce((m, x) => (m[x[key] ?? "—"] = (m[x[key] ?? "—"] || 0) + 1, m), {});
const fr = n => String(n).replace(".", ",");

document.getElementById("sub").textContent = "Généré le " + D.generated + " à partir de " + D.source + " · " + F.length + " constats";

// KPI
const bySev = count(F, "severity"), tools = Object.keys(count(F, "tool"));
[["", F.length, "constats au total"], ["crit", bySev.critical || 0, "critiques"], ["high", bySev.high || 0, "élevés"], ["", tools.length, "outils ayant remonté des résultats"],
 ["", Object.keys(count(F.filter(f => f.cwe), "cwe")).length, "types de faiblesses (CWE)"]].forEach(([c, v, l]) => {
  const k = el("div", "card kpi " + c); k.append(el("div", "v", v), el("div", "l", l)); document.getElementById("kpis").append(k); });

// Métriques
const mt = document.getElementById("metrics");
if (!Object.keys(M).length) mt.append(el("p", "muted", "metrics.json absent : lancez l'étape report."));
else { const t = el("table"), h = el("tr");
  ["Outil","Famille","Constats","TP","FP","FN","Précision","Rappel",""].forEach((x, i) => h.append(el("th", i > 1 && i < 8 ? "n" : "", x)));
  t.append(h);
  Object.entries(M).sort((a, b) => b[1].recall - a[1].recall).forEach(([name, m]) => { const r = el("tr");
    r.append(el("td", "", name), el("td", "", m.category.toUpperCase()));
    [m.findings, m.TP, m.FP, m.FN, fr(m.precision.toFixed(2)), Math.round(m.recall * 100) + " %"].forEach(v => r.append(el("td", "n", v)));
    const b = el("td"), bar = el("div", "bar"), i = el("i"); i.style.width = (m.recall * 100) + "%"; bar.append(i); b.append(bar); r.append(b); t.append(r); });
  mt.append(t, el("p", "muted", "Rappel = part des vulnérabilités connues retrouvées. La précision est une borne basse : tout constat hors vérité terrain compte comme faux positif.")); }

// Sévérité par famille
const sv = document.getElementById("sev"), maxCat = Math.max(...CAT.map(c => F.filter(f => f.category === c).length), 1);
CAT.forEach(c => { const fs = F.filter(f => f.category === c), row = el("div", "row"), st = el("div", "stack"), s = count(fs, "severity");
  st.style.width = Math.max(fs.length / maxCat * 100, 2) + "%";
  SEV.forEach(k => { if (s[k]) { const sp = el("span"); sp.style.width = (s[k] / fs.length * 100) + "%"; sp.style.background = col(k); sp.title = SEVFR[k] + " : " + s[k]; st.append(sp); } });
  row.append(el("span", "", c.toUpperCase()), st, el("b", "", fs.length)); sv.append(row); });
SEV.forEach(k => { const s = el("span"), i = el("i"); i.style.background = col(k); s.append(i, SEVFR[k] + " (" + (bySev[k] || 0) + ")"); document.getElementById("legend").append(s); });

// CWE
const cw = Object.entries(count(F.filter(f => f.cwe), "cwe")).sort((a, b) => b[1] - a[1]).slice(0, 8), cmax = cw.length ? cw[0][1] : 1, ct = el("table");
cw.forEach(([k, v]) => { const r = el("tr"), b = el("td"), bar = el("div", "bar"), i = el("i"); i.style.width = (v / cmax * 100) + "%"; bar.append(i); b.append(bar);
  r.append(el("td", "", k), b, el("td", "n", v)); ct.append(r); });
document.getElementById("cwe").append(ct);

// Manqués
const ms = document.getElementById("missed"); let any = false;
Object.entries(M).forEach(([name, m]) => { if (m.missed && m.missed.length) { any = true; const p = el("p"); p.append(el("b", "", name + " : ")); m.missed.forEach(x => p.append(el("span", "chip", x))); ms.append(p); } });
if (!any) ms.append(el("p", "muted", Object.keys(M).length ? "Aucune." : "metrics.json absent."));
else ms.append(el("p", "muted", "Ces identifiants viennent de la vérité terrain : ce sont les règles ou modes de scan à ajouter en priorité."));

// Table
const opt = (id, label, vals, names) => { const s = document.getElementById(id); s.append(new Option(label, "")); vals.forEach(v => s.append(new Option(names ? names[v] : v, v))); };
opt("fTool", "Tous les outils", tools); opt("fSev", "Toutes les sévérités", SEV.filter(s => bySev[s]), SEVFR); opt("fCat", "Toutes les familles", CAT.filter(c => F.some(f => f.category === c)));
const order = Object.fromEntries(SEV.map((s, i) => [s, i])), sorted = [...F].sort((a, b) => order[a.severity] - order[b.severity]);
function render() { const t = fTool.value, s = fSev.value, c = fCat.value, q = fText.value.toLowerCase(), tb = document.getElementById("rows"); tb.textContent = "";
  const list = sorted.filter(f => (!t || f.tool === t) && (!s || f.severity === s) && (!c || f.category === c) && (!q || (f.title + " " + f.rule + " " + f.location).toLowerCase().includes(q)));
  list.forEach(f => { const r = el("tr"), p = el("span", "pill " + f.severity, SEVFR[f.severity] || f.severity); p.style.background = col(f.severity);
    const a = el("td"); a.append(p); r.append(a, el("td", "", f.tool), el("td", "", f.cwe || "—"), el("td", "", f.title), el("td", "loc", f.location)); tb.append(r); });
  document.getElementById("count").textContent = list.length + " constat(s) affiché(s) sur " + F.length; }
const fTool = document.getElementById("fTool"), fSev = document.getElementById("fSev"), fCat = document.getElementById("fCat"), fText = document.getElementById("fText");
[fTool, fSev, fCat].forEach(x => x.onchange = render); fText.oninput = render; render();
</script></body></html>
"""
OUT.parent.mkdir(parents=True, exist_ok=True)
OUT.write_text(HTML.replace("__DATA__", blob), encoding="utf-8")
print(f"dashboard -> {OUT} ({len(findings)} findings, {len(metrics)} tools)")
