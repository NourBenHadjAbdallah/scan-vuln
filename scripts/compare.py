#!/usr/bin/env python3
"""Compare deux runs (avant/après correctif, nouvelle règle, etc.). Usage: compare.py before.json after.json [out_prefix]"""
import json, sys, html, collections
b, a = json.load(open(sys.argv[1])), json.load(open(sys.argv[2]))
pre = sys.argv[3] if len(sys.argv) > 3 else "results/normalized/diff"
fb, fa = {f["fingerprint"]: f for f in b}, {f["fingerprint"]: f for f in a}
new = [fa[k] for k in fa.keys() - fb.keys()]; fixed = [fb[k] for k in fb.keys() - fa.keys()]; kept = [fa[k] for k in fa.keys() & fb.keys()]
cnt = lambda L: collections.Counter(f["tool"] for f in L)
summary = dict(before=len(b), after=len(a), new=len(new), fixed=len(fixed), persisting=len(kept),
               by_tool=dict(new=cnt(new), fixed=cnt(fixed), persisting=cnt(kept)))
json.dump(dict(summary=summary, new=new, fixed=fixed), open(pre + ".json", "w"), indent=2, ensure_ascii=False)
row = lambda f, c: f"<tr class={c}><td>{f['tool']}<td>{f['severity']}<td>{html.escape(f['title'])}<td>{html.escape(f['location'])}"
rows = "".join(row(f, "new") for f in new) + "".join(row(f, "fixed") for f in fixed)
open(pre + ".html", "w").write(f"""<meta charset=utf-8><style>body{{font:14px sans-serif;margin:2em}}td{{padding:4px 8px;border-bottom:1px solid #ddd}}
.new{{background:#fde8e8}}.fixed{{background:#e6f6e6}}</style><h2>Comparaison avant / après</h2>
<p>Avant: {len(b)} · Après: {len(a)} · <b style=color:#b00>Nouveaux: {len(new)}</b> · <b style=color:#080>Corrigés: {len(fixed)}</b> · Persistants: {len(kept)}</p>
<table><tr><th>Outil<th>Sévérité<th>Titre<th>Localisation{rows}</table>""")
print(json.dumps(summary, indent=2))
