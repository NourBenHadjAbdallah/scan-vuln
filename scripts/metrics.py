#!/usr/bin/env python3
"""Précision / rappel / F1 par outil vs vérité terrain. Usage: metrics.py findings.json ground_truth.json [out.json]"""
import json, sys
F, GT = json.load(open(sys.argv[1])), json.load(open(sys.argv[2]))
def match(f, g):
    return (f["category"] == g["category"] and (not g.get("cwe") or f.get("cwe") == g["cwe"])
            and (not g.get("hint") or g["hint"].lower() in f["location"].lower()))
res = {}
for tool in sorted({f["tool"] for f in F}):
    fs = [f for f in F if f["tool"] == tool]; cat = fs[0]["category"]
    gts = [g for g in GT if g["category"] == cat]
    det = [g for g in gts if any(match(f, g) for f in fs)]
    tp = [f for f in fs if any(match(f, g) for g in gts)]
    p = len(tp) / len(fs); r = len(det) / len(gts) if gts else 0
    res[tool] = dict(category=cat, findings=len(fs), TP=len(tp), FP=len(fs) - len(tp), ground_truth=len(gts), detected=len(det),
                     FN=len(gts) - len(det), precision=round(p, 3), recall=round(r, 3),
                     f1=round(2 * p * r / (p + r), 3) if p + r else 0, missed=[g["id"] for g in gts if g not in det])
json.dump(res, open(sys.argv[3] if len(sys.argv) > 3 else "results/normalized/metrics.json", "w"), indent=2)
print(f"{'tool':<10}{'cat':<6}{'find':>5}{'TP':>5}{'FP':>5}{'FN':>4}{'prec':>7}{'rec':>7}{'F1':>7}")
for t, m in res.items():
    print(f"{t:<10}{m['category']:<6}{m['findings']:>5}{m['TP']:>5}{m['FP']:>5}{m['FN']:>4}{m['precision']:>7}{m['recall']:>7}{m['f1']:>7}")
