#!/usr/bin/env python3
"""Aggregate allsan TP/FP labels: precision per class, and ToFu (full arm) false negatives =
allsan TP/TP-low on a tool the full arm did not flag, or flagged with a different class."""
import collections, glob, json, os, sys
HERE = os.path.dirname(os.path.abspath(__file__))
E = {}
for fn in ("allsan_evidence.json", "allsan_evidence15.json"):   # 251 set (ids 1-928) + 15 added repos (ids 1001+)
    if os.path.exists(os.path.join(HERE, fn)):
        E.update({x["id"]: x for x in json.load(open(os.path.join(HERE, fn)))})
L = {}
for f in sorted(glob.glob(os.path.join(HERE, "labels", "*.json"))):
    for x in json.load(open(f)): L[x["id"]] = x
missing = sorted(set(E) - set(L)); extra = sorted(set(L) - set(E))
out = {"n_items": len(E), "n_labelled": len(L), "missing": missing, "extra": extra}
rows = [dict(E[i], **{k: L[i][k] for k in ("label", "basis", "reason", "code_ref")}) for i in sorted(L) if i in E]
def tally(rs):
    c = collections.Counter(r["label"] for r in rs); n = len(rs)
    tp, tpl = c["TP"], c["TP-low"]
    alert_tp = sum(1 for r in rs if r["label"] == "TP" and r.get("basis") != "code-only")
    return dict(n=n, TP=tp, TP_low=tpl, FP=c["FP"], UNCLEAR=c["UNCLEAR"],
                strict_prec=round(tp / n, 3) if n else 0, lenient_prec=round((tp + tpl) / n, 3) if n else 0,
                strict_alert_grounded=alert_tp)
out["allsan_all"] = tally(rows)
out["by_class"] = {c: tally([r for r in rows if r["cls"] == c]) for c in sorted({r["cls"] for r in rows})}
shared = [r for r in rows if r["full_class"]]; new = [r for r in rows if not r["full_class"]]
out["allsan_on_tools_full_also_flagged"] = tally(shared)
out["allsan_on_tools_full_missed"] = tally(new)
# ToFu false negatives (tool-level): allsan real bug on a tool full did not flag at all
fn_strict = [r for r in new if r["label"] == "TP"]; fn_len = [r for r in new if r["label"] in ("TP", "TP-low")]
# class-level: full flagged the tool but with a different class, and allsan's class is real
fn_cls = [r for r in shared if r["full_class"] != r["cls"] and r["label"] in ("TP", "TP-low")]
out["tofu_false_negatives"] = dict(
    tool_level_strict=len(fn_strict), tool_level_lenient=len(fn_len),
    class_level_extra_lenient=len(fn_cls),
    strict_by_class=dict(collections.Counter(r["cls"] for r in fn_strict)),
    lenient_by_class=dict(collections.Counter(r["cls"] for r in fn_len)),
    strict_repos=sorted({r["repo"] for r in fn_strict}),
    strict_items=[dict(repo=r["repo"], tool=r["tool"], cls=r["cls"], basis=r["basis"], reason=r["reason"]) for r in fn_strict])
json.dump(out, open(os.path.join(HERE, "allsan_label_summary.json"), "w"), indent=1)
json.dump(rows, open(os.path.join(HERE, "allsan_labels_joined.json"), "w"), indent=1)
print(json.dumps({k: v for k, v in out.items() if k != "tofu_false_negatives"}, indent=1))
fn = dict(out["tofu_false_negatives"]); fn.pop("strict_items"); print(json.dumps(fn, indent=1))
