#!/usr/bin/env python3
"""Populate `file_backed_params` (and matching `predefined_seeds`) in the
per-tool configs.

WHY THIS EXISTS
---------------
All 173 configs ship `predefined_seeds: []` and no `file_backed_params`, and
`src/__main__.py` did not even read that key -- so ToFu's whole file-backed
path (`src/predefined_seeds/`, `FuzzFileManager`, the `predefined_seed:<name>`
protocol) was DEAD in the eval harness, though `targets/fuzz_*.py` used it.

The consequence, measured 2026-09-10 on ArchimedesCrypto/excel-reader-mcp:
a tool taking a file path receives the literal string the seed mapper produced
("test") and answers

    MCP error -32600: File not found: test

on EVERY input. The tool never executes, no sanitizer can fire, and the run
reports a healthy "0 findings". It is also why the paper's binary-seed claim
(create_pdf/docx/zip -> "predefined_seed:<name>") has never been observed
working: nothing ever enabled it.

REPORT FIRST, APPLY SECOND
--------------------------
Marking a parameter file-backed CHANGES WHAT THE TOOL RECEIVES: the value is
replaced by a path to a temp file. A false positive (a `path` that is really a
URL path, or a workspace-relative key) would silently corrupt that tool's
inputs. So this prints its proposal and does nothing unless given --apply.

    python3 eval/infer_file_params.py              # propose, change nothing
    python3 eval/infer_file_params.py --apply      # write the configs
    python3 eval/infer_file_params.py --revert     # restore from the backups
"""
import argparse, glob, json, os, re, shutil, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.environ.setdefault("OLLAMA_CLOUD_API_KEY", "ollama")
SEED_DIR = os.path.join(ROOT, "src/predefined_seeds")

# A property is file-backed only if its NAME looks like a file handle. Matching
# on the description too was tried and pulled in far too much ("...the path of
# the URL...").
NAME_RX = re.compile(
    r"(^|_)(file|filepath|file_path|filename|file_name|path|doc|document|"
    r"attachment|upload|source_file|input_file|workbook|spreadsheet)($|_)", re.I)
# `path` is ambiguous. Require a file-ish signal in the tool or property text.
AMBIGUOUS = {"path", "source", "input"}
FILEISH_RX = re.compile(
    r"\b(file|excel|xlsx|csv|pdf|docx|word|pptx|zip|archive|json|xml|html|"
    r"markdown|\.md|har|workbook|spreadsheet|document|read|parse|convert|load)\b", re.I)

EXT_HINTS = [
    (r"\bxlsx?\b|\bexcel\b|\bworkbook\b|\bspreadsheet\b", ".xlsx"),
    (r"\bcsv\b", ".csv"), (r"\bpdf\b", ".pdf"),
    (r"\bdocx?\b|\bword\b", ".docx"), (r"\bpptx?\b|\bpowerpoint\b", ".pptx"),
    (r"\bzip\b|\barchive\b", ".zip"), (r"\bhar\b", ".har"),
    (r"\bjson\b", ".json"), (r"\bxml\b", ".xml"),
    (r"\bhtml?\b", ".html"), (r"\bmarkdown\b|\.md\b", ".md"),
]
SEED_FOR_EXT = {
    ".xlsx": "sample.xlsx", ".pdf": "sample.pdf", ".docx": "sample.docx",
    ".pptx": "sample.pptx", ".zip": "sample.zip", ".json": "sample.json",
    ".xml": "sample.xml", ".html": "sample.html",
}


def extensions_for(text):
    exts = [e for rx, e in EXT_HINTS if re.search(rx, text or "", re.I)]
    # No hint at all: offer a spread so FuzzFileManager's byte-driven picker
    # can explore formats rather than pinning one arbitrary guess.
    return exts or [".txt", ".json", ".xml", ".html", ".csv"]


def infer(prop, attrs, tool_name, tool_desc):
    if (attrs or {}).get("type", "string") != "string":
        return None
    if (attrs or {}).get("enum"):
        return None
    if not NAME_RX.search(prop):
        return None
    context = f"{tool_name} {tool_desc} {prop} {(attrs or {}).get('description','')}"
    if prop.lower() in AMBIGUOUS and not FILEISH_RX.search(context):
        return None
    return {"extension": extensions_for(context), "prefix": f"fuzz_{prop}_"}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--revert", action="store_true")
    a = ap.parse_args()

    cfgs = sorted(glob.glob(os.path.join(ROOT, "eval/configs/*.json")))
    if a.revert:
        n = 0
        for c in cfgs:
            b = c + ".bak-preFileParams"
            if os.path.exists(b):
                shutil.copy(b, c); os.remove(b); n += 1
        print(f"reverted {n} config(s)"); return

    from src.client import MCPInspector
    by_repo = {}
    for c in cfgs:
        by_repo.setdefault(json.load(open(c))["_repo"], []).append(c)

    changed = unreachable = 0
    for repo, files in sorted(by_repo.items()):
        cfg0 = json.load(open(files[0]))
        try:
            insp = MCPInspector(command=cfg0["command"], args=cfg0["args"])
            tools = {t["name"]: t for t in insp._query_server() if t.get("name")}
        except Exception as e:
            print(f"  !! {repo}: cannot reach server ({type(e).__name__}: {e}); skipped")
            unreachable += len(files); continue
        for c in files:
            cfg = json.load(open(c))
            t = tools.get(cfg["target_tool"])
            if not t:
                continue
            props = ((t.get("inputSchema") or {}).get("properties") or {})
            fbp = {}
            for prop, attrs in props.items():
                spec = infer(prop, attrs, cfg["target_tool"], t.get("description", ""))
                if spec:
                    fbp[prop] = spec
            if not fbp:
                continue
            # DO NOT touch predefined_seeds. fuzzer._setup_corpus_seeds does
            #     if self.predefined_seeds: seeds = self.predefined_seeds
            #     else:                     seeds = llm.generate_seeds(...)
            # so a non-empty predefined_seeds REPLACES the LLM stage -- ToFu's
            # central claim -- and it expects full ARGUMENT OBJECTS, not
            # filenames. Setting it to ['sample.xlsx'] wrote a single corpus
            # entry containing the JSON string "sample.xlsx"; libFuzzer reported
            # "seed corpus: files: 1", no LLM_SEEDGEN marker was emitted at all,
            # and excel-reader::get_cell logged
            #     EXEC_SUMMARY n_exec=15872 n_success=0
            #     EXEC_ERROR n=48337 detail='Invalid cell address: '
            # i.e. strictly worse than before. Measured 2026-09-10, reverted.
            # file_backed_params alone is what this script may set.
            seeds = []
            changed += 1
            print(f"  {os.path.basename(c)}")
            for k, v in fbp.items():
                print(f"      {k}: {v['extension']}")
            if seeds:
                print(f"      predefined_seeds: {seeds}")
            if a.apply:
                if not os.path.exists(c + ".bak-preFileParams"):
                    shutil.copy(c, c + ".bak-preFileParams")
                cfg["file_backed_params"] = fbp
                cfg["predefined_seeds"] = seeds
                json.dump(cfg, open(c, "w"), indent=1)

    print(f"\n{changed} config(s) would gain file_backed_params "
          f"({unreachable} skipped: server unreachable) out of {len(cfgs)}")
    print("APPLIED." if a.apply else "DRY RUN -- nothing written. Re-run with --apply.")


if __name__ == "__main__":
    main()
