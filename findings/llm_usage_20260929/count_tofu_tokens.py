import json,glob,os,ast,re,collections,statistics,inspect,sys
import tiktoken
WT=sys.argv[1]; S=sys.argv[2]
enc=tiktoken.get_encoding("o200k_base"); T=lambda s: len(enc.encode(s))
src=open(f'{WT}/src/sanitizers/__init__.py').read()
i=src.index('AVAILABLE_SANITIZERS = {'); j=src.index('\n}',i)+2
AV=ast.literal_eval(src[i+len('AVAILABLE_SANITIZERS = '):j])
san_fmt="\n".join(f"- {k}: {v}" for k,v in AV.items())
llm=open(f'{WT}/src/llm.py').read()
a=llm.index('prompt = f"""\nYou are an expert security engineer'); b=llm.index('"""',a+15); SEL=llm[a+len('prompt = f"""'):b]
a=llm.index('prompt = f"""\nYou are a security and QA'); b=llm.index('\n"""',a+15); SEED=llm[a+len('prompt = f"""'):b]+"\n"
bank={os.path.basename(f)[:-5]:json.load(open(f)) for f in glob.glob(f'{WT}/src/seed_bank/*.json')}
# categories_for_sanitizers from llm.py
ns={}; k=llm.index('SANITIZER_SEED_CATEGORIES = ['); e=llm.index('\nclass ',k)
exec(llm[k:e],ns); cats=ns['categories_for_sanitizers']
# file-builder tool schemas as bound (name + docstring + params), approximated from source
fb=[]
for name in ['create_pdf','create_docx','create_xlsx','create_pptx','create_zip','create_xml','create_html','create_json']:
    m=re.search(r'def '+name+r'\(([^)]*)\)[^:]*:\s*"""(.*?)"""',llm,re.S)
    fb.append({"type":"function","function":{"name":name,"description":m.group(2).strip(),"parameters":{"type":"object","properties":{p.split(':')[0].strip():{"type":"string"} for p in m.group(1).split(',') if p.strip()}}}})
FB_TOK=T(json.dumps(fb))
defs=collections.defaultdict(list)
for d in json.load(open(f'{S}/viper_tooldefs.json')): defs[d['name']].append(d)
# cisco descriptions
cdesc={}
for f in glob.glob(f'{S}/cisco/c273/*.json'):
    if f.endswith('.behavioral.json'): continue
    try: d=json.load(open(f))
    except Exception: continue
    repo=os.path.basename(f)[:-5]
    for r in d.get('scan_results') or []: cdesc[(repo,r.get('tool_name'))]=r.get('tool_description') or ''
tot=collections.Counter(); per=[]; src_meta=collections.Counter()
for f in sorted(glob.glob(f'{S}/tofucache/llm_cache_ablation/*.json')):
    key=os.path.basename(f)[:-5]; repo,tool=key.split('__',1)[0]+'__'+key.split('__')[1], key.split('__',2)[2]
    c=json.load(open(f)); sel=c.get('selected_sanitizers') or []; rules=c.get('rules') or {}; seeds=c.get('seeds') or []
    seedkeys=set()
    for s in seeds:
        if isinstance(s,dict): seedkeys|=set(s)
    cand=defs.get(tool,[])
    best=None
    for d in cand:
        props=set(((d.get('parameters') or {}).get('properties') or {}).keys())
        if best is None or len(props&seedkeys)>len(set(((best.get('parameters') or {}).get('properties') or {}).keys())&seedkeys): best=d
    if best: schema=best.get('parameters') or {"type":"object","properties":{}}; desc=best.get('description') or ''; src_meta['viper']+=1
    else:
        schema={"type":"object","properties":{k:{"type":"string"} for k in sorted(seedkeys)}}; desc=cdesc.get((repo,tool),''); src_meta['fallback']+=1
    props=(schema or {}).get('properties') or {}
    sel_in=T(SEL.replace('{tool_name}',tool).replace('{tool_description}',desc).replace('{input_schema}',str(schema)).replace('{sanitizers_format}',san_fmt))
    sel_out=T(json.dumps({"selected_sanitizers":sel,"rules":rules}))
    wanted=cats(sel,bank)[0] if sel else []
    bp={c:bank[c] for c in wanted} if wanted else bank
    bdesc="".join(f"- Category: '{c}'\n  Description: {v['description']}\n  Sample Payloads: {json.dumps(v['payloads'][:3])}\n\n" for c,v in bp.items())
    sdesc=("\nThe following security sanitizers have been selected for this tool. Your test cases MUST exercise the properties they check:\n"+"\n".join(f"- {n}" for n in sel)+"\n") if sel else ""
    ex={p:f"<{(v or {}).get('type','any')}>" for p,v in props.items()}
    seed_in=T(SEED.replace('{tool_name}',tool).replace('{tool_description}',desc).replace('{input_schema}',str(schema)).replace('{selected_desc}',sdesc).replace('{seed_bank_desc}',bdesc).replace('{json.dumps(example_structure)}',json.dumps(ex)))+FB_TOK
    seed_out=T(json.dumps(seeds))
    nfb=len({v for s in seeds if isinstance(s,dict) for v in s.values() if isinstance(v,str) and v.startswith('predefined_seed:')})
    calls=2+nfb
    inp=sel_in+seed_in+nfb*seed_in; out=sel_out+seed_out
    per.append((key,calls,inp,out)); tot['calls']+=calls; tot['in']+=inp; tot['out']+=out; tot['fb']+=nfb
n=len(per); servers=len({k.split('__')[0]+'__'+k.split('__')[1] for k,*_ in per})
print(json.dumps(dict(tools=n,servers=servers,meta_source=dict(src_meta),calls=tot['calls'],file_builder_rounds=tot['fb'],input_tokens=tot['in'],output_tokens=tot['out'],
  per_tool=dict(calls=round(tot['calls']/n,2),input=round(tot['in']/n),output=round(tot['out']/n),input_median=statistics.median(p[2] for p in per),output_median=statistics.median(p[3] for p in per)),
  per_server=dict(calls=round(tot['calls']/servers,1),input=round(tot['in']/servers),output=round(tot['out']/servers))),indent=1))
