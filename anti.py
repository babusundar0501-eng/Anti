#!/usr/bin/env python3
"""Anti: cautious cross-platform on-demand malware triage scanner."""
from __future__ import annotations
import argparse, hashlib, json, math, os, shutil, string, time, uuid
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

APP_DIR=Path.home()/".anti"; QUARANTINE_DIR=APP_DIR/"quarantine"; MANIFEST=QUARANTINE_DIR/"manifest.json"
CHUNK=1024*1024; MAX_SAMPLE=1024*1024; MAX_SIZE=512*1024*1024
EICAR=b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR"
INJECTION_APIS=(b"VirtualAllocEx",b"WriteProcessMemory",b"CreateRemoteThread",b"NtUnmapViewOfSection",b"SetWindowsHookEx")
DOC_EXTS={".pdf",".jpg",".jpeg",".png",".gif",".txt",".doc",".docx",".xls",".xlsx",".ppt",".pptx",".mp3",".mp4"}

def entropy(data):
    if not data:return 0.0
    c=Counter(data); n=len(data)
    return -sum((v/n)*math.log2(v/n) for v in c.values())

def sha256_file(path):
    h=hashlib.sha256()
    with path.open("rb") as f:
        for b in iter(lambda:f.read(CHUNK),b""):h.update(b)
    return h.hexdigest()

def inspect_file(path):
    r={"path":str(path),"status":"clean","severity":"info","reasons":[],"sha256":None,"size":None,"entropy":None,"quarantined":False}
    try:
        if path.is_symlink() or not path.is_file():
            r["status"]="skipped";r["reasons"].append("Not a regular file");return r
        size=path.stat().st_size;r["size"]=size
        if size>MAX_SIZE:
            r["status"]="skipped";r["reasons"].append("File exceeds 512 MB scan limit");return r
        sample=bytearray();tail=b"";eicar=False
        with path.open("rb") as f:
            while True:
                block=f.read(CHUNK)
                if not block:break
                if len(sample)<MAX_SAMPLE:sample.extend(block[:MAX_SAMPLE-len(sample)])
                if EICAR in tail+block:eicar=True
                tail=(tail+block)[-len(EICAR):]
        data=bytes(sample);r["sha256"]=sha256_file(path);r["entropy"]=round(entropy(data),3)
        ext=path.suffix.lower();pe=data.startswith(b"MZ");elf=data.startswith(b"\x7fELF")
        if eicar:
            r["status"]="threat";r["severity"]="critical";r["reasons"].append("EICAR antivirus test signature detected")
        if (pe or elf) and ext in DOC_EXTS:
            r["status"]="threat";r["severity"]="critical";r["reasons"].append("Executable header disguised as document/media file")
        if pe:
            hits=[x.decode("ascii") for x in INJECTION_APIS if x in data]
            if len(hits)>=2:
                r["status"]="suspicious";r["severity"]="high";r["reasons"].append("Multiple process-injection API names: "+", ".join(hits))
            if r["entropy"]>=7.75 and r["status"]=="clean":
                r["status"]="suspicious";r["severity"]="medium";r["reasons"].append("Very high PE sample entropy; packing/encryption is possible")
        if r["status"]=="clean":r["reasons"].append("No configured indicators found (not proof of safety)")
    except OSError as e:
        r["status"]="error";r["severity"]="warning";r["reasons"].append(f"Could not inspect file: {e}")
    return r

def load_manifest():
    try:
        d=json.loads(MANIFEST.read_text(encoding="utf-8"));return d if isinstance(d,list) else []
    except (OSError,json.JSONDecodeError):return []

def save_manifest(entries):
    QUARANTINE_DIR.mkdir(parents=True,exist_ok=True)
    t=MANIFEST.with_suffix(".tmp");t.write_text(json.dumps(entries,indent=2),encoding="utf-8");t.replace(MANIFEST)

def quarantine_file(path,r):
    if r["severity"]!="critical" or not path.exists():return False
    QUARANTINE_DIR.mkdir(parents=True,exist_ok=True);stored=QUARANTINE_DIR/(uuid.uuid4().hex+"_"+path.name+".quarantined")
    try:
        shutil.move(str(path),str(stored));entries=load_manifest()
        entries.append({"id":stored.name,"stored_path":str(stored),"original_path":str(path),"sha256":r["sha256"],"quarantined_at":datetime.now(timezone.utc).isoformat()})
        save_manifest(entries);r["quarantined"]=True;return True
    except OSError as e:r["reasons"].append(f"Quarantine failed: {e}");return False

def iter_files(targets):
    q=QUARANTINE_DIR.resolve()
    for target in targets:
        if not target.exists():print(f"[SKIP] Not found: {target}");continue
        if target.is_file() and not target.is_symlink():
            try:
                p=target.resolve()
                if p!=q and q not in p.parents:yield target
            except OSError:pass
        elif target.is_dir() and not target.is_symlink():
            for root,dirs,files in os.walk(target,followlinks=False):
                rp=Path(root);dirs[:]=[d for d in dirs if not (rp/d).is_symlink() and (rp/d).resolve()!=q and q not in (rp/d).resolve().parents]
                for name in files:
                    p=rp/name
                    if p.is_symlink():continue
                    try:
                        v=p.resolve()
                        if v==q or q in v.parents:continue
                    except OSError:continue
                    yield p

def quick_targets():
    h=Path.home();return [h/n for n in ("Desktop","Downloads","Documents") if (h/n).exists()]
def long_targets():return [Path.home()]
def pc_targets():
    if os.name=="nt":return [Path(f"{d}:\\") for d in string.ascii_uppercase if Path(f"{d}:\\").exists()]
    return [Path("/")]

def run_scan(targets,auto=False):
    start=time.time();results=[];seen=set()
    print("\nANTI SECURITY SCANNER\nTargets: "+", ".join(map(str,targets)))
    print("Mode: "+("report + reversible quarantine of critical findings" if auto else "report only"))
    for p in iter_files(targets):
        try:k=str(p.resolve())
        except OSError:k=str(p)
        if k in seen:continue
        seen.add(k);r=inspect_file(p);results.append(r)
        if r["status"] in ("threat","suspicious","error"):
            print(f'[{r["severity"].upper()}] {p}')
            for reason in r["reasons"]:print("  - "+reason)
            if auto and r["severity"]=="critical" and quarantine_file(p,r):print("  -> Moved to reversible quarantine")
    c=Counter(x["status"] for x in results);elapsed=round(time.time()-start,2)
    report={"scanner":"Anti","created_at":datetime.now(timezone.utc).isoformat(),"targets":list(map(str,targets)),"files_inspected":len(results),"elapsed_seconds":elapsed,"summary":dict(c),"results":results}
    APP_DIR.mkdir(parents=True,exist_ok=True);out=APP_DIR/"last_scan.json";out.write_text(json.dumps(report,indent=2),encoding="utf-8")
    print(f"\nInspected {len(results)} | threats {c['threat']} | suspicious {c['suspicious']} | errors {c['error']} | skipped {c['skipped']}")
    print(f"Report: {out}\nA clean result is not a safety guarantee. Anti is not real-time protection.")
    return 1 if c["threat"] or c["suspicious"] else 0

def restore_item(item_id):
    entries=load_manifest();item=next((x for x in entries if x.get("id")==item_id),None)
    if not item:print("Quarantine item not found.");return False
    src=Path(item["stored_path"]);dst=Path(item["original_path"])
    if not src.exists():print("Quarantined file is missing.");return False
    if dst.exists():print(f"Restore blocked; destination already exists: {dst}");return False
    try:
        dst.parent.mkdir(parents=True,exist_ok=True);shutil.move(str(src),str(dst))
        save_manifest([x for x in entries if x.get("id")!=item_id]);print("Restored:",dst);return True
    except OSError as e:print("Restore failed:",e);return False

def main():
    p=argparse.ArgumentParser(description="Anti — cautious on-demand security scanner");s=p.add_subparsers(dest="command",required=True)
    for name in ("quick","long","pc"):
        x=s.add_parser(name);x.add_argument("--quarantine",action="store_true")
    x=s.add_parser("scan");x.add_argument("path",type=Path);x.add_argument("--quarantine",action="store_true")
    s.add_parser("quarantine");x=s.add_parser("restore");x.add_argument("id")
    a=p.parse_args()
    if a.command=="quarantine":
        es=load_manifest()
        if not es:print("Quarantine is empty.")
        for e in es:print(f'{e["id"]}\n  Original: {e["original_path"]}\n  SHA-256: {e.get("sha256")}')
        return 0
    if a.command=="restore":return 0 if restore_item(a.id) else 1
    targets={"quick":quick_targets,"long":long_targets,"pc":pc_targets}.get(a.command,lambda:[a.path.expanduser()])()
    if not targets:print("No default folders found. Use: python anti.py scan <folder>");return 2
    return run_scan(targets,a.quarantine)
if __name__=="__main__":raise SystemExit(main())
