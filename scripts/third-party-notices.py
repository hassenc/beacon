#!/usr/bin/env python3
"""Collect dependency license texts from the resolved, verified module cache."""
import json,pathlib,subprocess
raw=subprocess.check_output(['go','list','-deps','-json','./cmd/beacon']).decode();decoder=json.JSONDecoder();modules=[]
while raw.strip():
    value,end=decoder.raw_decode(raw.lstrip());modules.append(value);raw=raw.lstrip()[end:]
parts=['# Third-party notices\n\nThe application is Apache-2.0. The following dependency license texts accompany distributed binaries. Tooling used only to build or scan is not linked into the application.\n']
modules={p["Module"]["Path"]:p["Module"] for p in modules if p.get("Module") and not p["Module"].get("Main")}
for m in modules.values():
    root=pathlib.Path(m['Dir']);licenses=sorted(p for p in root.iterdir() if p.is_file() and p.name.upper().startswith(('LICENSE','COPYING','NOTICE')))
    if not licenses:raise SystemExit('Missing license: '+m['Path'])
    parts.append('\n## '+m['Path']+' '+m['Version']+'\n')
    for p in licenses:parts.append('\n### '+p.name+'\n\n```text\n'+p.read_text()+'\n```\n')
goroot=pathlib.Path(subprocess.check_output(['go','env','GOROOT']).decode().strip())
parts.append('\n## Go runtime\n\n```text\n'+(goroot/'LICENSE').read_text()+'\n```\n')
pathlib.Path('THIRD_PARTY_NOTICES.md').write_text('\n'.join(line.rstrip() for line in ''.join(parts).splitlines())+'\n')
