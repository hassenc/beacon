#!/usr/bin/env python3
import hashlib, pathlib, subprocess, tarfile
out=pathlib.Path('artifacts/release')
files=subprocess.check_output(['git','ls-files','-z']).decode().split('\0')
if not any(f=='go.mod' for f in files):
    raise SystemExit('Stage reviewed source before assembling a candidate archive.')
with tarfile.open(out/'beacon-source.tar.gz','w:gz') as tar:
    for f in sorted(filter(None,files)):
        p=pathlib.Path(f)
        if p.is_file():
            info=tar.gettarinfo(str(p),'beacon/'+f)
            info.uid=info.gid=0;info.uname=info.gname='';info.mtime=0
            with p.open('rb') as body: tar.addfile(info,body)
with (out/'SHA256SUMS').open('w') as manifest:
    for p in sorted(out.iterdir()):
        if p.is_file() and p.name!='SHA256SUMS':
            manifest.write(hashlib.sha256(p.read_bytes()).hexdigest()+'  '+p.name+'\n')
print('Candidate artifacts are in artifacts/release. No publication or signing performed.')
