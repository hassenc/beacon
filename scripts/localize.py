#!/usr/bin/env python3
"""Translate literal template text before rendering; never process user content."""
import html, json, pathlib, re, sys
root=pathlib.Path('internal/beacon/web')
catalog=json.loads((root/'fr.json').read_text())
missing=set(); stale=[]
def translate(value):
    key=value.strip()
    if not re.search('[A-Za-z]',key):return value
    if key not in catalog:
        missing.add(key);return value
    return value[:len(value)-len(value.lstrip())]+html.escape(catalog[key],quote=False)+value[len(value.rstrip()):]
for path in root.glob('*.html'):
    if '.fr.' in path.name:continue
    source=path.read_text()
    # Values remain stable when visible option labels are translated.
    source=re.sub(r'<option>([^<{}]+)</option>',lambda m:'<option value="'+html.escape(m[1],quote=True)+'">'+m[1]+'</option>',source)
    masked=re.sub(r'{{.*?}}',lambda m:' '*len(m[0]),source)
    patches=[]
    for m in re.finditer(r'>([^<>]+)<',masked):
        original=source[m.start(1):m.end(1)]
        parts=re.split(r'({{.*?}})',original)
        text=''.join(p if p.startswith('{{') else translate(p) for p in parts)
        patches.append((m.start(1),m.end(1),text))
    for m in re.finditer(r'(?:placeholder|aria-label)="([^"{}]+)"',source):
        patches.append((m.start(1),m.end(1),translate(m[1])))
    for start,end,text in sorted(patches,reverse=True):source=source[:start]+text+source[end:]
    target=path.with_name(path.stem+'.fr.html')
    if '--check' in sys.argv:
        if not target.exists() or target.read_text()!=source:stale.append(str(target))
    else:target.write_text(source)
if missing:raise SystemExit('Missing French strings: '+json.dumps(sorted(missing),ensure_ascii=False))
if stale:raise SystemExit('Regenerate localized templates: '+', '.join(stale))
