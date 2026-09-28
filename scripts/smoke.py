#!/usr/bin/env python3
"""Live HTTP smoke drill using synthetic data only. Leaves its case in the evaluation queue."""
import datetime
import http.cookiejar
import html
import io
import pathlib
import re
import urllib.parse
import urllib.request
import uuid
import zipfile

root = pathlib.Path(__file__).resolve().parent.parent
values = {}
for line in (root / '.env').read_text().splitlines():
    if '=' in line and not line.startswith('#'):
        k, v = line.split('=', 1)
        values[k] = v.strip().strip('"')
base = values['BEACON_URL']
parsed = urllib.parse.urlparse(base)
if parsed.hostname not in ('localhost', '127.0.0.1', '::1'):
    raise SystemExit('Smoke drill only supports a loopback evaluation deployment.')

def client():
    return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
def get(c, path):
    return c.open(base + path, timeout=15)
def csrf(page):
    return html.unescape(re.search(r'name="csrf" value="([^"]+)"', page).group(1))
def post(c, path, fields):
    req = urllib.request.Request(base + path, urllib.parse.urlencode(fields).encode(), headers={'Origin': base})
    return c.open(req, timeout=20)

reporter = client()
page = get(reporter, '/report').read().decode()
token = csrf(page)
boundary = 'beacon-' + uuid.uuid4().hex
fields = {'csrf': token, 'title': 'Synthetic end-to-end response drill', 'product': 'unknown',
          'description': 'Synthetic report for verifying persistence and recovery. No real vulnerability.',
          'steps': '1. Submit this synthetic report.\n2. Record acknowledgement.\n3. Verify conversation and evidence.',
          'impact': 'No real impact. Evaluation only.'}
parts = []
for key, value in fields.items():
    parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="{key}"\r\n\r\n{value}\r\n'.encode())
evidence = b'SYNTHETIC evidence for the Beacon recovery drill.\n'
parts.append(f'--{boundary}\r\nContent-Disposition: form-data; name="evidence"; filename="drill.txt"\r\nContent-Type: text/plain\r\n\r\n'.encode() + evidence + b'\r\n')
parts.append(f'--{boundary}--\r\n'.encode())
req = urllib.request.Request(base + '/report', b''.join(parts), headers={'Content-Type': f'multipart/form-data; boundary={boundary}', 'Origin': base})
receipt = reporter.open(req, timeout=20).read().decode()
ref = re.search(r'BCN-\d{4}-[0-9a-f]{10}', receipt).group()
recovery = re.search(r'BCN-RCVR-[0-9a-f]{64}', receipt).group()
public = post(reporter, '/recover', {'csrf': token, 'ref': ref, 'token': recovery}).read().decode()
assert ref in public
team = client()
login = get(team, '/login').read().decode()
team_csrf = csrf(login)
signed = post(team, '/login', {'csrf': team_csrf, 'email': values['BEACON_ADMIN_EMAIL'], 'password': values['BEACON_ADMIN_PASSWORD']})
assert signed.url.endswith('/app'), 'Sign-in did not create a usable session'

def edit(action, fields):
    page = get(team, '/app/cases/' + ref).read().decode()
    revision = re.search(r'name="revision" value="(\d+)"', page).group(1)
    return post(team, '/app/cases/' + ref + '/' + action, {'csrf': team_csrf, 'revision': revision, **fields})

edit('message', {'body': 'Synthetic internal-only drill note.', 'visibility': 'INTERNAL'}).read()
edit('message', {'body': 'Synthetic acknowledgement to the reporter.', 'visibility': 'REPORTER_VISIBLE', 'confirm': 'yes'}).read()
for status in ['ACKNOWLEDGED', 'TRIAGE', 'INVESTIGATING', 'REMEDIATING', 'DISCLOSURE_PENDING', 'RESOLVED', 'CLOSED']:
    edit('update', {'status': status, 'severity': 'LOW', 'owner': ''}).read()
public = get(reporter, '/reporter').read().decode()
assert 'Synthetic acknowledgement to the reporter.' in public
assert 'Synthetic internal-only drill note.' not in public
assert 'Closed' in public
page = get(team, '/app/cases/' + ref).read().decode()
revision = re.search(r'name="revision" value="(\d+)"', page).group(1)
archive = post(team, '/app/cases/' + ref + '/export', {'csrf': team_csrf, 'confirm': 'yes', 'revision': revision}).read()
with zipfile.ZipFile(io.BytesIO(archive)) as z:
    blobs = [z.read(name) for name in z.namelist() if name.startswith('attachments/')]
    assert blobs == [evidence], 'Evidence was not preserved in the export'
post(team, '/logout', {'csrf': team_csrf}).read()
print(f'Live HTTP drill passed: {ref}; private intake → team login → communication → closure → evidence export.')
