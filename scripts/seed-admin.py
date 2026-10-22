"""Idempotent bootstrap over the private Docker address; never prints secrets."""
import json
import os
import secrets
import subprocess
import urllib.error
import urllib.parse
import urllib.request
address = subprocess.check_output(['docker','inspect','-f','{{(index .NetworkSettings.Networks "sir-server_sir-net").IPAddress}}','sir-auth'],text=True).strip()
body=json.dumps(dict(admin_email=os.environ['ADMIN_EMAIL'],admin_password=os.environ['ADMIN_PASSWORD'],client_id='sir-cli',client_secret=secrets.token_hex(32),client_name='SIR CLI')).encode()
url=f'http://{address}:8080/setup?'+urllib.parse.urlencode(dict(secret=os.environ['SETUP_SECRET']))
request=urllib.request.Request(url,data=body,headers={'Content-Type':'application/json'})
try:
    with urllib.request.urlopen(request,timeout=15) as response: status=response.status
except urllib.error.HTTPError as error: status=error.code
if status not in (201,409): raise SystemExit(f'Setup failed with HTTP {status}')
print(f'Setup status: {status}')
