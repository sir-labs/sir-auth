"""Read-only native OAuth discovery probe; contains no credentials."""
import subprocess
import urllib.parse
import urllib.request

# Network/address is inspected at deployment time, never hard-coded.
address = subprocess.check_output([
    'docker', 'inspect', '-f', '{{(index .NetworkSettings.Networks "sir-server_sir-net").IPAddress}}', 'sir-auth'
], text=True).strip()
query = urllib.parse.urlencode(dict(response_type='code',client_id='note-app-desktop',
    redirect_uri='http://127.0.0.1:54321/callback',scope='openid',state='0'*32,
    code_challenge='E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM',code_challenge_method='S256'))
with urllib.request.urlopen(f'http://{address}:8080/oauth/authorize?{query}', timeout=15) as response:
    assert response.status == 200
    assert 'Note App Desktop' in response.read().decode()
print('Native public client is registered; S256 authorization page responds')
