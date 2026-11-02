"""Parse every owned deployment config without deploying or resolving host data."""
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import yaml

ROOT=Path(__file__).resolve().parents[1]
yaml.SafeLoader.add_constructor('!override',lambda loader,node: loader.construct_sequence(node) if isinstance(node,yaml.SequenceNode) else loader.construct_mapping(node) if isinstance(node,yaml.MappingNode) else loader.construct_scalar(node))
files=sorted([*ROOT.glob('components/**/compose*.yaml'),*ROOT.glob('vendor/**/compose*.yaml')])
assert len(files)==12,len(files)
fixture_env=dict(os.environ, MIDDLEWARE_RELEASE_ROOT='/ci-only/release', KONG_PG_PASSWORD='ci-disposable-only', SMS_DB_PASSWORD='ci-disposable-only', SMS_DLR_TOKEN='ci-disposable-only', PORTAL_ENV_FILE='/ci-only/portal.env')
for file in files:
    data=yaml.safe_load(file.read_text())
    assert isinstance(data.get('services'),dict) and data['services'],file
    for name,service in data['services'].items():
        if 'image' in service:
            assert re.fullmatch(r'[^@]+@sha256:[0-9a-f]{64}',service['image']),(file,name)
    subprocess.run(['docker','compose','-f',str(file),'config','--no-env-resolution','--quiet'],check=True,env=fixture_env)
sms=yaml.safe_load((ROOT/'components/sms-api/compose.yaml').read_text())
assert sms['services']['api']['environment']['LIVE_SMS_DELIVERY']=='false'
assert sms['services']['api']['environment']['LIVE_SUBMISSION_ENABLED']=='false'
assert all(sms['services'][name]['read_only'] for name in ('api','event-worker'))
assert yaml.safe_load((ROOT/'VENDOR-DEPLOYMENT-AUTHORITY.yaml').read_text())['policy']['runtime_replacement_authorized'] is False
assert yaml.safe_load((ROOT/'AUTHORITY-IMPORT-MANIFEST.yaml').read_text())['business_writes_enabled'] is False
assert json.loads((ROOT/'monitoring-integration.v1.json').read_text())['activation_enabled'] is False
owned={str(p.relative_to(ROOT)) for p in (ROOT/'components').rglob('*.py') if '/tests/' not in str(p) and not p.name.startswith('test_')}
assert owned=={'components/kong-service-auth-adapter/adapter.py','components/monitoring-receiver/app.py','components/private-integration-gateway/gateway.py','components/sms-api/app/__init__.py','components/sms-api/app/main.py','components/sms-api/app/event_worker.py'},owned
assert {str(p.relative_to(ROOT)) for p in (ROOT/'vendor').rglob('*.lua')}=={'vendor/kong-gateway/plugins/codestra-gateway-identity/handler.lua','vendor/kong-gateway/plugins/codestra-gateway-identity/schema.lua'}
# Use the existing immutable Caddy authority only as an offline parser. The external
# host-owned snippet is an explicit empty CI fixture, never production certification.
image='caddy@sha256:5f5c8640aae01df9654968d946d8f1a56c497f1dd5c5cda4cf95ab7c14d58648'
subprocess.run(['docker','pull',image],check=True)
with tempfile.TemporaryDirectory() as temporary:
    snippet=Path(temporary)/'breero-private-route';snippet.write_text('# Isolated parser fixture; external runtime route is not certified.\n')
    for config in sorted((ROOT/'vendor').glob('*/Caddyfile')):
        text=config.read_text()
        imports=re.findall(r'^\s*import\s+(\S+)',text,re.M)
        assert imports in ([],['/etc/caddy/snippets/breero-private-route']),config
        subprocess.run(['docker','run','--rm','--network','none','--read-only','--user','65532:65532','--cap-drop','ALL','--security-opt','no-new-privileges','-v',f'{ROOT}:/source:ro','-v',f'{snippet}:/etc/caddy/snippets/breero-private-route:ro','--entrypoint','caddy',image,'adapt','--config','/source/'+str(config.relative_to(ROOT)),'--adapter','caddyfile'],check=True,stdout=subprocess.DEVNULL)
print('ALL_OWNED_COMPOSE_CADDY_SOURCE_AND_SAFETY_CONTRACTS=PASS; external host data/runtime not certified')
