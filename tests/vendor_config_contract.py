"""Owned configuration validation; exact external fragments remain runtime HOLD."""
import copy
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import yaml

ROOT=Path(os.environ.get('CONTRACT_SOURCE_ROOT',Path(__file__).resolve().parents[1])).resolve()
REVIEWED_BASE='ca31307942895370b468fc5358697ccf1ddfde7e'
FROZEN_VENDOR_FILES={
    "vendor/caddy-upstream-gateway/Caddyfile": {
        "mode": "100644",
        "blob": "346cd960eaf24cd1f570c40e3a62f9d3b514d56e"
    },
    "vendor/caddy-upstream-gateway/compose.yaml": {
        "mode": "100644",
        "blob": "9ef20e9b2003a7e989b622f22c615e62dcbcd1f9"
    },
    "vendor/kong-gateway/compose.yaml": {
        "mode": "100644",
        "blob": "d5e4f92da734274e2aff263621ff65db10e7adf4"
    },
    "vendor/kong-gateway/plugins/codestra-gateway-identity/handler.lua": {
        "mode": "100644",
        "blob": "f182322543304b306711394def7f7aea3cdc8c99"
    },
    "vendor/kong-gateway/plugins/codestra-gateway-identity/schema.lua": {
        "mode": "100644",
        "blob": "20aad3c02e8a1502a5005076338de0ee416fe779"
    },
    "vendor/n8n-internal-proxy/Caddyfile": {
        "mode": "100644",
        "blob": "1fe0afe7c8a47006aa1f43fb97e2a60b6a6e4fe9"
    },
    "vendor/n8n-internal-proxy/compose.yaml": {
        "mode": "100644",
        "blob": "5346ba6109cecf2b8df5c0aec507276821962b2d"
    },
    "vendor/odoo-internal-proxy/Caddyfile": {
        "mode": "100644",
        "blob": "eafa2f7360b6b51c61f6cf9f3babbbcb9e2d244b"
    },
    "vendor/odoo-internal-proxy/compose.yaml": {
        "mode": "100644",
        "blob": "518dcd9e681f8c5fe5ebe1316ce6838763c0ab4d"
    },
    "vendor/private-vicidial-ingress/Caddyfile": {
        "mode": "100644",
        "blob": "8a382ad2380981fe9473720fa41add33cbfeb9af"
    },
    "vendor/private-vicidial-ingress/compose.yaml": {
        "mode": "100644",
        "blob": "cd549f1756dc3bc4b489040e6c9c6a4683a0ef13"
    },
    "vendor/reseller-portal-postgres/compose.yaml": {
        "mode": "100644",
        "blob": "6c023419d219391dd1a173a20796b52139864755"
    },
    "vendor/stalwart/compose.yaml": {
        "mode": "100644",
        "blob": "9dae24b0ba3d8f580be4a445c103f2ac9f5a4215"
    }
}
PARTIAL_COMPOSE={
    'vendor/private-vicidial-ingress/compose.yaml',
    'vendor/reseller-portal-postgres/compose.yaml',
}
PARTIAL_CADDY='vendor/private-vicidial-ingress/Caddyfile'
EXTERNAL_ENV_FILES={'/etc/kyqra-telnexa-integration/shared.env', '/etc/codestra/secrets/kyqra-telnexa/middleware.env', '${PORTAL_ENV_FILE:-/etc/codestra/secrets/reseller-portal.env}', '/etc/codestra/secrets/mail-platform/stalwart/runtime.env'}
yaml.SafeLoader.add_constructor('!override',lambda loader,node: loader.construct_sequence(node) if isinstance(node,yaml.SequenceNode) else loader.construct_mapping(node) if isinstance(node,yaml.MappingNode) else loader.construct_scalar(node))


def git_inventory(root):
    raw=subprocess.check_output(['git','ls-files','--stage','-z','--','vendor'],cwd=root).decode()
    result={}
    for entry in raw.split('\0'):
        if entry:
            metadata,path=entry.split('\t',1);mode,blob,stage=metadata.split()
            if stage!='0':raise ValueError('Unmerged vendor Git entry')
            result[path]={'mode':mode,'blob':blob}
    return result


def validate_vendor_authority(root,inventory=None):
    """Freeze every original vendor file; no unknown source/config enters this lane."""
    inventory=git_inventory(root) if inventory is None else inventory
    if inventory!=FROZEN_VENDOR_FILES:raise ValueError('Vendor Git path/blob/mode authority changed')
    actual={str(p.relative_to(root)) for p in (root/'vendor').rglob('*') if p.is_file() or p.is_symlink()}
    if actual!=set(FROZEN_VENDOR_FILES):raise ValueError('Vendor file added or removed')
    for name,expected in FROZEN_VENDOR_FILES.items():
        path=root/name
        if path.is_symlink() or path.stat().st_mode & 0o111:raise ValueError('Vendor symlink/executable denied')
        raw=path.read_bytes();blob=hashlib.sha1(f'blob {len(raw)}\0'.encode()+raw).hexdigest()
        if blob!=expected['blob']:raise ValueError('Vendor complete raw Git blob changed')
    return validate_external_fragments(root)


def validate_external_fragments(root):
    ingress=yaml.safe_load((root/'vendor/private-vicidial-ingress/compose.yaml').read_text())
    if set(ingress['services'])!={'reverse-proxy','private-vicidial-ingress'}:raise ValueError('Unknown partial override service')
    if ingress['services']['reverse-proxy']!={'ports':['65.109.65.169:80:80','65.109.65.169:443:443']}:raise ValueError('Unknown external parent override keys/ports')
    service=ingress['services']['private-vicidial-ingress']
    if service['environment']!={'VICIDIAL_EVENT_INGRESS_ROUTING_ENABLED':'false'}:raise ValueError('External ingress activation changed')
    expected_volumes=[
        '${MIDDLEWARE_RELEASE_ROOT:?exact release root required}/deploy/readiness/Caddyfile.private-vicidial-ingress:/etc/caddy/Caddyfile:ro',
        '${MIDDLEWARE_RELEASE_ROOT:?exact release root required}/deploy/breero/Caddyfile.private-route:/etc/caddy/snippets/breero-private-route:ro',
        '/etc/codestra/pki/middleware-private-ingress:/run/secrets/middleware-private-ingress:ro',
        '/opt/codestra/logs/caddy:/var/log/caddy',
    ]
    if service['volumes']!=expected_volumes or service['read_only'] is not True:raise ValueError('External ingress input or safety contract changed')
    portal=yaml.safe_load((root/'vendor/reseller-portal-postgres/compose.yaml').read_text())
    if portal['services']['portal']['build']!={'context':'../..','dockerfile':'deploy/reseller-portal/Dockerfile'}:raise ValueError('External portal source reference changed')
    if portal['services']['oidc-gateway']['volumes']!=['./oauth2-proxy.cfg:/etc/oauth2-proxy/oauth2-proxy.cfg:ro']:raise ValueError('External OIDC config reference changed')
    if not all(service['read_only'] is True for service in portal['services'].values()):raise ValueError('Portal safety contract changed')
    caddy=(root/PARTIAL_CADDY).read_text()
    if re.findall(r'^\s*import\s+(\S+)',caddy,re.M)!=['/etc/caddy/snippets/breero-private-route']:raise ValueError('External Caddy import changed')
    if 'mode require_and_verify' not in caddy or 'respond 403' not in caddy:raise ValueError('Private ingress deny/authentication guards changed')
    return [
        {'path':'vendor/private-vicidial-ingress/compose.yaml','status':'EXTERNAL_RUNTIME_BINDING_HOLD','unresolved':['reverse-proxy parent Compose authority','MIDDLEWARE_RELEASE_ROOT/deploy/readiness/Caddyfile.private-vicidial-ingress','MIDDLEWARE_RELEASE_ROOT/deploy/breero/Caddyfile.private-route']},
        {'path':'vendor/reseller-portal-postgres/compose.yaml','status':'EXTERNAL_RUNTIME_BINDING_HOLD','unresolved':['../../deploy/reseller-portal/Dockerfile','./oauth2-proxy.cfg']},
        {'path':PARTIAL_CADDY,'status':'EXTERNAL_RUNTIME_BINDING_HOLD','unresolved':['/etc/caddy/snippets/breero-private-route']},
    ]


def validate_env_references(service):
    references=service.get('env_file',[])
    if isinstance(references,str):references=[references]
    if not isinstance(references,list) or not all(isinstance(ref,str) and ref in EXTERNAL_ENV_FILES for ref in references):
        raise ValueError('Unreviewed external environment reference')


def validate_standalone_compose(root):
    files=sorted([*root.glob('components/**/compose*.yaml'),*root.glob('vendor/**/compose*.yaml')])
    if len(files)!=12:raise ValueError('Unreviewed Compose inventory')
    count=0
    fixture_env=dict(os.environ,MIDDLEWARE_RELEASE_ROOT='/ci-only/release',KONG_PG_PASSWORD='ci-disposable-only',SMS_DB_PASSWORD='ci-disposable-only',SMS_DLR_TOKEN='ci-disposable-only')
    for file in files:
        data=yaml.safe_load(file.read_text())
        if not isinstance(data.get('services'),dict) or not data['services']:raise ValueError('Missing services')
        for name,service in data['services'].items():
            if 'image' in service and not re.fullmatch(r'[^@]+@sha256:[0-9a-f]{64}',service['image']):raise ValueError('Mutable image reference')
            validate_env_references(service)
        if str(file.relative_to(root)) in PARTIAL_COMPOSE:
            continue  # Exact frozen fragment contract above, explicitly NOT complete Compose certification.
        with tempfile.TemporaryDirectory() as temporary:
            fixture=Path(temporary)/'empty.env';fixture.write_text('')
            candidate=file.read_text()
            for reference in EXTERNAL_ENV_FILES:
                if not reference.startswith('${'):candidate=candidate.replace(reference,str(fixture))
            parse_file=Path(temporary)/'compose.yaml';parse_file.write_text(candidate)
            environment=dict(fixture_env,PORTAL_ENV_FILE=str(fixture))
            subprocess.run(['docker','compose','--project-directory',str(file.parent),'-f',str(parse_file),'config','--no-env-resolution','--quiet'],check=True,env=environment)
        count+=1
    if count!=10:raise ValueError('Standalone Compose inventory changed')
    return count


def validate_safety_and_owned_inventory(root):
    sms=yaml.safe_load((root/'components/sms-api/compose.yaml').read_text())
    assert sms['services']['api']['environment']['LIVE_SMS_DELIVERY']=='false'
    assert sms['services']['api']['environment']['LIVE_SUBMISSION_ENABLED']=='false'
    assert all(sms['services'][name]['read_only'] for name in ('api','event-worker'))
    vendor=yaml.safe_load((root/'VENDOR-DEPLOYMENT-AUTHORITY.yaml').read_text())
    assert vendor['production_changed'] is False and vendor['deployment_authorized'] is False
    assert vendor['policy']['runtime_replacement_authorized'] is False
    assert vendor['policy']['external_business_writes_enabled'] is False
    authority=yaml.safe_load((root/'AUTHORITY-IMPORT-MANIFEST.yaml').read_text())
    assert authority['production_changed'] is False and authority['business_writes_enabled'] is False
    monitoring=json.loads((root/'monitoring-integration.v1.json').read_text())
    assert monitoring['activation_enabled'] is False and monitoring['runtime_onboarding_allowed'] is False
    owned={str(p.relative_to(root)) for p in (root/'components').rglob('*.py') if '/tests/' not in str(p) and not p.name.startswith('test_')}
    assert owned=={'components/kong-service-auth-adapter/adapter.py','components/monitoring-receiver/app.py','components/private-integration-gateway/gateway.py','components/sms-api/app/__init__.py','components/sms-api/app/main.py','components/sms-api/app/event_worker.py'},owned


CADDY_AMD64_SHA256='b7105518e3ed1c0761f232e44fc09345535533c9cb0abf0e12809416c7ac64d9'


def capability_free_parser_copy(source,target,expected_sha=CADDY_AMD64_SHA256):
    """Preserve exact bytes while avoiding the official binary's bind-service filecap.

    This is only an offline parser copy; production images and container capability
    bounds/no-new-privileges remain unchanged. Exclusive creation preserves no xattrs.
    """
    raw=source.read_bytes()
    if hashlib.sha256(raw).hexdigest()!=expected_sha:raise ValueError('Caddy parser source bytes do not match the verified OCI layer')
    with target.open('xb') as handle:handle.write(raw)
    target.chmod(0o755)
    if 'security.capability' in os.listxattr(target):raise ValueError('Parser copy retains a file capability')
    if hashlib.sha256(target.read_bytes()).hexdigest()!=expected_sha:raise ValueError('Caddy parser copy changed bytes')


def validate_standalone_caddy(root):
    image='caddy@sha256:5f5c8640aae01df9654968d946d8f1a56c497f1dd5c5cda4cf95ab7c14d58648'
    subprocess.run(['docker','pull','--platform','linux/amd64',image],check=True)
    count=0
    with tempfile.TemporaryDirectory() as temporary:
        extracted=Path(temporary)/'caddy-original';parser=Path(temporary)/'caddy-parser'
        # Create does not start a server or execute the image entrypoint.
        container=subprocess.check_output(['docker','create','--platform','linux/amd64','--network','none',image],text=True).strip()
        try:subprocess.run(['docker','cp',container+':/usr/bin/caddy',str(extracted)],check=True)
        finally:subprocess.run(['docker','rm','--volumes',container],check=True)
        capability_free_parser_copy(extracted,parser)
        print('CADDY_PARSER_IDENTICAL_BYTES_NO_FILE_CAPABILITY=PASS sha256='+CADDY_AMD64_SHA256)
        for config in sorted((root/'vendor').glob('*/Caddyfile')):
            if str(config.relative_to(root))==PARTIAL_CADDY:continue
            if re.findall(r'^\s*import\s+(\S+)',config.read_text(),re.M):raise ValueError('Unknown external Caddy import')
            subprocess.run(['docker','run','--rm','--platform','linux/amd64','--network','none','--read-only','--user','65532:65532','--cap-drop','ALL','--security-opt','no-new-privileges','-v',f'{root}:/source:ro','-v',f'{parser}:/ci-tools/caddy:ro','--entrypoint','/ci-tools/caddy',image,'adapt','--config','/source/'+str(config.relative_to(root)),'--adapter','caddyfile'],check=True,stdout=subprocess.DEVNULL)
            count+=1
    if count!=3:raise ValueError('Standalone Caddy inventory changed')
    return count


def main():
    holds=validate_vendor_authority(ROOT)
    validate_safety_and_owned_inventory(ROOT)
    compose=validate_standalone_compose(ROOT)
    caddy=validate_standalone_caddy(ROOT)
    print(json.dumps({'source_contract':'PASS','standalone_compose_validated':compose,'standalone_caddy_parsed':caddy,'frozen_vendor_files':len(FROZEN_VENDOR_FILES),'external_runtime_binding_holds':holds,'production_activation_authorized':False},sort_keys=True))

if __name__=='__main__':main()
