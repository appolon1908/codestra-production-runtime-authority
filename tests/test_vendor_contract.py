import copy
import hashlib
from unittest.mock import patch
from pathlib import Path
import shutil
import tempfile
import unittest
import yaml
from vendor_config_contract import ROOT, FROZEN_VENDOR_FILES, validate_vendor_authority, validate_external_fragments, validate_env_references, capability_free_parser_copy

class FrozenVendorContractTests(unittest.TestCase):
    def setUp(self):
        directory=tempfile.TemporaryDirectory();self.addCleanup(directory.cleanup)
        self.root=Path(directory.name);shutil.copytree(ROOT/'vendor',self.root/'vendor')
        self.inventory=copy.deepcopy(FROZEN_VENDOR_FILES)

    def test_exact_frozen_inventory_emits_explicit_external_runtime_holds(self):
        holds=validate_vendor_authority(self.root,self.inventory)
        self.assertEqual(len(holds),3)
        self.assertTrue(all(x['status']=='EXTERNAL_RUNTIME_BINDING_HOLD' for x in holds))
        self.assertTrue(all(x['unresolved'] for x in holds))

    def test_every_vendor_blob_and_mode_change_is_denied(self):
        for path in FROZEN_VENDOR_FILES:
            with self.subTest(path=path):
                changed=copy.deepcopy(self.inventory);changed[path]['blob']='a'*40
                self.assertRaises(ValueError,validate_vendor_authority,self.root,changed)
                changed=copy.deepcopy(self.inventory);changed[path]['mode']='100755'
                self.assertRaises(ValueError,validate_vendor_authority,self.root,changed)
                file=self.root/path;original=file.read_bytes();file.write_bytes(original+b'\n')
                self.assertRaises(ValueError,validate_vendor_authority,self.root,self.inventory)
                file.write_bytes(original)

    def test_added_removed_and_symlink_vendor_files_are_denied(self):
        path=self.root/'vendor/new.conf';path.write_text('new')
        self.assertRaises(ValueError,validate_vendor_authority,self.root,self.inventory);path.unlink()
        path=self.root/next(iter(FROZEN_VENDOR_FILES));original=path.read_bytes();path.unlink()
        self.assertRaises(ValueError,validate_vendor_authority,self.root,self.inventory)
        target=self.root/'target';target.write_bytes(original);path.symlink_to(target)
        self.assertRaises(ValueError,validate_vendor_authority,self.root,self.inventory)

    def test_partial_override_shape_and_activation_tampering_are_denied(self):
        path=self.root/'vendor/private-vicidial-ingress/compose.yaml';original=path.read_text()
        for changed in (original.replace('VICIDIAL_EVENT_INGRESS_ROUTING_ENABLED: "false"','VICIDIAL_EVENT_INGRESS_ROUTING_ENABLED: "true"'),original.replace('reverse-proxy:\n','reverse-proxy:\n    image: untrusted:latest\n'),original.replace('65.109.65.169:80:80','0.0.0.0:80:80'),original.replace('${MIDDLEWARE_RELEASE_ROOT:?exact release root required}','/untrusted')):
            path.write_text(changed)
            self.assertRaises(ValueError,validate_external_fragments,self.root)
        path.write_text(original)

    def test_external_portal_dockerfile_oidc_and_caddy_reference_changes_are_denied(self):
        path=self.root/'vendor/reseller-portal-postgres/compose.yaml';original=path.read_text()
        for changed in (original.replace('deploy/reseller-portal/Dockerfile','other/Dockerfile'),original.replace('./oauth2-proxy.cfg','./untrusted.cfg')):
            path.write_text(changed);self.assertRaises(ValueError,validate_external_fragments,self.root)
        path.write_text(original)
        path=self.root/'vendor/private-vicidial-ingress/Caddyfile';path.write_text(path.read_text().replace('/etc/caddy/snippets/breero-private-route','/etc/caddy/other'))
        self.assertRaises(ValueError,validate_external_fragments,self.root)

    def test_all_default_environment_inputs_are_exact_and_unknown_inputs_fail(self):
        for file in sorted([*ROOT.glob('components/**/compose*.yaml'),*ROOT.glob('vendor/**/compose*.yaml')]):
            for service in yaml.safe_load(file.read_text())['services'].values():validate_env_references(service)
        for references in ('/unreviewed.env',[{'path':'/unreviewed.env'}],None):
            self.assertRaises(ValueError,validate_env_references,{'env_file':references})

    def test_parser_copy_is_byte_identical_and_has_no_file_capability(self):
        source=self.root/'parser-source';source.write_bytes(b'isolated parser fixture')
        target=self.root/'parser-copy';digest=hashlib.sha256(source.read_bytes()).hexdigest()
        capability_free_parser_copy(source,target,digest)
        self.assertEqual(source.read_bytes(),target.read_bytes())
        self.assertEqual(target.stat().st_mode & 0o777,0o755)
        self.assertRaises(FileExistsError,capability_free_parser_copy,source,target,digest)

    def test_parser_wrong_source_hash_or_retained_filecap_fails(self):
        source=self.root/'parser-source';source.write_bytes(b'isolated parser fixture')
        self.assertRaises(ValueError,capability_free_parser_copy,source,self.root/'wrong','0'*64)
        digest=hashlib.sha256(source.read_bytes()).hexdigest()
        with patch('vendor_config_contract.os.listxattr',return_value=['security.capability']):
            self.assertRaises(ValueError,capability_free_parser_copy,source,self.root/'retained',digest)

    def test_vendor_source_cannot_rewrite_its_expected_blob(self):
        path=next(iter(FROZEN_VENDOR_FILES));file=self.root/path;file.write_bytes(file.read_bytes()+b'changed')
        raw=file.read_bytes();import hashlib
        self.inventory[path]['blob']=hashlib.sha1(f'blob {len(raw)}\0'.encode()+raw).hexdigest()
        self.assertRaises(ValueError,validate_vendor_authority,self.root,self.inventory)

if __name__=='__main__':unittest.main()
