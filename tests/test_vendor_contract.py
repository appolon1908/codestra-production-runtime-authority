import copy
from pathlib import Path
import shutil
import tempfile
import unittest
import yaml
from vendor_config_contract import ROOT, FROZEN_VENDOR_FILES, validate_vendor_authority, validate_external_fragments

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

    def test_vendor_source_cannot_rewrite_its_expected_blob(self):
        path=next(iter(FROZEN_VENDOR_FILES));file=self.root/path;file.write_bytes(file.read_bytes()+b'changed')
        raw=file.read_bytes();import hashlib
        self.inventory[path]['blob']=hashlib.sha1(f'blob {len(raw)}\0'.encode()+raw).hexdigest()
        self.assertRaises(ValueError,validate_vendor_authority,self.root,self.inventory)

if __name__=='__main__':unittest.main()
