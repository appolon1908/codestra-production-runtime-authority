import hashlib
import io
import os
from unittest.mock import patch
from component_helpers import NoEgressTest, load_component

main=load_component('sms-api','app/main.py')

class SmsApiGuardTests(NoEgressTest):
    def test_verifier_requires_exact_sha256_material(self):
        with patch.dict(os.environ,{},clear=True):self.assertRaises(RuntimeError,main.verifier,'TEST')
        with patch.dict(os.environ,{'TEST_SHA256_FILE':'/ci-only'}):
            with patch('builtins.open',return_value=io.StringIO('invalid')):self.assertRaises(RuntimeError,main.verifier,'TEST')
            expected=hashlib.sha256(b'ci-only').hexdigest()
            with patch('builtins.open',return_value=io.StringIO(expected)):
                self.assertEqual(main.verifier('TEST'),expected)

    def test_body_bound_and_gateway_identity_are_denied_before_database(self):
        client=main.app.test_client()
        with patch.object(main,'db',side_effect=AssertionError('No DB access for rejected requests')):
            self.assertEqual(client.post('/v1/messages',data=b'x'*(main.MAX_BODY+1)).status_code,413)
            with patch.object(main,'verifier',return_value=hashlib.sha256(b'expected').hexdigest()):
                self.assertEqual(client.post('/v1/messages',json={}).status_code,401)

    def test_synthetic_and_live_carrier_receipts_stay_fail_closed(self):
        for synthetic,live in ((True,False),(True,True),(False,False),(False,True)):
            expected=not synthetic and live
            self.assertIs(main.validate_carrier_submission(synthetic=synthetic,live_delivery=live,receipt={'carrier_submitted':expected}),expected)
            self.assertRaises(RuntimeError,main.validate_carrier_submission,synthetic=synthetic,live_delivery=live,receipt={'carrier_submitted':not expected})

    def test_unicode_and_extension_segment_boundaries(self):
        self.assertEqual(main.segments('😀'*35),1);self.assertEqual(main.segments('😀'*36),2)
        self.assertEqual(main.segments('€'*80),1);self.assertEqual(main.segments('€'*81),2)
