import hashlib
import hmac
import io
import json
import os
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch
from component_helpers import NoEgressTest, load_component

gateway = load_component('private-integration-gateway','gateway.py')

class GatewayBehaviorTests(NoEgressTest):
    def setUp(self):
        super().setUp(); directory=tempfile.TemporaryDirectory(); self.addCleanup(directory.cleanup)
        guard=patch.object(gateway,'DB',str(Path(directory.name)/'gateway.db'));guard.start();self.addCleanup(guard.stop)
        guard=patch.dict(os.environ,{'TELNEXA_MIDDLEWARE_API_KEY':'ci-only-key','TELNEXA_WEBHOOK_SECRET':'ci-only-secret'});guard.start();self.addCleanup(guard.stop)
        gateway.initialize()

    def handler(self, payload=None, event='ci-event-123', stamp=None):
        payload = payload or {'message_id':'ci-message','tenant_id':'ci-tenant','correlation_id':'ci-correlation'}
        body=json.dumps(payload).encode();stamp=stamp or str(int(gateway.time.time()))
        signature=hmac.new(b'ci-only-secret',gateway.canonical(stamp,event,'telnexa',body),hashlib.sha256).hexdigest()
        h=gateway.Handler.__new__(gateway.Handler);h.path='/api/v1/telnexa/dlr'
        h.headers={'Authorization':'Bearer ci-only-key','X-Telnexa-Timestamp':stamp,'X-Telnexa-Event-Id':event,'X-Telnexa-Signature':'sha256='+signature,'X-Source-System':'telnexa','Content-Length':str(len(body))}
        h.rfile=io.BytesIO(body);h.send_json=MagicMock();return h,body

    def test_signed_ingress_replay_and_distinct_lifecycle_events(self):
        h,body=self.handler();h.ingress('telnexa',body);self.assertEqual(h.send_json.call_args.args[0],202)
        h.ingress('telnexa',body);self.assertEqual(h.send_json.call_args.args[0],409)
        h,body=self.handler(event='ci-event-456');h.ingress('telnexa',body)
        self.assertEqual(h.send_json.call_args.args[0],202)
        with gateway.db() as conn:self.assertEqual(conn.execute('SELECT count(*) FROM events').fetchone()[0],2)

    def test_expired_wrong_source_signature_and_key_denied(self):
        cases=[('Authorization','Bearer bad'),('X-Source-System','other'),('X-Telnexa-Signature','sha256=wrong'),('X-Telnexa-Timestamp','1')]
        for field,value in cases:
            h,body=self.handler();h.headers[field]=value;h.ingress('telnexa',body)
            self.assertEqual(h.send_json.call_args.args[0],401)

    def test_bound_body_and_unknown_mode_are_denied(self):
        h,body=self.handler();h.ingress('telnexa',body+b' ');self.assertEqual(h.send_json.call_args.args[0],401)
        h,body=self.handler()
        with patch.object(gateway,'MODE','invalid'):h.do_POST()
        self.assertEqual(h.send_json.call_args.args[0],404)

    def test_outbound_mock_is_idempotent_and_never_submits_to_carrier(self):
        h,_=self.handler();payload={'customer_id':'ci','to':'test','body':'test','idempotency_key':'isolated-id'}
        for duplicate in (False,True):
            h.outbound(json.dumps(payload).encode());result=h.send_json.call_args.args[1]
            self.assertEqual(result['duplicate'],duplicate);self.assertFalse(result['carrier_submitted'])

    def test_delivery_failure_retries_and_dead_letters_without_network(self):
        h,body=self.handler();h.ingress('telnexa',body)
        with gateway.db() as conn:row=dict(conn.execute('SELECT * FROM events').fetchone())
        with patch.dict(os.environ,{'DOWNSTREAM_CONTROL_PLANE_URL':'https://invalid.test'}):
            gateway.deliver(row)
            with gateway.db() as conn:failed=dict(conn.execute('SELECT * FROM events').fetchone())
            self.assertEqual(failed['state'],'queued');self.assertEqual(failed['attempts'],1)
            row['attempts']=4;gateway.deliver(row)
        with gateway.db() as conn:self.assertEqual(conn.execute('SELECT state FROM events').fetchone()[0],'dead_letter')

    def test_successful_delivery_binds_signed_event_identity(self):
        h,body=self.handler();h.ingress('telnexa',body)
        with gateway.db() as conn:row=dict(conn.execute('SELECT * FROM events').fetchone())
        response=MagicMock();response.__enter__.return_value.status=202
        with patch.dict(os.environ,{'DOWNSTREAM_CONTROL_PLANE_URL':'https://invalid.test'}),patch.object(gateway.urllib.request,'urlopen',return_value=response) as network:
            gateway.deliver(row)
        request=network.call_args.args[0];envelope=json.loads(request.data)
        self.assertEqual(envelope['idempotency_key'],'gateway:telnexa:ci-event-123')
        self.assertEqual(envelope['tenant_id'],'ci-tenant')
        with gateway.db() as conn:self.assertEqual(conn.execute('SELECT state FROM events').fetchone()[0],'delivered')
