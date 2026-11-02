from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
from unittest.mock import MagicMock, patch
from component_helpers import NoEgressTest, load_component

worker=load_component('sms-api','app/event_worker.py')

class WorkerTests(NoEgressTest):
    def row(self, attempts=0):
        return {'id':1,'event_id':'ci-event','customer_code':'SYNTHETIC-CI','correlation_id':'ci-correlation','payload':{'synthetic':True},'event_type':'sms.delivered','event_version':'1.0','created_at':datetime(2026,1,1,tzinfo=timezone.utc),'attempt_count':attempts}

    def test_envelope_preserves_tenant_idempotency_retry_and_source(self):
        result=worker.envelope(self.row(2))
        self.assertEqual(result['tenant_id'],'SYNTHETIC-CI');self.assertEqual(result['idempotency_key'],'ci-event')
        self.assertEqual(result['metadata']['retry_attempt'],3);self.assertEqual(result['event_type'],'telnexa.sms.delivered')

    def test_delivery_signature_binds_exact_event_and_body(self):
        response=MagicMock();response.__enter__.return_value.status=202
        with patch.dict(os.environ,{'TELNEXA_WEBHOOK_SECRET':'ci-only-secret','TELNEXA_MIDDLEWARE_API_KEY':'ci-only-key','SMS_EVENT_CONTROL_PLANE_URL':'https://invalid.test'}),patch.object(worker.urllib.request,'urlopen',return_value=response) as network:
            worker.deliver(self.row())
        request=network.call_args.args[0];stamp=request.headers['X-timestamp']
        expected=hmac.new(b'ci-only-secret',b'\n'.join((stamp.encode(),b'ci-event',b'telnexa',request.data)),hashlib.sha256).hexdigest()
        self.assertEqual(request.headers['X-signature'],'sha256='+expected)
        self.assertEqual(json.loads(request.data)['customer_id'],'SYNTHETIC-CI')

    def test_once_has_no_work_without_delivery(self):
        conn=MagicMock();conn.execute.return_value.fetchone.return_value=None
        with patch.object(worker,'deliver') as deliver:self.assertFalse(worker.once(conn));deliver.assert_not_called()

    def test_once_success_and_failure_use_transactional_states(self):
        for attempts, outcome in ((0,'failed'),(4,'dead_letter')):
            conn=MagicMock();conn.execute.return_value.fetchone.return_value=self.row(attempts)
            with patch.object(worker,'deliver',side_effect=RuntimeError('ci-only')):self.assertTrue(worker.once(conn))
            args=conn.execute.call_args.args[1]
            self.assertEqual(args[0],outcome);self.assertEqual(args[1],attempts+1)
            self.assertEqual(args[2],'RuntimeError')
            self.assertTrue(conn.transaction.called)
        conn=MagicMock();conn.execute.return_value.fetchone.return_value=self.row()
        with patch.object(worker,'deliver'):self.assertTrue(worker.once(conn))
        self.assertIn("delivery_state='delivered'",conn.execute.call_args.args[0])

    def test_unaccepted_control_plane_status_fails(self):
        response=MagicMock();response.__enter__.return_value.status=500
        with patch.dict(os.environ,{'TELNEXA_WEBHOOK_SECRET':'ci-only-secret','TELNEXA_MIDDLEWARE_API_KEY':'ci-only-key','SMS_EVENT_CONTROL_PLANE_URL':'https://invalid.test'}),patch.object(worker.urllib.request,'urlopen',return_value=response):
            self.assertRaises(RuntimeError,worker.deliver,self.row())

    def test_bounded_startup_recovers_processing_without_starting_loop(self):
        conn=MagicMock();connection=MagicMock();connection.__enter__.return_value=conn
        with patch.object(worker,'running',False),patch.object(worker.signal,'signal'),patch.object(worker.psycopg,'connect',return_value=connection),patch.dict(os.environ,{'DATABASE_URL':'ci-only-mocked'}):
            worker.main()
        self.assertIn("WHERE delivery_state='processing'",conn.execute.call_args.args[0])
        self.assertIn("delivery_state='failed'",conn.execute.call_args.args[0])
