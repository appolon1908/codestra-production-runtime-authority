"""Disposable PostgreSQL contracts. Refuse every non-CI database identity."""
import hashlib
import hmac
import json
import os
from pathlib import Path
import time
import unittest
from unittest.mock import MagicMock, patch
import psycopg
from psycopg.conninfo import conninfo_to_dict
from psycopg.rows import dict_row
from component_helpers import ROOT, load_component

main=load_component('sms-api','app/main.py')
worker=load_component('sms-api','app/event_worker.py')

class PostgresContracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dsn=os.environ['CI_DATABASE_URL']
        params=conninfo_to_dict(cls.dsn)
        if os.environ.get('CI_DATABASE_ISOLATED')!='true' or params.get('dbname')!='codestra_ci' or params.get('host') not in ('127.0.0.1','localhost','authority-postgres-ci'):
            raise RuntimeError('Only the disposable CI PostgreSQL identity is permitted')
        cls.conn=psycopg.connect(cls.dsn,row_factory=dict_row,autocommit=True)
        for file in sorted((ROOT/'components/sms-api/migrations').glob('*.sql')):cls.conn.execute(file.read_text())

    @classmethod
    def tearDownClass(cls):cls.conn.close()

    def setUp(self):
        self.conn.execute('TRUNCATE sms_accounts CASCADE')
        # Seed the latest schema directly; historical migration002 predates
        # provider_sender NOTNULL and must not be replayed as a current fixture.
        account=self.conn.execute("INSERT INTO sms_accounts(kong_consumer_id,customer_code,status,sms_entitled,balance) VALUES('2a9add4c-70fa-4e12-9b62-ed3d1090349a','SYNTHETIC-A','active',true,10) RETURNING id").fetchone()['id']
        self.conn.execute("INSERT INTO sms_account_limits(account_id,messages_per_minute,max_segments,duplicate_window_seconds) VALUES(%s,2,6,300)",(account,))
        self.conn.execute("INSERT INTO sms_sender_profiles(account_id,sender,sender_type,country_codes,provider_sender) VALUES(%s,'CODESTRA','alphanumeric',ARRAY['+1809'],'TEST')",(account,))
        env={'DATABASE_URL':self.dsn,'LIVE_SUBMISSION_ENABLED':'false','LIVE_SMS_DELIVERY':'false','TELNEXA_BASE_URL':'https://invalid.test','TELNEXA_CLIENT_CERT_FILE':'/ci-only/client.crt','TELNEXA_CLIENT_KEY_FILE':'/ci-only/client.key','TELNEXA_CA_FILE':'/ci-only/ca.crt','TELNEXA_MIDDLEWARE_API_KEY':'ci-fixture-key','TELNEXA_WEBHOOK_SECRET':'ci-fixture-secret','SMS_DLR_TOKEN':'ci-fixture-token'}
        guard=patch.dict(os.environ,env);guard.start();self.addCleanup(guard.stop)
        guard=patch.object(main,'verifier',return_value=hashlib.sha256(b'ci-gateway').hexdigest());guard.start();self.addCleanup(guard.stop)
        self.headers={'X-Codestra-Gateway-Token':'ci-gateway','X-Consumer-ID':'2a9add4c-70fa-4e12-9b62-ed3d1090349a','Idempotency-Key':'ci-message-001','X-Correlation-ID':'ci-correlation'}
        self.client=main.app.test_client()

    def submit(self, **data):
        payload={'to':'+18095550123','from':'CODESTRA','text':'isolated contract','synthetic':True};payload.update(data)
        receipt=MagicMock(status_code=202);receipt.json.return_value={'accepted':True,'carrier_submitted':False,'adapter_message_id':'ci-adapter-001'}
        with patch.object(main.requests,'post',return_value=receipt) as provider:
            response=self.client.post('/messages',json=payload,headers=self.headers)
        return response,provider

    def dlr(self,message,status='DELIVRD',event='ci-event-0001'):
        payload={'event_id':event,'message_id':message,'status':status,'customer_id':'SYNTHETIC-A','correlation_id':'ci-correlation'}
        body=json.dumps(payload).encode();stamp=str(int(time.time()))
        signature=hmac.new(b'ci-fixture-secret',stamp.encode()+b'\n'+event.encode()+b'\ntelnexa\n'+body,hashlib.sha256).hexdigest()
        headers={'Authorization':'Bearer ci-fixture-token','X-Telnexa-Timestamp':stamp,'X-Telnexa-Event-Id':event,'X-Telnexa-Signature':'sha256='+signature,'X-Source-System':'telnexa','Content-Type':'application/json'}
        return self.client.post('/internal/dlr',data=body,headers=headers)

    def test_all_migrations_and_database_constraints(self):
        tables=self.conn.execute("SELECT tablename FROM pg_tables WHERE schemaname='public'").fetchall()
        self.assertIn('sms_dlr_dead_letters',{x['tablename'] for x in tables})
        self.assertIn('sms_internal_events',{x['tablename'] for x in tables})
        with self.assertRaises(psycopg.errors.CheckViolation):
            self.conn.execute("UPDATE sms_accounts SET balance=-1 WHERE customer_code='SYNTHETIC-A'")
        self.assertEqual(self.conn.execute("SELECT balance FROM sms_accounts WHERE customer_code='SYNTHETIC-A'").fetchone()['balance'],10)

    def test_synthetic_submission_is_idempotent_and_reserves_once(self):
        response,provider=self.submit();self.assertEqual(response.status_code,202,response.get_data(as_text=True));provider.assert_called_once()
        request=json.loads(provider.call_args.kwargs['data']);self.assertEqual(request['sender'],'TEST')
        response,provider=self.submit();self.assertEqual(response.status_code,200,response.get_data(as_text=True));provider.assert_not_called()
        self.assertEqual(self.conn.execute('SELECT count(*) n FROM sms_balance_ledger').fetchone()['n'],1)
        self.assertEqual(self.conn.execute("SELECT balance FROM sms_accounts WHERE customer_code='SYNTHETIC-A'").fetchone()['balance'],__import__('decimal').Decimal('9.99'))
        response,_=self.submit(text='changed');self.assertEqual(response.status_code,409)

    def test_live_submission_disabled_before_provider_request(self):
        response,provider=self.submit(synthetic=False)
        self.assertEqual(response.status_code,503,response.get_data(as_text=True));provider.assert_not_called()
        self.assertEqual(self.conn.execute('SELECT count(*) n FROM sms_messages').fetchone()['n'],0)

    def test_signed_dlr_duplicate_conflict_and_synthetic_ledger_safety(self):
        response,_=self.submit();self.assertEqual(response.status_code,202,response.get_data(as_text=True));message=response.json['message_id']
        response=self.dlr(message);self.assertEqual(response.status_code,200,response.get_data(as_text=True))
        response=self.dlr(message);self.assertTrue(response.json['duplicate'])
        response=self.dlr(message,'FAILED');self.assertEqual(response.status_code,409)
        self.assertEqual(self.conn.execute('SELECT state FROM sms_balance_ledger').fetchone()['state'],'provisional')
        self.assertEqual(self.conn.execute('SELECT count(*) n FROM sms_dlr_events').fetchone()['n'],1)
        self.assertEqual(self.conn.execute('SELECT count(*) n FROM sms_dlr_dead_letters').fetchone()['n'],1)

    def test_worker_claims_and_delivers_actual_database_event_without_network(self):
        response,_=self.submit();self.assertEqual(response.status_code,202,response.get_data(as_text=True))
        with patch.object(worker,'deliver') as deliver:self.assertTrue(worker.once(self.conn));deliver.assert_called_once()
        self.assertEqual(self.conn.execute('SELECT delivery_state FROM sms_internal_events').fetchone()['delivery_state'],'delivered')
        with patch.object(worker,'deliver') as deliver:self.assertFalse(worker.once(self.conn));deliver.assert_not_called()

    def test_carrier_fixture_failure_releases_reservation_exactly_once(self):
        response,_=self.submit();self.assertEqual(response.status_code,202,response.get_data(as_text=True));message=response.json['message_id']
        # Database-only fixture: never enable live submission or contact a carrier.
        self.conn.execute('UPDATE sms_messages SET carrier_submitted=true WHERE id=%s',(message,))
        response=self.dlr(message,'FAILED');self.assertEqual(response.status_code,200,response.get_data(as_text=True))
        self.assertEqual(self.conn.execute('SELECT state FROM sms_balance_ledger').fetchone()['state'],'released')
        self.assertEqual(self.conn.execute("SELECT balance FROM sms_accounts WHERE customer_code='SYNTHETIC-A'").fetchone()['balance'],10)
        self.dlr(message,'FAILED')
        self.assertEqual(self.conn.execute("SELECT balance FROM sms_accounts WHERE customer_code='SYNTHETIC-A'").fetchone()['balance'],10)

    def test_carrier_fixture_delivered_finalizes_and_stale_status_cannot_regress(self):
        response,_=self.submit();self.assertEqual(response.status_code,202,response.get_data(as_text=True));message=response.json['message_id']
        self.conn.execute('UPDATE sms_messages SET carrier_submitted=true WHERE id=%s',(message,))
        self.assertEqual(self.dlr(message).status_code,200)
        self.assertEqual(self.conn.execute('SELECT state FROM sms_balance_ledger').fetchone()['state'],'finalized')
        self.assertEqual(self.dlr(message,'FAILED','ci-stale-0002').status_code,200)
        self.assertEqual(self.conn.execute('SELECT status FROM sms_messages').fetchone()['status'],'delivered')
        self.assertEqual(self.conn.execute('SELECT state FROM sms_balance_ledger').fetchone()['state'],'finalized')

    def test_worker_retry_limit_is_enforced_by_actual_postgres_state(self):
        response,_=self.submit();self.assertEqual(response.status_code,202,response.get_data(as_text=True))
        for attempt in range(1,6):
            self.conn.execute('UPDATE sms_internal_events SET next_retry_at=now()')
            with patch.object(worker,'deliver',side_effect=RuntimeError('isolated failure')):self.assertTrue(worker.once(self.conn))
            row=self.conn.execute('SELECT delivery_state,attempt_count FROM sms_internal_events').fetchone()
            self.assertEqual(row['attempt_count'],attempt)
            self.assertEqual(row['delivery_state'],'dead_letter' if attempt==5 else 'failed')
        with patch.object(worker,'deliver') as provider:self.assertFalse(worker.once(self.conn));provider.assert_not_called()

    def test_readiness_and_metrics_use_disposable_database(self):
        self.assertEqual(self.client.get('/readyz').status_code,200)
        response=self.client.get('/metrics');self.assertEqual(response.status_code,200)
        self.assertIn('codestra_sms_',response.get_data(as_text=True))

if __name__=='__main__':unittest.main()
