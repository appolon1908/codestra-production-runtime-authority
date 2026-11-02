import asyncio
import hashlib
import hmac
import json
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, patch
from fastapi import HTTPException
from component_helpers import NoEgressTest, load_component

receiver = load_component('monitoring-receiver', 'app.py')

class Request:
    def __init__(self, body): self.raw = body
    async def body(self): return self.raw

class ReceiverTests(NoEgressTest):
    def setUp(self):
        super().setUp(); directory = tempfile.TemporaryDirectory(); self.addCleanup(directory.cleanup)
        self.addCleanup(patch.stopall)
        patch.object(receiver, 'DB', str(Path(directory.name) / 'alerts.db')).start()
        self.body = json.dumps({'version':'4','groupKey':'ci','status':'firing','alerts':[]}).encode()

    def receive(self, **kwargs):
        args = dict(route='primary', request=Request(self.body), authorization=None, x_codestra_timestamp=None, x_codestra_nonce=None, x_codestra_signature=None)
        args.update(kwargs); return asyncio.run(receiver.receive(**args))

    def test_hmac_acceptance_replay_and_signed_body_binding(self):
        stamp, nonce = str(int(receiver.time.time())), 'isolated-nonce'
        signature = hmac.new(receiver.SECRET, stamp.encode()+b'.'+nonce.encode()+b'.'+self.body, hashlib.sha256).hexdigest()
        args = dict(x_codestra_timestamp=stamp,x_codestra_nonce=nonce,x_codestra_signature=signature)
        result = self.receive(**args); self.assertTrue(result['accepted'])
        with self.assertRaises(HTTPException) as caught: self.receive(**args)
        self.assertEqual(caught.exception.status_code,409)
        with self.assertRaises(HTTPException) as caught: self.receive(**dict(args,x_codestra_nonce='changed'))
        self.assertEqual(caught.exception.status_code,401)

    def test_missing_expired_and_wrong_credentials_are_denied(self):
        for args in ({}, {'authorization':'Bearer wrong'}, {'x_codestra_timestamp':'1','x_codestra_nonce':'ci','x_codestra_signature':'wrong'}):
            with self.assertRaises(HTTPException) as caught: self.receive(**args)
            self.assertEqual(caught.exception.status_code,401)

    def test_route_body_bound_and_schema_enforced(self):
        token = 'Bearer '+receiver.BEARER.decode()
        for args, status in (({'route':'unknown'},404), ({'request':Request(b'x'*262145)},413), ({'request':Request(b'{"unexpected":true}')},422)):
            with self.assertRaises(HTTPException) as caught: self.receive(authorization=token,**args)
            self.assertEqual(caught.exception.status_code,status)

    def test_status_ack_and_dashboard_require_bearer(self):
        result = self.receive(authorization='Bearer '+receiver.BEARER.decode())
        for function, args in ((receiver.ack,(result['id'],)),(receiver.status,(result['id'],)),(receiver.dashboard,())):
            with self.assertRaises(HTTPException): function(*args,authorization='Bearer wrong')
        token = 'Bearer '+receiver.BEARER.decode()
        self.assertFalse(receiver.status(result['id'],token)['acknowledged'])
        self.assertTrue(receiver.ack(result['id'],token)['acknowledged'])
        self.assertTrue(receiver.status(result['id'],token)['acknowledged'])
        self.assertEqual(receiver.dashboard(token)['series'][0]['count'],1)

    def test_rate_limit_and_readiness_use_only_temporary_database(self):
        self.assertEqual(receiver.ready(),{'status':'ready'})
        with receiver.db() as conn:
            conn.executemany('INSERT INTO requests VALUES(?)',[(int(receiver.time.time()),)]*60)
        with self.assertRaises(HTTPException) as caught: self.receive(authorization='Bearer '+receiver.BEARER.decode())
        self.assertEqual(caught.exception.status_code,429)

    def test_finite_escalation_iteration_is_idempotent_and_ack_respected(self):
        result=self.receive(authorization='Bearer '+receiver.BEARER.decode())
        with receiver.db() as conn:conn.execute('UPDATE alerts SET created=?',(int(receiver.time.time())-901,))
        for _ in range(2):
            with patch.object(receiver.asyncio,'sleep',new=AsyncMock(side_effect=StopAsyncIteration)):
                self.assertRaises(StopAsyncIteration,asyncio.run,receiver.escalation_worker())
        with receiver.db() as conn:
            self.assertEqual(conn.execute("SELECT count(*) FROM alerts WHERE route='secondary'").fetchone()[0],1)
            self.assertEqual(conn.execute("SELECT count(*) FROM audit WHERE action='escalate'").fetchone()[0],1)
            conn.execute('DELETE FROM alerts WHERE id=?',('escalation-'+result['id'],))
        receiver.ack(result['id'],'Bearer '+receiver.BEARER.decode())
        with patch.object(receiver.asyncio,'sleep',new=AsyncMock(side_effect=StopAsyncIteration)):
            self.assertRaises(StopAsyncIteration,asyncio.run,receiver.escalation_worker())
        with receiver.db() as conn:self.assertEqual(conn.execute("SELECT count(*) FROM alerts WHERE route='secondary'").fetchone()[0],0)
