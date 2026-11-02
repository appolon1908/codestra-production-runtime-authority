import io
from unittest.mock import MagicMock, patch
from component_helpers import NoEgressTest, load_component

adapter = load_component('kong-service-auth-adapter', 'adapter.py')

class AdapterTests(NoEgressTest):
    def handler(self, path='/sms/messages', headers=None, body=b'{}'):
        h = adapter.Handler.__new__(adapter.Handler)
        h.path, h.command = path, 'POST'
        h.headers = headers or {'Content-Length': str(len(body))}
        h.rfile, h.wfile = io.BytesIO(body), io.BytesIO()
        h.send_safe, h.send_response, h.send_header, h.end_headers = [MagicMock() for _ in range(4)]
        return h

    def test_only_exact_prefix_routes_are_proxied(self):
        for path in ('/sms-not', '/crm-attacker', '/other'):
            h = self.handler(path); h.proxy(); h.send_safe.assert_called_once_with(404, b'not found\n')
        self.assertEqual(self.handler('/crm/x?q=1').route()[2], '/v1/crm/x?q=1')

    def test_invalid_length_and_oversized_body_are_denied_before_network(self):
        for length, status in (('bad', 400), (str(adapter.MAX_BODY + 1), 413)):
            h = self.handler(headers={'Content-Length': length}); h.proxy()
            self.assertEqual(h.send_safe.call_args.args[0], status)

    def test_health_is_local_and_does_not_proxy(self):
        h = self.handler('/healthz'); h.proxy(); h.send_safe.assert_called_once_with(200, b'ok\n')

    def test_trusted_route_identity_replaces_customer_header_and_filters_response(self):
        h = self.handler(headers={'Content-Length': '2', 'Host': 'attacker', 'X-Codestra-Gateway-Token': 'untrusted', 'Connection': 'close', 'X-Request-ID': 'ci'})
        conn = MagicMock(); conn.getresponse.return_value.status = 201
        conn.getresponse.return_value.read.return_value = b'accepted'
        conn.getresponse.return_value.getheaders.return_value = [('Server', 'private'), ('Content-Type', 'application/json')]
        with patch.object(adapter.http.client, 'HTTPConnection', return_value=conn) as network:
            h.proxy()
        network.assert_called_once_with('codestra-sms-api-api-1', 8080, timeout=10)
        sent = conn.request.call_args.kwargs['headers']
        self.assertEqual(sent['X-Codestra-Gateway-Token'], adapter.SECRETS['/sms'])
        self.assertEqual(sent['Host'], 'codestra-sms-api-api-1')
        self.assertNotIn('Connection', sent)
        h.send_response.assert_called_once_with(201)
        self.assertNotIn(('Server', 'private'), [c.args for c in h.send_header.call_args_list])
        self.assertEqual(h.wfile.getvalue(), b'accepted'); conn.close.assert_called_once()

    def test_upstream_failure_is_sanitized(self):
        h = self.handler()
        with patch.object(adapter.http.client, 'HTTPConnection', side_effect=RuntimeError('sensitive detail')):
            h.proxy()
        h.send_safe.assert_called_once_with(502, b'upstream unavailable\n')

    def test_invalid_secret_material_is_rejected(self):
        with patch('builtins.open', return_value=io.StringIO('short')):
            self.assertRaises(RuntimeError, adapter.read_secret, '/ci-only')
