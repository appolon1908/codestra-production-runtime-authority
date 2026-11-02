"""Isolated owned-source imports; production paths are never opened."""
import importlib.util
import io
import os
from pathlib import Path
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]

def load_component(name, filename):
    directory = Path(os.environ.get('COMPONENT_SOURCE_ROOT', ROOT / 'components' / name))
    spec = importlib.util.spec_from_file_location(name.replace('-', '_') + '_under_test', directory / filename)
    module = importlib.util.module_from_spec(spec)
    original = open
    def isolated_open(path, *args, **kwargs):
        if str(path).startswith('/run/secrets/'):
            value = ('ci-fixture-' + 'x' * 40)
            return io.BytesIO(value.encode()) if args and 'b' in args[0] else io.StringIO(value)
        return original(path, *args, **kwargs)
    with patch('builtins.open', isolated_open):
        spec.loader.exec_module(module)
    return module

class NoEgressTest(unittest.TestCase):
    def setUp(self):
        for target in ('socket.create_connection', 'socket.socket.connect', 'urllib.request.urlopen', 'http.client.HTTPConnection'):
            guard = patch(target, side_effect=AssertionError('External network is forbidden in source tests'))
            guard.start(); self.addCleanup(guard.stop)
