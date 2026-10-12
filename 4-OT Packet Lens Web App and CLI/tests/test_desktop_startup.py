"""Embedded Qt launcher HTTP readiness tests."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import sys
import threading
import unittest
from unittest import mock

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import desktop

class HealthHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/api/health":
            content = b'{"status":"ok"}'
            self.send_response(200)
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)
        else:
            self.send_error(404)
    def log_message(self, *_):
        pass

class StartupTests(unittest.TestCase):
    def test_health_request_waits_for_real_http_response(self):
        server = ThreadingHTTPServer(('127.0.0.1',0), HealthHandler)
        thread=threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            desktop.wait_for_server(f'http://127.0.0.1:{server.server_port}', thread, timeout=3)
        finally:
            server.shutdown(); server.server_close(); thread.join(timeout=3)

    def test_health_request_fails_for_stopped_server(self):
        thread=mock.Mock()
        thread.is_alive.return_value=False
        with self.assertRaisesRegex(RuntimeError, 'stopped'):
            desktop.wait_for_server('http://127.0.0.1:1', thread, timeout=0.1)

    def test_no_edge_requirement_in_desktop_shell(self):
        source=(ROOT / 'desktop.py').read_text(encoding='utf-8')
        self.assertIn('QWebEngineView', source)
        self.assertIn('QApplication', source)
        self.assertNotIn('msedge.exe', source)
        self.assertIn('127.0.0.1', source)
        self.assertNotIn('0.0.0.0', source)

if __name__ == '__main__':
    unittest.main()
