"""Exercise the real Heimdall binary with controlled identity and application servers."""
import copy
import http.client
import http.server
import json
import pathlib
import socket
import subprocess
import tempfile
import threading
import time
import unittest
from urllib.parse import parse_qs, urlsplit

import yaml

ROOT = pathlib.Path(__file__).resolve().parents[1]

class Backend(http.server.BaseHTTPRequestHandler):
    calls = []
    identity_status = 200

    def log_message(self, *_):
        pass

    def do_GET(self):
        if self.path == "/oauth2/userinfo":
            status = self.identity_status if self.headers.get("Cookie") == "__Secure-elektro_admin=valid" else 401
            body = {"user": "stable-subject", "email": "admin@example.com"}
        else:
            status, body = 200, {"path": self.path, "headers": dict(self.headers)}
            self.calls.append((self.command, self.path))
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(body).encode())

    do_POST = do_GET

def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]

class ProxyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.backend = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Backend)
        threading.Thread(target=cls.backend.serve_forever, daemon=True).start()
        cls.directory = tempfile.TemporaryDirectory()
        directory = pathlib.Path(cls.directory.name)
        values = yaml.safe_load((ROOT / "infrastructure/heimdall/release.yaml").read_text())["spec"]["values"]
        config = {k: copy.deepcopy(values[k]) for k in ("serve", "management", "log", "metrics", "tracing", "mechanisms", "default_rule", "providers")}
        cls.port = free_port()
        config["serve"]["host"] = "127.0.0.1"
        config["serve"]["port"] = cls.port
        config["management"]["host"] = "127.0.0.1"
        config["management"]["port"] = free_port()
        config["providers"]["file_system"]["src"] = str(directory / "rules")
        endpoint = f"127.0.0.1:{cls.backend.server_port}"
        config["mechanisms"]["authenticators"][2]["config"]["identity_info_endpoint"]["url"] = f"http://{endpoint}/oauth2/userinfo"
        rules = yaml.safe_load((ROOT / "infrastructure/heimdall/rules.yaml").read_text())
        for rule in rules["rules"]:
            rule["forward_to"]["host"] = endpoint
        (directory / "rules").mkdir()
        (directory / "rules/rules.yaml").write_text(yaml.safe_dump(rules))
        (directory / "config.yaml").write_text(yaml.safe_dump(config))
        cls.log = open(directory / "heimdall.log", "w+")
        cls.process = subprocess.Popen(["heimdall", "serve", "proxy", "-c", str(directory / "config.yaml"), *values["extraArgs"]],
                                       stdout=cls.log, stderr=subprocess.STDOUT)
        for _ in range(100):
            if cls.process.poll() is not None:
                cls.log.seek(0)
                raise RuntimeError(cls.log.read())
            try:
                # Rule providers initialize asynchronously; wait for a known rule.
                if cls.request(host="sso.admin.internal", path="/oauth2/start")[0] == 200:
                    break
            except OSError:
                pass
            time.sleep(0.1)
        else:
            cls.process.terminate()
            cls.log.seek(0)
            raise RuntimeError(cls.log.read())

    @classmethod
    def tearDownClass(cls):
        cls.process.terminate()
        cls.process.wait(timeout=10)
        cls.backend.shutdown()
        cls.backend.server_close()
        cls.log.close()
        cls.directory.cleanup()

    @classmethod
    def request(cls, host="longhorn.admin.internal", path="/", method="GET", **headers):
        conn = http.client.HTTPConnection("127.0.0.1", cls.port, timeout=5)
        conn.request(method, path, headers={"Host": host, **headers})
        response = conn.getresponse()
        result = response.status, dict(response.getheaders()), response.read()
        conn.close()
        return result

    def setUp(self):
        Backend.calls.clear()
        Backend.identity_status = 200

    def test_anonymous_api_and_forged_identity_are_denied(self):
        self.assertEqual(self.request(**{"X-Authenticated-Subject": "admin"})[0], 401)
        self.assertEqual(Backend.calls, [])

    def test_browser_redirect_preserves_url_and_ignores_forwarded_headers(self):
        status, headers, _ = self.request(path="/v1/volumes?limit=20", Accept="text/html",
                                          **{"X-Forwarded-Host": "attacker.example", "X-Forwarded-Uri": "/oauth2/callback"})
        self.assertIn(status, (302, 303, 307))
        redirect = urlsplit(headers["Location"])
        self.assertEqual(redirect.netloc, "sso.admin.internal")
        self.assertEqual(parse_qs(redirect.query)["rd"], ["https://longhorn.admin.internal/v1/volumes?limit=20"])
        self.assertEqual(Backend.calls, [])

    def test_valid_session_reaches_app_without_leaking_cookie(self):
        status, _, body = self.request(Cookie="__Secure-elektro_admin=valid")
        self.assertEqual(status, 200)
        headers = {k.lower(): v for k, v in json.loads(body)["headers"].items()}
        self.assertEqual(headers.get("cookie"), "authn=redacted")
        self.assertEqual(headers["x-authenticated-subject"], "stable-subject")

    def test_invalid_session_and_identity_outage_fail_closed(self):
        self.assertEqual(self.request(Cookie="__Secure-elektro_admin=forged")[0], 401)
        Backend.identity_status = 503
        self.assertGreaterEqual(self.request(Cookie="__Secure-elektro_admin=valid")[0], 500)
        self.assertEqual(Backend.calls, [])

    def test_unknown_host_and_private_oauth_endpoint_are_denied(self):
        for host, path in [("unknown.admin.internal", "/"), ("sso.admin.internal", "/oauth2/userinfo"),
                           ("longhorn.admin.internal", "/oauth2/callback")]:
            self.assertEqual(self.request(host=host, path=path)[0], 401)
        self.assertEqual(Backend.calls, [])

    def test_writes_require_origin_even_with_valid_session(self):
        self.assertEqual(self.request(method="POST", Cookie="__Secure-elektro_admin=valid",
                                      Origin="https://other.internal")[0], 403)
        self.assertEqual(Backend.calls, [])
        self.assertEqual(self.request(method="POST", Cookie="__Secure-elektro_admin=valid",
                                      Origin="https://longhorn.admin.internal")[0], 200)

    def test_oauth_callback_is_public_only_on_sso_host(self):
        self.assertEqual(self.request(host="sso.admin.internal", path="/oauth2/callback?code=test")[0], 200)

if __name__ == "__main__":
    unittest.main()
