"""Exercise actual nginx routing and the authorizer with controlled auth services."""
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
NGINX = os.environ.get("NGINX", shutil.which("nginx"))
TOKEN = "a" * 43


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args):
        return None


class Stub(BaseHTTPRequestHandler):
    fga_available = True

    def do_GET(self):
        if self.server.server_port == 4180:
            valid = "__Host-cluster_sso=valid" in self.headers.get("Cookie", "")
            self.send_response(202 if valid else 401)
            if valid:
                self.send_header("X-Auth-Request-User", "alice")
            self.end_headers()
        else:
            body = json.dumps(dict(self.headers)).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    def do_POST(self):
        data = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        allowed = data["tuple_key"]["object"] in ("clustersite:home.internal", "clustersite:s3.internal")
        body = json.dumps({"allowed": allowed}).encode()
        self.send_response(200 if self.fga_available else 503)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        pass


@unittest.skipUnless(NGINX, "Set NGINX to run live reverse-proxy tests")
class EdgeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory()
        cls.path = Path(cls.directory.name)
        cls.processes, cls.servers = [], []
        cls.log = tempfile.TemporaryFile()
        cls.addClassCleanup(cls.stop)
        for port in (4180, 19090, 19091):
            server = ThreadingHTTPServer(("127.0.0.1", port), Stub)
            threading.Thread(target=server.serve_forever, daemon=True).start()
            cls.servers.append(server)
        replacements = {"${DOMAIN}": "internal", "${ADMIN_DOMAIN}": "admin.internal", "${CLUSTER_DNS_IP}": "127.0.0.1"}
        raw = (ROOT / "apps/edge/nginx.conf").read_text()
        sites = (ROOT / "apps/edge/sites.json").read_text()
        for source, destination in replacements.items():
            raw, sites = raw.replace(source, destination), sites.replace(source, destination)
        raw = re.sub(r"[a-z0-9.-]+\.svc\.cluster\.local:[0-9]+", "127.0.0.1:19090", raw)
        raw = raw.replace("listen 8080", "listen 18088").replace("/tmp/", str(cls.path) + "/")
        raw = raw.replace("worker_processes auto", "worker_processes 1")
        if os.geteuid() == 0:
            raw = "user root;\n" + raw
        (cls.path / "nginx.conf").write_text(raw)
        (cls.path / "sites.json").write_text(sites)
        (cls.path / "openfga.json").write_text(json.dumps({"store_id": "0" * 26, "model_id": "1" * 26}))
        (cls.path / "agents.json").write_text(json.dumps({hashlib.sha256(TOKEN.encode()).hexdigest(): {
            "principal": "agent:backup", "expires_at": int(time.time()) + 3600}}))
        (cls.path / "openfga-token").write_text("test")
        (cls.path / "logs").mkdir()
        env = dict(os.environ, AUTHN_CONFIG=str(cls.path), AUTHN_SECRETS=str(cls.path),
                   AUTHN_STATE=str(cls.path), OPENFGA_URL="http://127.0.0.1:19091")
        cls.processes.append(subprocess.Popen([os.sys.executable, str(ROOT / "apps/edge/authorizer.py")],
                                              env=env, stdout=cls.log, stderr=cls.log))
        cls.processes.append(subprocess.Popen([NGINX, "-p", str(cls.path) + "/", "-c", str(cls.path / "nginx.conf"),
                                              "-g", "daemon off;"], stdout=cls.log, stderr=cls.log))
        for _ in range(100):
            try:
                cls.get("unknown", "/healthz")
                urllib.request.urlopen("http://127.0.0.1:9080/healthz", timeout=1).close()
                break
            except OSError:
                if any(p.poll() is not None for p in cls.processes):
                    cls.log.seek(0)
                    raise RuntimeError(cls.log.read().decode())
                time.sleep(0.05)
        else:
            raise RuntimeError("Edge failed to start")

    @classmethod
    def stop(cls):
        for process in cls.processes:
            process.terminate()
            process.wait(timeout=5)
        for server in cls.servers:
            server.shutdown()
            server.server_close()
        cls.log.close()
        cls.directory.cleanup()

    @classmethod
    def get(cls, host, path="/", headers=None):
        request = urllib.request.Request("http://127.0.0.1:18088" + path, headers={"Host": host, **(headers or {})})
        opener = urllib.request.build_opener(NoRedirect)
        try:
            response = opener.open(request, timeout=3)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            return response.status, response.headers, response.read()

    def test_no_login_and_forged_headers_cannot_reach_an_upstream(self):
        status, headers, _ = self.get("home.internal", headers={"X-Auth-Request-User": "admin", "X-Cluster-Principal": "user:admin"})
        self.assertEqual(status, 302)
        self.assertEqual(headers["Location"], "https://home.internal/oauth2/start?rd=/")

    def test_authentication_does_not_imply_admin_access(self):
        self.assertEqual(self.get("longhorn.admin.internal", headers={"Cookie": "__Host-cluster_sso=valid"})[0], 403)

    def test_upstream_receives_verified_identity_and_no_credentials(self):
        status, _, body = self.get("home.internal", headers={"Cookie": "__Host-cluster_sso=valid; app=session",
                                                           "X-Forwarded-User": "admin", "X-Cluster-Principal": "user:admin"})
        self.assertEqual(status, 200)
        headers = json.loads(body)
        self.assertEqual(headers["X-Cluster-Principal"], "user:alice")
        self.assertEqual(headers["X-Forwarded-User"], "user:alice")
        self.assertEqual(headers["Cookie"], "app=session")
        self.assertNotIn("Authorization", headers)

    def test_s3_retains_sigv4_but_strips_site_token(self):
        status, _, body = self.get("s3.internal", headers={"Authorization": "AWS4-HMAC-SHA256 example", "X-Cluster-Token": TOKEN})
        self.assertEqual(status, 200)
        headers = json.loads(body)
        self.assertEqual(headers["Authorization"], "AWS4-HMAC-SHA256 example")
        self.assertEqual(headers["X-Cluster-Principal"], "agent:backup")
        self.assertNotIn("X-Cluster-Token", headers)

    def test_machine_denials_do_not_redirect_to_browser_login(self):
        self.assertEqual(self.get("home.internal", headers={"Authorization": "Bearer invalid"})[0], 401)

    def test_authorization_outage_fails_closed(self):
        Stub.fga_available = False
        try:
            self.assertGreaterEqual(self.get("home.internal", headers={"Cookie": "__Host-cluster_sso=valid"})[0], 500)
        finally:
            Stub.fga_available = True

    def test_internal_auth_location_and_unknown_hosts_are_not_public(self):
        self.assertEqual(self.get("home.internal", "/_authn_check")[0], 404)
        self.assertEqual(self.get("unknown.internal")[0], 404)
        self.assertEqual(self.get("auth.internal", "/if/admin/")[0], 404)

    def test_identity_discovery_requires_authentication_but_not_a_site_grant(self):
        status, _, body = self.get("longhorn.admin.internal", "/authn/identity", {"Cookie": "__Host-cluster_sso=valid"})
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body), {"principal": "user:alice"})

    def test_identity_login_returns_to_identity_before_any_site_grant(self):
        status, headers, _ = self.get("longhorn.admin.internal", "/authn/identity")
        self.assertEqual(status, 302)
        self.assertEqual(headers["Location"],
                         "https://longhorn.admin.internal/oauth2/start?rd=/authn/identity")

    def test_invalid_agent_at_identity_does_not_start_browser_login(self):
        status, _, _ = self.get("home.internal", "/authn/identity",
                                {"Authorization": "Bearer invalid"})
        self.assertEqual(status, 401)


if __name__ == "__main__":
    unittest.main()
