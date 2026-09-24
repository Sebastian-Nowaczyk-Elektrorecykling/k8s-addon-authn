"""Real OpenFGA API tests; use the pinned server with its in-memory test datastore."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.request
from http.server import ThreadingHTTPServer
import threading
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
BINARY = os.environ.get("OPENFGA", shutil.which("openfga"))
sys.path.insert(0, str(ROOT / "scripts"))
import access
sys.path.insert(0, str(ROOT / "apps/edge"))
import permissions


@unittest.skipUnless(BINARY, "Set OPENFGA to run the real authorization-model tests")
class ModelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.log = tempfile.TemporaryFile()
        cls.proc = subprocess.Popen([BINARY, "run", "--datastore-engine=memory", "--http-addr=127.0.0.1:18080",
                                     "--grpc-addr=127.0.0.1:18081", "--playground-enabled=false",
                                     "--authn-method=preshared", "--authn-preshared-keys=test-only"],
                                    stdout=cls.log, stderr=cls.log)
        cls.addClassCleanup(cls.stop)
        for _ in range(100):
            try:
                cls.call("GET", "/healthz")
                break
            except OSError:
                if cls.proc.poll() is not None:
                    cls.log.seek(0)
                    raise RuntimeError(cls.log.read().decode())
                time.sleep(0.1)
        else:
            raise RuntimeError("OpenFGA did not start")
        cls.store = cls.call("POST", "/stores", {"name": "test"})["id"]
        cls.model = cls.call("POST", f"/stores/{cls.store}/authorization-models",
                             json.loads((ROOT / "openfga/model.json").read_text()))["authorization_model_id"]
        cls.call("POST", f"/stores/{cls.store}/write", {"authorization_model_id": cls.model,
                  "writes": {"tuple_keys": [
                      {"user": "user:alice", "relation": "member", "object": "clustersite:home.internal"},
                      {"user": "agent:backup", "relation": "member", "object": "clustersite:s3.internal"}]}})

    @classmethod
    def stop(cls):
        cls.proc.terminate()
        cls.proc.wait(timeout=10)
        cls.log.close()

    @classmethod
    def call(cls, method, path, data=None):
        request = urllib.request.Request("http://127.0.0.1:18080" + path, method=method,
                                         headers={"Content-Type": "application/json", "Authorization": "Bearer test-only"},
                                         data=None if data is None else json.dumps(data).encode())
        with urllib.request.urlopen(request, timeout=3) as response:
            return json.loads(response.read() or "{}")

    def test_users_and_agents_get_only_their_assigned_sites(self):
        for user, host, expected in [
            ("user:alice", "home.internal", True), ("user:alice", "s3.internal", False),
            ("user:bob", "home.internal", False), ("agent:backup", "s3.internal", True),
            ("agent:backup", "home.internal", False), ("agent:alice", "home.internal", False),
            ("user:alice", "longhorn.admin.internal", False),
        ]:
            with self.subTest(user=user, host=host):
                result = self.call("POST", f"/stores/{self.store}/check", {
                    "authorization_model_id": self.model, "consistency": "HIGHER_CONSISTENCY",
                    "tuple_key": {"user": user, "relation": "can_access", "object": "clustersite:" + host}})
                self.assertEqual(result["allowed"], expected)

    def test_revocation_takes_effect(self):
        key = {"user": "user:temporary", "relation": "member", "object": "clustersite:home.internal"}
        for operation, expected in [("writes", True), ("deletes", False)]:
            self.call("POST", f"/stores/{self.store}/write", {
                "authorization_model_id": self.model, operation: {"tuple_keys": [key]}})
            result = self.call("POST", f"/stores/{self.store}/check", {
                "authorization_model_id": self.model, "consistency": "HIGHER_CONSISTENCY",
                "tuple_key": {**key, "relation": "can_access"}})
            self.assertEqual(result["allowed"], expected)

    def test_native_api_requires_a_key_but_health_probe_does_not(self):
        with urllib.request.urlopen("http://127.0.0.1:18080/healthz", timeout=3) as response:
            self.assertEqual(response.status, 200)
        with self.assertRaises(urllib.error.HTTPError) as error:
            urllib.request.urlopen("http://127.0.0.1:18080/stores", timeout=3)
        self.assertEqual(error.exception.code, 401)

    def test_initializer_is_idempotent_and_can_recover_its_state(self):
        state = {}

        def get_state(*args, **kwargs):
            return state.get("configmap")

        def save_state(kind, name, data):
            state["configmap"] = {"data": data}

        with patch.object(access, "get", side_effect=get_state), patch.object(access, "apply", side_effect=save_state):
            access.initialize(self.call)
            initial = json.loads(state["configmap"]["data"]["openfga.json"])
            access.initialize(self.call)
            self.assertEqual(json.loads(state["configmap"]["data"]["openfga.json"]), initial)
            state.clear()
            access.initialize(self.call)
            self.assertEqual(json.loads(state["configmap"]["data"]["openfga.json"]), initial)

    def test_permissions_console_checks_admin_access_and_manages_dynamic_site_grants(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / "sites.json").write_text(json.dumps({"budget.internal": {
                "name": "Budget", "host": "budget.internal", "source": "budget/budget"}}))
            (path / "openfga.json").write_text(json.dumps({"store_id": self.store, "model_id": self.model}))
            (path / "openfga-token").write_text("test-only")
            (path / "rejected.json").write_text("{}")
            self.call("POST", f"/stores/{self.store}/write", {"authorization_model_id": self.model,
                "writes": {"tuple_keys": [{"user": "user:operator", "relation": "member",
                                           "object": "clustersite:" + permissions.HOST}]}})
            with patch.multiple(permissions.authorizer, CONFIG=path, STATE=path, SECRETS=path,
                                OPENFGA_URL="http://127.0.0.1:18080"), patch.object(permissions, "DISCOVERY", path):
                server = ThreadingHTTPServer(("127.0.0.1", 0), permissions.Handler)
                thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
                try:
                    def console(url, principal="user:operator", data=None, origin=True):
                        headers = {"X-Cluster-Principal": principal}
                        if data is not None:
                            headers.update({"Content-Type": "application/json", "X-Requested-With": "authn-permissions"})
                            if origin: headers["Origin"] = "https://" + permissions.HOST
                        req = urllib.request.Request(f"http://127.0.0.1:{server.server_port}" + url,
                            headers=headers, data=None if data is None else json.dumps(data).encode())
                        try:
                            response = urllib.request.urlopen(req, timeout=3)
                        except urllib.error.HTTPError as error:
                            response = error
                        with response:
                            raw = response.read()
                            self.assertNotIn(b"test-only", raw, "Native API key must never reach the browser")
                            return response.status, raw

                    for principal in ("", "user:alice", "agent:backup"):
                        self.assertEqual(console("/api/catalog", principal=principal)[0], 403)
                    self.assertEqual(console("/api/catalog")[0], 200)
                    grant = {"action": "grant", "principal": "user:console-test", "host": "budget.internal"}
                    self.assertEqual(console("/api/membership", data=grant, origin=False)[0], 403)
                    self.assertEqual(console("/api/membership", data={**grant, "host": "unregistered.internal"})[0], 400)
                    self.assertFalse(permissions.authorizer.allowed("user:console-test", "budget.internal"))
                    self.assertEqual(console("/api/membership", data=grant)[0], 200)
                    self.assertEqual(console("/api/membership", data=grant)[0], 200)
                    self.assertTrue(permissions.authorizer.allowed("user:console-test", "budget.internal"))
                    status, body = console("/api/grants?host=budget.internal")
                    self.assertEqual(status, 200)
                    self.assertIn("user:console-test", json.loads(body)["principals"])
                    self.assertEqual(console("/api/membership", data={**grant, "action": "revoke"})[0], 200)
                    self.assertFalse(permissions.authorizer.allowed("user:console-test", "budget.internal"))
                    # Removing console access also blocks an already-running browser.
                    self.call("POST", f"/stores/{self.store}/write", {"authorization_model_id": self.model,
                        "deletes": {"tuple_keys": [{"user": "user:operator", "relation": "member", "object": "clustersite:" + permissions.HOST}]}})
                    self.assertEqual(console("/api/catalog")[0], 403)
                finally:
                    server.shutdown(); server.server_close(); thread.join(timeout=5)


if __name__ == "__main__":
    unittest.main()
