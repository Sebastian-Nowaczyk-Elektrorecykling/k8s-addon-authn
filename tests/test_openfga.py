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
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
BINARY = os.environ.get("OPENFGA", shutil.which("openfga"))
sys.path.insert(0, str(ROOT / "scripts"))
import access


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


if __name__ == "__main__":
    unittest.main()
