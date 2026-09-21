import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("authorizer", ROOT / "apps/edge/authorizer.py")
auth = importlib.util.module_from_spec(spec)
spec.loader.exec_module(auth)


class AuthorizationTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name)
        for name in ("CONFIG", "SECRETS", "STATE"):
            p = patch.object(auth, name, self.path)
            p.start()
            self.addCleanup(p.stop)
        (self.path / "sites.json").write_text(json.dumps({"home.internal": {}, "s3.internal": {"native_authorization": True}}))
        (self.path / "openfga.json").write_text(json.dumps({"store_id": "0" * 26, "model_id": "1" * 26}))
        (self.path / "openfga-token").write_text("server-only-secret")
        self.token = "a" * 43
        self.registry = {hashlib.sha256(self.token.encode()).hexdigest(): {
            "principal": "agent:test", "expires_at": int(time.time()) + 60}}
        self.save_registry()
        self.headers = {"X-Original-Host": "home.internal", "Cookie": "__Host-cluster_sso=valid"}

    def save_registry(self):
        (self.path / "agents.json").write_text(json.dumps(self.registry))

    def test_caller_identity_cannot_replace_session_identity(self):
        self.headers["X-Auth-Request-User"] = "administrator"
        self.headers["X-Cluster-Principal"] = "user:administrator"
        with patch.object(auth, "request", side_effect=[(202, {"X-Auth-Request-User": "actual-sub"}, b""),
                                                       (200, {}, b'{"allowed": true}')]) as call:
            status, headers, _ = auth.authorize(self.headers)
        self.assertEqual(status, 204)
        self.assertEqual(headers["X-Cluster-Principal"], "user:actual-sub")
        request_body = json.loads(call.call_args.args[2])
        self.assertEqual(request_body["tuple_key"]["user"], "user:actual-sub")
        self.assertEqual(request_body["tuple_key"]["object"], "clustersite:home.internal")
        self.assertEqual(request_body["authorization_model_id"], "1" * 26)
        self.assertEqual(request_body["consistency"], "HIGHER_CONSISTENCY")

    def test_forged_headers_without_session_are_rejected(self):
        with patch.object(auth, "request") as call:
            status, _, _ = auth.authorize({"X-Original-Host": "home.internal", "X-Auth-Request-User": "admin"})
        self.assertEqual(status, 401)
        call.assert_not_called()

    def test_unknown_host_is_rejected_before_authentication(self):
        self.headers["X-Original-Host"] = "home.internal.evil.example"
        with patch.object(auth, "request") as call:
            self.assertEqual(auth.authorize(self.headers)[0], 403)
        call.assert_not_called()

    def test_denied_and_unavailable_fga_never_allow_access(self):
        for response in [(200, {}, b'{"allowed": false}'), (200, {}, b'{"allowed": "true"}'),
                         (500, {}, b""), (302, {}, b""), (200, {}, b"invalid")]:
            with self.subTest(response=response), patch.object(auth, "request", side_effect=[
                    (202, {"X-Auth-Request-User": "person"}, b""), response]):
                if response[0] == 200 and response[2] != b"invalid":
                    self.assertEqual(auth.authorize(self.headers)[0], 403)
                else:
                    with self.assertRaises((RuntimeError, ValueError)):
                        auth.authorize(self.headers)

    def test_agent_uses_its_own_identity_and_grant(self):
        headers = {"X-Original-Host": "home.internal", "Authorization": "Bearer " + self.token}
        with patch.object(auth, "request", return_value=(200, {}, b'{"allowed": true}')) as call:
            self.assertEqual(auth.authorize(headers)[1]["X-Cluster-Principal"], "agent:test")
        self.assertEqual(call.call_count, 1)

    def test_native_authorization_is_not_mistaken_for_an_agent_token(self):
        headers = {"X-Original-Host": "s3.internal", "Authorization": "AWS4-HMAC-SHA256 example",
                   "X-Cluster-Token": self.token}
        with patch.object(auth, "request", return_value=(200, {}, b'{"allowed": true}')):
            self.assertEqual(auth.authorize(headers)[1]["X-Cluster-Principal"], "agent:test")

    def test_unknown_expired_and_revoked_agents_fail_without_cookie_fallback(self):
        for state in ("unknown", "expired", "revoked"):
            if state == "expired":
                next(iter(self.registry.values()))["expires_at"] = time.time() - 1
            elif state == "revoked":
                self.registry = {}
            self.save_registry()
            token = "b" * 43 if state == "unknown" else self.token
            with patch.object(auth, "request") as call:
                self.assertEqual(auth.authorize({**self.headers, "X-Cluster-Token": token})[0], 401)
            call.assert_not_called()

    def test_identity_endpoint_reveals_only_the_authenticated_principal(self):
        with patch.object(auth, "request", return_value=(202, {"X-Auth-Request-User": "person"}, b"")) as call:
            status, _, body = auth.authorize(self.headers, identity_only=True)
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body), {"principal": "user:person"})
        self.assertEqual(call.call_count, 1)

    def test_sso_cookies_are_not_disclosed_to_applications(self):
        cookies = "app=ok; __Host-cluster_sso=secret; __Host-cluster_sso_1=part2; __Host-cluster_sso_csrf_abc=csrf"
        self.assertEqual(auth.upstream_cookie(cookies), "app=ok")


if __name__ == "__main__":
    unittest.main()
