"""Run the bootstrap scripts against a simulated API; never contact a cluster."""
import base64
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
ACCESS = "authn-admin/authn-admin-access"


def fake_kubectl():
    directory = Path(os.environ["BOOTSTRAP_TEST_CLUSTER"])
    args = sys.argv[2:]
    with (directory / "calls.jsonl").open("a") as log:
        log.write(json.dumps(args) + "\n")
    namespace = None
    if args[:1] == ["-n"]:
        namespace, args = args[1], args[2:]
    secrets_file = directory / "secrets.json"
    secrets = json.loads(secrets_file.read_text())
    if args[:2] == ["get", "secret"]:
        key = f"{namespace}/{args[2]}"
        if key == ACCESS and os.environ.get("BOOTSTRAP_TEST_ACCESS_ERROR"):
            sys.exit("Forbidden: cannot read authn-admin-access")
        if key not in secrets:
            assert "--ignore-not-found" in args, args
            return
        if args[-1] == "name":
            print(f"secret/{args[2]}")
        else:
            assert key == "cert-manager/internal-ca", args
            print(json.dumps({"data": {"tls.crt": base64.b64encode(b"fixture CA").decode()}}))
    elif args[:4] == ["create", "secret", "generic", "authn-admin-access"]:
        assert namespace == "authn-admin"
        assert ACCESS not in secrets, "Existing allowlist must never be overwritten"
        filename = next(a.split("=", 2)[2] for a in args if a.startswith("--from-file=emails="))
        secrets[ACCESS] = Path(filename).read_text()
        secrets_file.write_text(json.dumps(secrets))
    elif args[:2] == ["create", "configmap"]:
        assert args[2] == "authn-internal-ca", args
        print("{}")
    elif args[:1] == ["apply"]:
        if "-f" in args:
            sys.stdin.read()
    elif args == ["config", "current-context"]:
        print("bootstrap-test")
    elif args[:1] not in (["wait"], ["annotate"]):
        raise AssertionError(args)


class SecretBootstrapTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        (self.root / "scripts").mkdir()
        (self.root / ".state").mkdir()
        for name in ("initialize-secrets.sh", "bootstrap.sh", "provision-zitadel.sh", "check.sh"):
            shutil.copyfile(ROOT / "scripts" / name, self.root / "scripts" / name)
        self.secrets_file = self.root / "secrets.json"
        self.secrets_file.write_text(json.dumps({
            "authn-system/zitadel-masterkey": "existing",
            "authn-system/zitadel-domain-provisioner": "existing",
            "authn-admin/openfga-api-credentials": "existing",
            "cert-manager/internal-ca": "existing",
        }))
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.command("kubectl", f"exec {shlex.quote(sys.executable)} {shlex.quote(str(Path(__file__).resolve()))} fake-kubectl \"$@\"")
        # Certificate validation and identity provisioning are outside these tests.
        self.command("openssl", '[ "$1" = x509 ] || exit 99')
        for name in ("curl", "tofu"):
            self.command(name, "exit 99")
        self.env = dict(os.environ, PATH=f"{self.bin}:{os.environ['PATH']}",
                        BOOTSTRAP_TEST_CLUSTER=str(self.root))

    def command(self, name, body):
        path = self.bin / name
        path.write_text(f"#!/bin/sh\n{body}\n")
        path.chmod(0o755)

    def run_script(self, name="initialize-secrets.sh", *args):
        return subprocess.run(["bash", str(self.root / "scripts" / name), *args],
                              cwd=self.root, env=self.env, capture_output=True, text=True)

    def calls(self):
        path = self.root / "calls.jsonl"
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def test_allowlist_exists_before_flux_even_when_identity_provisioning_fails(self):
        (self.root / "scripts/provision-zitadel.sh").write_text("exit 23\n")
        result = self.run_script("bootstrap.sh", "--admin-email", "owner@example.com")
        self.assertEqual(result.returncode, 23, result.stderr)
        self.assertEqual(json.loads(self.secrets_file.read_text())[ACCESS], "owner@example.com\n")
        calls = self.calls()
        creation = next(i for i, call in enumerate(calls)
                        if call[:6] == ["-n", "authn-admin", "create", "secret", "generic", "authn-admin-access"])
        self.assertLess(creation, calls.index(["apply", "-k", "bootstrap"]))

    def test_rerun_preserves_all_existing_administrators(self):
        secrets = json.loads(self.secrets_file.read_text())
        secrets[ACCESS] = "owner@example.com\nsecond@example.com\n"
        self.secrets_file.write_text(json.dumps(secrets))
        for args in ((), ("--admin-email", "owner@example.com")):
            result = self.run_script("initialize-secrets.sh", *args)
            self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(self.secrets_file.read_text()), secrets)
        self.assertFalse(any("create" in call and "secret" in call for call in self.calls()))

    def test_missing_allowlist_requires_an_explicit_email(self):
        result = self.run_script()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Rerun with --admin-email", result.stderr)
        self.assertNotIn(ACCESS, json.loads(self.secrets_file.read_text()))

    def test_api_failure_is_not_treated_as_a_missing_secret(self):
        self.env["BOOTSTRAP_TEST_ACCESS_ERROR"] = "1"
        result = self.run_script("initialize-secrets.sh", "--admin-email", "owner@example.com")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Forbidden", result.stderr)
        self.assertFalse(any("create" in call for call in self.calls()))

    def test_invalid_email_cannot_add_allowlist_entries(self):
        for address in ("", "*", "not-an-email", "owner@example.com\nsecond@example.com"):
            with self.subTest(address=address):
                result = self.run_script("initialize-secrets.sh", "--admin-email", address)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("one real administrator email", result.stderr)
        self.assertEqual(self.calls(), [])

    def test_different_bootstrap_owner_is_rejected_before_secret_creation(self):
        (self.root / ".state/admin-email").write_text("owner@example.com")
        result = self.run_script("initialize-secrets.sh", "--admin-email", "other@example.com")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Administrator differs", result.stderr)
        self.assertEqual(self.calls(), [])

    def test_provisioning_and_checks_report_missing_allowlist_before_waiting(self):
        (self.root / ".state/ca.crt").write_text("fixture CA")
        for script, args in (("provision-zitadel.sh", ("--admin-email", "owner@example.com")),
                             ("check.sh", ())):
            with self.subTest(script=script):
                result = self.run_script(script, *args)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("Missing authn-admin/authn-admin-access", result.stderr)
        self.assertTrue(all(call[:4] == ["-n", "authn-admin", "get", "secret"] for call in self.calls()))


if __name__ == "__main__":
    if sys.argv[1:2] == ["fake-kubectl"]:
        fake_kubectl()
    else:
        unittest.main()
