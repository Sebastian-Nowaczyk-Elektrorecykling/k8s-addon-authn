"""Operator-side Kubernetes helpers; no service account is granted these powers."""
import base64
import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def kubectl(*args, body=None):
    timeout = "0" if "wait" in args else "30s"
    return subprocess.run(["kubectl", "--request-timeout=" + timeout, *args], check=True,
                          input=json.dumps(body) if body is not None else None,
                          text=True, stdout=subprocess.PIPE).stdout


def get(kind, name, namespace="authn", optional=False):
    raw = kubectl("-n", namespace, "get", kind, name, "-o", "json",
                  *(["--ignore-not-found"] if optional else []))
    return json.loads(raw) if raw.strip() else None


def apply(kind, name, data, namespace="authn"):
    body = {"apiVersion": "v1", "kind": kind,
            "metadata": {"name": name, "namespace": namespace},
            "stringData" if kind == "Secret" else "data": data}
    kubectl("create" if kind == "Secret" else "apply", "-f", "-", body=body)


def secret(name):
    return {k: base64.b64decode(v).decode() for k, v in get("secret", name)["data"].items()}


def settings():
    return get("configmap", "cluster-settings", "flux-system")["data"]


def sites(live=False):
    if live:
        current = get("configmap", "authn-runtime", optional=True)
        if not current:
            raise ValueError("Site controller has not initialized authn-runtime; check authn-site-controller logs")
        return list(json.loads(current["data"]["sites.json"]).values())
    data = settings()
    raw = (ROOT / "config/sites.json").read_text()
    for key in ("DOMAIN", "ADMIN_DOMAIN"):
        raw = raw.replace("${" + key + "}", data[key])
    return json.loads(raw)
