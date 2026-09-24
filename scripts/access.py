#!/usr/bin/env python3
"""Manage OpenFGA and expiring agent credentials through your local kubeconfig."""
import argparse
import base64
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

from common import ROOT, apply, get, kubectl, secret, sites


@contextmanager
def api():
    token = secret("authn-secrets")["openfga-token"]
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    process = subprocess.Popen(["kubectl", "-n", "authn", "port-forward", "--address=127.0.0.1",
                                "service/openfga", f"{port}:8080"], stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL)
    base = f"http://127.0.0.1:{port}"

    def call(method, path, data=None):
        req = urllib.request.Request(base + path, method=method,
                                     headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"},
                                     data=None if data is None else json.dumps(data).encode())
        try:
            with urllib.request.urlopen(req, timeout=10) as response:
                body = response.read()
                return json.loads(body) if body else {}
        except urllib.error.HTTPError as error:
            raise ValueError(f"OpenFGA {method} {path} returned HTTP {error.code}") from None

    try:
        deadline = time.monotonic() + 30
        while True:
            try:
                call("GET", "/healthz")
                break
            except (OSError, ValueError):
                if process.poll() is not None or time.monotonic() > deadline:
                    raise ValueError("Could not establish a local OpenFGA port-forward") from None
                time.sleep(0.2)
        yield call
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


def digest_model(model):
    # The API materializes protobuf defaults (null metadata, empty conditions,
    # computedUserset.object=""). Ignore those, but retain the meaningful
    # `this: {}` relation marker, so an API round-trip keeps the same fingerprint.
    def normalize(value):
        if isinstance(value, dict):
            normalized = {key: normalize(item) for key, item in value.items()}
            return {key: item for key, item in normalized.items()
                    if key == "this" or item not in (None, "", {}, [])}
        if isinstance(value, list):
            return [normalize(item) for item in value]
        return value
    return hashlib.sha256(json.dumps(normalize(model), sort_keys=True).encode()).hexdigest()


def initialize(call, upgrade=False):
    model = json.loads((ROOT / "openfga/model.json").read_text())
    current = get("configmap", "authn-openfga-state", optional=True)
    if current:
        state = json.loads(current["data"]["openfga.json"])
        # Verify that the pinned model still exists in the current datastore.
        call("GET", f"/stores/{state['store_id']}/authorization-models/{state['model_id']}")
        if state["model_sha256"] == digest_model(model):
            print("OpenFGA store and pinned model already initialized.")
            return
        if not upgrade:
            raise ValueError("Model changed; review the migration and run init --upgrade-model")
        store_id = state["store_id"]
    else:
        stores, cursor = [], ""
        while True:
            page = call("GET", "/stores?page_size=100" + ("&continuation_token=" + urllib.parse.quote(cursor) if cursor else ""))
            stores += [s for s in page.get("stores", []) if s["name"] == "cluster-sites"]
            cursor = page.get("continuation_token", "")
            if not cursor:
                break
        if len(stores) > 1:
            raise ValueError("Multiple cluster-sites stores exist; recover the intended state ConfigMap explicitly")
        store_id = stores[0]["id"] if stores else call("POST", "/stores", {"name": "cluster-sites"})["id"]
    models = call("GET", f"/stores/{store_id}/authorization-models?page_size=100").get("authorization_models", [])
    found = next((m["id"] for m in models if digest_model({k: v for k, v in m.items() if k != "id"}) == digest_model(model)), None)
    if models and not found and not upgrade:
        raise ValueError("Existing store has a different model; inspect it before init --upgrade-model")
    model_id = found or call("POST", f"/stores/{store_id}/authorization-models", model)["authorization_model_id"]
    state = {"store_id": store_id, "model_id": model_id, "model_sha256": digest_model(model)}
    apply("ConfigMap", "authn-openfga-state", {"openfga.json": json.dumps(state)})
    print("OpenFGA store and pinned model initialized; no access was granted automatically.")


def membership(call, action, principal, hosts):
    if not re.fullmatch(r"(?:user|agent):[A-Za-z0-9_.@-]{1,200}", principal):
        raise ValueError("Use user:<OIDC-sub> or agent:<name>")
    if not all(re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", host) and "." in host for host in hosts):
        raise ValueError("Use exact lowercase hostnames")
    if action == "grant":
        known = {s["host"] for s in sites(live=True)}
        if not set(hosts).issubset(known):
            raise ValueError("Hosts must be registered exact hostnames: " + ", ".join(sorted(known)))
    # Revocation also supports removed sites, so retained tuples can be cleaned up.
    state = json.loads(get("configmap", "authn-openfga-state")["data"]["openfga.json"])
    for host in hosts:
        key = {"user": principal, "relation": "member", "object": "clustersite:" + host}
        exists = bool(call("POST", f"/stores/{state['store_id']}/read", {"tuple_key": key}).get("tuples"))
        if exists != (action == "grant"):
            call("POST", f"/stores/{state['store_id']}/write", {
                "authorization_model_id": state["model_id"],
                "writes" if action == "grant" else "deletes": {"tuple_keys": [key]}})
        print(f"{action}: {principal} -> {host}")


def agent(action, name, output=None, days=30):
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", name):
        raise ValueError("Agent name must contain letters, digits, dots, underscores or hyphens")
    existing = get("secret", "authn-agents")
    registry = json.loads(base64.b64decode(existing["data"]["agents.json"]))
    principal = "agent:" + name
    if action == "create-agent":
        if not 1 <= days <= 365:
            raise ValueError("Token lifetime must be 1..365 days")
        path = Path(output).expanduser().resolve()
        if path.is_relative_to(ROOT):
            raise ValueError("Write the credential outside the Git checkout")
        token = secrets.token_urlsafe(32)
        with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w") as file:
            file.write(token)
        registry[hashlib.sha256(token.encode()).hexdigest()] = {
            "principal": principal, "expires_at": int(time.time()) + days * 86400}
    else:
        registry = {digest: item for digest, item in registry.items() if item["principal"] != principal}
    # resourceVersion makes concurrent edits fail instead of silently losing tokens.
    body = {"apiVersion": "v1", "kind": "Secret", "metadata": {
        "name": "authn-agents", "namespace": "authn", "resourceVersion": existing["metadata"]["resourceVersion"]},
        "data": {"agents.json": base64.b64encode(json.dumps(registry).encode()).decode()}}
    kubectl("replace", "-f", "-", body=body)
    print(f"{action}: {principal}. Projected Secret updates can take about two minutes.")
    if action == "create-agent":
        print(f"Credential saved to {path}; site grants are still required.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("sites", help="List the controller's current built-in and discovered sites")
    init = sub.add_parser("init")
    init.add_argument("--upgrade-model", action="store_true")
    for command in ("grant", "revoke"):
        command_parser = sub.add_parser(command)
        command_parser.add_argument("principal")
        command_parser.add_argument("hosts", nargs="+")
    create = sub.add_parser("create-agent")
    create.add_argument("name")
    create.add_argument("--output", required=True)
    create.add_argument("--days", type=int, default=30)
    sub.add_parser("revoke-agent").add_argument("name")
    args = parser.parse_args()
    if args.command == "sites":
        for site in sites(live=True):
            print(f"{site['host']}\t{site.get('source', 'built-in')}\t{site['upstream']}")
    elif args.command in ("create-agent", "revoke-agent"):
        agent(args.command, args.name, getattr(args, "output", None), getattr(args, "days", 30))
    else:
        with api() as call:
            if args.command == "init":
                initialize(call, args.upgrade_model)
            else:
                membership(call, args.command, args.principal, args.hosts)


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, OSError, subprocess.CalledProcessError) as error:
        sys.exit(f"Access management failed: {error}")
