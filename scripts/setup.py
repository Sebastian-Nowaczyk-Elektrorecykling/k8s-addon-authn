#!/usr/bin/env python3
"""Check the existing cluster, initialize secrets once, and attach Flux."""
import argparse
import base64
import fnmatch
import ipaddress
import json
import re
import secrets
import subprocess
import sys

from common import ROOT, apply, get, kubectl, settings, sites


def preflight():
    for name in ("gateway", "dns", "pki", "storage-cnpg", "storage-classes", "storage-longhorn", "storage-garage"):
        obj = get("kustomization.kustomize.toolkit.fluxcd.io", name, "flux-system")
        if not any(c["type"] == "Ready" and c["status"] == "True"
                   and c.get("observedGeneration") == obj["metadata"]["generation"]
                   for c in obj.get("status", {}).get("conditions", [])):
            raise ValueError(f"Prerequisite flux-system/{name} is not ready")
    data = settings()
    for key in ("DOMAIN", "ADMIN_DOMAIN"):
        if not re.fullmatch(r"[a-z0-9]+(?:[.-][a-z0-9]+)*", data[key]):
            raise ValueError(f"Invalid cluster-settings {key}")
    ipaddress.IPv4Address(data["CLUSTER_DNS_IP"])
    for name in ("longhorn", "longhorn-cnpg"):
        get("storageclass", name)
    gateway = get("gateway", "internal", "gateway-system")
    for section, scope in (("apps-https", "applications"), ("admin-https", "administration")):
        listener = next(x for x in gateway["spec"]["listeners"] if x["name"] == section)
        if listener["allowedRoutes"]["namespaces"]["selector"]["matchLabels"].get("elektro.internal/route-scope") != scope:
            raise ValueError(f"Gateway listener {section} does not match the required namespace selector")
    claims = {s["host"] for s in sites()} | {"auth." + data["DOMAIN"]}
    routes = json.loads(kubectl("get", "httproutes", "-A", "-o", "json"))["items"]
    for route in routes:
        meta = route["metadata"]
        if (meta.get("labels", {}).get("kustomize.toolkit.fluxcd.io/name") == "authn-routes"
                and meta.get("labels", {}).get("kustomize.toolkit.fluxcd.io/namespace") == "flux-system"):
            continue
        attached = any(p["name"] == "internal" and p.get("namespace", meta["namespace"]) == "gateway-system"
                       and p.get("sectionName") in (None, "apps-https", "admin-https")
                       and p.get("port", 443) == 443 for p in route["spec"].get("parentRefs", []))
        patterns = route["spec"].get("hostnames", ["*"])
        if attached and any(fnmatch.fnmatchcase(host, pattern) for host in claims for pattern in patterns):
            raise ValueError(f"Conflicting route {meta['namespace']}/{meta['name']}. Remove its direct exposure first; "
                             "for hubble-test use the base repository's scripts/hubble-route.py remove.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--email", required=True, help="Initial authentik administrator email")
    parser.add_argument("--preflight-only", action="store_true")
    args = parser.parse_args()
    if not re.fullmatch(r"[^\s@]+@[^\s@]+", args.email):
        parser.error("Supply a valid administrator email")
    preflight()
    if args.preflight_only:
        print("Prerequisites and route ownership checked.")
        return
    kubectl("apply", "-k", str(ROOT / "infrastructure/namespaces"))
    required = {"authentik-secret-key", "oauth2-client-secret", "cookie-secret", "openfga-token", "bootstrap-password", "bootstrap-email"}
    existing = get("secret", "authn-secrets", optional=True)
    if existing:
        if not required.issubset(existing.get("data", {})):
            raise ValueError("Existing authn-secrets is incomplete; refusing to rotate or overwrite it")
    else:
        apply("Secret", "authn-secrets", {
            "authentik-secret-key": secrets.token_urlsafe(64),
            "oauth2-client-secret": secrets.token_urlsafe(48),
            "cookie-secret": base64.urlsafe_b64encode(secrets.token_bytes(32)).decode(),
            "openfga-token": secrets.token_urlsafe(48),
            "bootstrap-password": secrets.token_urlsafe(32), "bootstrap-email": args.email})
    if get("secret", "authn-agents", optional=True) is None:
        apply("Secret", "authn-agents", {"agents.json": "{}"})
    # Copy only the public CA certificate. Never read or export the private key.
    cert = kubectl("-n", "cert-manager", "get", "secret", "internal-ca",
                   "-o", r"jsonpath={.data.tls\.crt}")
    certificate = base64.b64decode(cert).decode()
    if "-----BEGIN CERTIFICATE-----" not in certificate:
        raise ValueError("The base cluster's public CA certificate is missing")
    apply("ConfigMap", "authn-ca", {"ca.crt": certificate})
    kubectl("apply", "-k", str(ROOT / "bootstrap"))
    # The root creates all child objects before becoming Ready.
    kubectl("-n", "flux-system", "wait", "kustomization/authn-addons", "--for=condition=Ready", "--timeout=5m")
    kubectl("-n", "flux-system", "wait", "kustomization", "-l", "app.kubernetes.io/part-of=authn-addons",
            "--for=condition=Ready", "--timeout=30m")
    subprocess.run([sys.executable, str(ROOT / "scripts/access.py"), "init"], check=True)
    print("Flux attachment and OpenFGA model are ready. Sign in and grant your principal access; see README.md.")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, KeyError, StopIteration, subprocess.CalledProcessError) as error:
        sys.exit(f"Setup failed: {error}")
