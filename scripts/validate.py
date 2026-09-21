#!/usr/bin/env python3
"""Build all Flux targets, render the pinned chart, and validate against CRDs."""
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import urllib.request

import yaml

ROOT = Path(__file__).resolve().parents[1]
CACHE = ROOT / ".cache"
SETTINGS = {"DOMAIN": "internal", "ADMIN_DOMAIN": "admin.internal", "CLUSTER_DNS_IP": "10.43.0.10"}


def run(*args, **kwargs):
    return subprocess.run(args, check=True, text=True, stdout=subprocess.PIPE, **kwargs).stdout


def fetch(url, name):
    path = CACHE / name
    if not path.exists():
        with urllib.request.urlopen(url, timeout=90) as response:
            path.write_bytes(response.read())
    return path


def substitute(text):
    def value(match):
        key = match.group(1)
        if key not in SETTINGS:
            raise ValueError("Unresolved Flux substitution: " + key)
        return SETTINGS[key]
    return re.sub(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}", value, text)


def main():
    CACHE.mkdir(exist_ok=True)
    for binary in ("kustomize", "helm", "kubeconform", "oauth2-proxy"):
        if not shutil.which(binary):
            sys.exit("Required tool: " + binary)
    run(sys.executable, str(ROOT / "scripts/generate.py"), "--check")
    children = list(yaml.safe_load_all((ROOT / "clusters/lan/infrastructure.yaml").read_text()))
    names = {c["metadata"]["name"] for c in children}
    paths = {c["spec"]["path"].removeprefix("./") for c in children}
    base_dependencies = {"gateway", "dns", "pki", "storage-cnpg", "storage-classes", "storage-longhorn", "storage-garage"}
    graph = {c["metadata"]["name"]: {d["name"] for d in c["spec"].get("dependsOn", [])} for c in children}
    done = base_dependencies.copy()
    while graph:
        ready = {n for n, deps in graph.items() if deps <= done}
        assert ready, "Flux dependency cycle or unknown dependency"
        done |= ready
        graph = {n: deps for n, deps in graph.items() if n not in ready}
    rendered = []
    for path in sorted(paths | {"clusters/lan", "bootstrap"}):
        docs = list(yaml.safe_load_all(substitute(run("kustomize", "build", str(ROOT / path)))))
        identities = [(d["apiVersion"], d["kind"], d["metadata"].get("namespace"), d["metadata"]["name"]) for d in docs]
        assert len(identities) == len(set(identities)), f"Duplicate resources in {path}"
        rendered.extend(docs)
    assert all(c["spec"]["sourceRef"]["name"] == "authn-addons" for c in children)
    for resource in rendered:
        assert resource["kind"] != "Ingress", "Use the existing Gateway API"
        assert resource["kind"] != "Secret", "Live credentials must not be committed"
        if resource["kind"] == "Service":
            assert resource["spec"].get("type", "ClusterIP") == "ClusterIP"
        if resource["kind"] == "HTTPRoute":
            assert all("*" not in h for h in resource["spec"]["hostnames"])
            for rule in resource["spec"]["rules"]:
                assert all(b["name"] == "authn-edge" for b in rule["backendRefs"]), "SSO bypass route"
        if resource["kind"] == "Cluster":
            assert resource["spec"]["storage"]["storageClass"] == "longhorn-cnpg"
    release = yaml.safe_load((ROOT / "apps/authentik/release.yaml").read_text())
    values = CACHE / "authentik-values.yaml"
    values.write_text(substitute(yaml.safe_dump(release["spec"]["values"])))
    version = release["spec"]["chart"]["spec"]["version"]
    chart = CACHE / f"authentik-{version}.tgz"
    if not chart.exists():
        run("helm", "pull", "authentik", "--repo", "https://charts.goauthentik.io", "--version", version, "--destination", str(CACHE))
    chart_docs = list(yaml.safe_load_all(run("helm", "template", "authentik", str(chart), "--namespace", "authn", "-f", str(values))))
    assert any(d and d["kind"] == "Service" and d["metadata"]["name"] == "authentik-server" for d in chart_docs)
    assert not any(d and d["kind"] in ("ClusterRole", "ClusterRoleBinding", "Ingress") for d in chart_docs)
    rendered.extend(d for d in chart_docs if d)
    schemas = CACHE / "schemas"
    schemas.mkdir(exist_ok=True)
    crds = [
        ("https://github.com/fluxcd/flux2/releases/download/v2.9.5/install.yaml", "flux.yaml"),
        ("https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.6.1/standard-install.yaml", "gateway.yaml"),
        ("https://raw.githubusercontent.com/cloudnative-pg/cloudnative-pg/v1.30.0/config/crd/bases/postgresql.cnpg.io_clusters.yaml", "cnpg.yaml"),
    ]
    for url, filename in crds:
        for crd in yaml.safe_load_all(fetch(url, filename).read_text()):
            if crd and crd.get("kind") == "CustomResourceDefinition":
                for version in crd["spec"]["versions"]:
                    schema = version["schema"]["openAPIV3Schema"]
                    name = crd["spec"]["names"]["kind"].lower() + "_" + version["name"] + ".json"
                    (schemas / name).write_text(json.dumps(schema))
    target = CACHE / "rendered.yaml"
    target.write_text(yaml.safe_dump_all(rendered, sort_keys=False))
    print(run("kubeconform", "-strict", "-summary", "-kubernetes-version", "1.36.4",
              "-schema-location", str(schemas / "{{.ResourceKind}}_{{.ResourceAPIVersion}}.json"),
              "-schema-location", "default", str(target)), end="")
    config = CACHE / "oauth2-proxy.cfg"
    ca = os.environ.get("VALIDATION_CA", "/etc/ssl/certs/ca-certificates.crt")
    config.write_text(substitute((ROOT / "apps/edge/oauth2-proxy.cfg").read_text()).replace("/ca/ca.crt", ca))
    print(run("oauth2-proxy", "--config=" + str(config), "--client-secret=validation-only",
              "--cookie-secret=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "--config-test"), end="")
    print(f"Validated {len(paths)} Flux targets, the authentik chart, schemas, and OAuth2 configuration.")


if __name__ == "__main__":
    main()
