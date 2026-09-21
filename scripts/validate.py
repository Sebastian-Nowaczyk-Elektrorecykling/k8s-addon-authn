#!/usr/bin/env python3
"""Render every Flux path and chart, validate API schemas and security boundaries."""
import json
import os
import pathlib
import shutil
import subprocess
import urllib.request

import jsonschema
import yaml

ROOT = pathlib.Path(__file__).resolve().parents[1]
CACHE = ROOT / ".cache"
CACHE.mkdir(exist_ok=True)
(CACHE / "tmp").mkdir(exist_ok=True)
os.environ["TMPDIR"] = str(CACHE / "tmp")

def run(args, **kwargs):
    return subprocess.run(args, check=True, text=True, capture_output=True, **kwargs).stdout

def documents(text):
    return [d for d in yaml.safe_load_all(text) if d]

def fetch(url, name):
    path = CACHE / name
    if not path.exists():
        # Only fixed, public upstream release artifacts are downloaded.
        with urllib.request.urlopen(url, timeout=60) as response:
            path.write_bytes(response.read())
    return path

def require(condition, message):
    if not condition:
        raise RuntimeError(message)

all_docs = []
owners = {}
for path in sorted(ROOT.glob("**/kustomization.yaml")):
    if ".cache" in path.parts:
        continue
    rendered = run(["kustomize", "build", str(path.parent)])
    docs = documents(rendered)
    all_docs.extend(docs)
    if "infrastructure" in path.parts:
        for obj in docs:
            key = (obj["apiVersion"], obj["kind"], obj["metadata"].get("namespace", ""), obj["metadata"]["name"])
            require(key not in owners, f"Duplicate Flux owner for {key}")
            owners[key] = path.parent.name

# Render the exact chart versions referenced by Flux, not unpinned latest charts.
releases = [d for d in all_docs if d["kind"] == "HelmRelease"]
repositories = {d["metadata"]["name"]: d["spec"]["url"] for d in all_docs if d["kind"] == "HelmRepository"}
rendered_charts = {}
for release in releases:
    name = release["metadata"]["name"]
    namespace = release["metadata"]["namespace"]
    spec = release["spec"]
    if "chartRef" in spec:
        version = "0.16.22"
        source = "oci://ghcr.io/dadrus/heimdall/chart/heimdall"
        args = ["helm", "pull", source, "--version", version, "--destination", str(CACHE)]
        chart = CACHE / f"heimdall-{version}.tgz"
    else:
        chart_spec = spec["chart"]["spec"]
        version = str(chart_spec["version"])
        chart_name = chart_spec["chart"]
        args = ["helm", "pull", chart_name, "--version", version, "--repo",
                repositories[chart_spec["sourceRef"]["name"]], "--destination", str(CACHE)]
        chart = CACHE / f"{chart_name}-{version}.tgz"
    if not chart.exists():
        run(args)
    values = CACHE / f"{name}-values.yaml"
    values.write_text(yaml.safe_dump(spec["values"]))
    output = run(["helm", "template", name, str(chart), "--namespace", namespace,
                  "--kube-version", "1.36.4", "-f", str(values)])
    (CACHE / f"{name}-rendered.yaml").write_text(output)
    rendered_charts[name] = documents(output)
    all_docs.extend(rendered_charts[name])
    print(f"Rendered {name} ({version})")
    if name == "oauth2-proxy":
        deployment = next(d for d in rendered_charts[name] if d["kind"] == "Deployment")
        proxy = next(c for c in deployment["spec"]["template"]["spec"]["containers"] if c["name"] == "oauth2-proxy")
        expected_image = f"quay.io/oauth2-proxy/oauth2-proxy:{spec['values']['image']['tag']}"
        require(proxy["image"] == expected_image,
                f"Unexpected OAuth2 Proxy image: {proxy['image']}; expected {expected_image}")

# Derive CRD schemas from the pinned upstream releases already used by the cluster.
bundles = [
    ("https://github.com/fluxcd/flux2/releases/download/v2.9.5/install.yaml", "flux-crds.yaml"),
    ("https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.6.1/standard-install.yaml", "gateway-crds.yaml"),
    ("https://raw.githubusercontent.com/cloudnative-pg/cloudnative-pg/release-1.30/releases/cnpg-1.30.0.yaml", "cnpg-crds.yaml"),
    ("https://raw.githubusercontent.com/cilium/cilium/v1.20.2/pkg/k8s/apis/cilium.io/client/crds/v2/ciliumnetworkpolicies.yaml", "cilium-crd.yaml"),
]
schemas = {}
for url, filename in bundles:
    for crd in documents(fetch(url, filename).read_text()):
        if crd.get("kind") != "CustomResourceDefinition":
            continue
        for version in crd["spec"]["versions"]:
            schemas[(crd["spec"]["group"] + "/" + version["name"], crd["spec"]["names"]["kind"])] = version["schema"]["openAPIV3Schema"]
builtins = {"v1", "apps/v1", "batch/v1", "rbac.authorization.k8s.io/v1", "networking.k8s.io/v1", "policy/v1", "autoscaling/v2"}
for obj in all_docs:
    key = (obj["apiVersion"], obj["kind"])
    if key in schemas:
        jsonschema.Draft7Validator(schemas[key]).validate(obj)
    else:
        require(obj["apiVersion"] in builtins, f"No schema for {key}")
native = [d for d in all_docs if d["apiVersion"] in builtins]
print(run(["kubeconform", "-strict", "-summary", "-kubernetes-version", "1.36.0"],
          input=yaml.safe_dump_all(native)).strip())

# Verify that public routes cannot bypass the authentication proxy.
routes = [d for d in all_docs if d["kind"] == "HTTPRoute"]
hubble_routes = [r for r in routes if "hubble.admin.internal" in r["spec"].get("hostnames", [])]
require(len(hubble_routes) == 1, "Hubble must have exactly one SSO route")
require(any(p["name"] == "internal" and p.get("namespace") == "gateway-system" and
            p.get("sectionName") == "admin-https" for p in hubble_routes[0]["spec"]["parentRefs"]),
        "Hubble must use the shared administration listener")
for route in routes:
    for host in route["spec"].get("hostnames", []):
        require(host.endswith(".internal"), f"Unexpected public domain {host}")
        if host not in {"auth.internal", "zitadel.admin.internal"}:
            require(host.endswith(".admin.internal"), f"Admin service under a user domain: {host}")
            for rule in route["spec"]["rules"]:
                backends = rule.get("backendRefs", [])
                require(backends and all(b["name"] == "heimdall" and b.get("port") == 4456 and
                        b.get("namespace", route["metadata"]["namespace"]) == "authn-admin"
                        for b in backends), f"SSO bypass: {host}")
# All configured reverse-proxy destinations resolve to intentional private services.
rules = yaml.safe_load((ROOT / "infrastructure/heimdall/rules.yaml").read_text())
for rule in rules["rules"]:
    if rule["id"] != "sso-endpoints":
        require(rule["execute"][0] == {"authenticator": "admin-session"}, f"Unprotected rule {rule['id']}")
    require(".svc.cluster.local:" in rule["forward_to"]["host"], "Public upstream would loop")

# Check hook dependencies, preventing install-time deadlocks.
openfga = rendered_charts["openfga"]
migration = next(d for d in openfga if d["kind"] == "Job" and d["metadata"]["name"].endswith("-migrate"))
require(migration["metadata"]["annotations"]["helm.sh/hook"] == "pre-install,pre-upgrade", "Migration must precede rollout")
migration_env = migration["spec"]["template"]["spec"]["containers"][0]["env"]
require(any(e["name"] == "OPENFGA_DATASTORE_URI" and "verify-full" in e.get("value", "") for e in migration_env), "Missing verified database TLS on migration")
for obj in openfga:
    if obj["kind"] == "Deployment":
        env = obj["spec"]["template"]["spec"]["containers"][0]["env"]
        require(any(e["name"] == "OPENFGA_AUTHN_METHOD" and e.get("value") == "preshared" for e in env), "OpenFGA API must authenticate")
        require(any(e["name"] == "OPENFGA_PLAYGROUND_ENABLED" and e.get("value") == "false" for e in env), "Playground must be disabled")
# Verify actual Heimdall config with the pinned production binary.
heimdall_cm = next(d for d in rendered_charts["heimdall"] if d["kind"] == "ConfigMap")
config = yaml.safe_load(heimdall_cm["data"]["heimdall.yaml"])
check_rules = CACHE / "rules"
check_rules.mkdir(exist_ok=True)
shutil.copyfile(ROOT / "infrastructure/heimdall/rules.yaml", check_rules / "rules.yaml")
config["providers"]["file_system"]["src"] = str(check_rules)
config_file = CACHE / "heimdall-check.yaml"
config_file.write_text(yaml.safe_dump(config))
flags = next(d for d in releases if d["metadata"]["name"] == "heimdall")["spec"]["values"]["extraArgs"]
print(run(["heimdall", "validate", "config", "-c", str(config_file), *flags]).strip())
for script in ROOT.glob("scripts/*.sh"):
    run(["bash", "-n", str(script)])
print("All builds, schemas and route boundaries passed. No OpenFGA model/store/tuple is deployed.")
