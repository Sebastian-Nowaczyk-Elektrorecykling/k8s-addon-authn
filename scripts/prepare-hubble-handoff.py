#!/usr/bin/env python3
"""Prepare the base repository's documented route handoff in a local checkout."""
import argparse
import json
import pathlib
import subprocess
import yaml

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("network_checkout", type=pathlib.Path)
args = parser.parse_args()
root = args.network_checkout.resolve()
config_file = root / "config/cluster.json"
generator = root / "scripts/config.py"
if not config_file.is_file() or not generator.is_file():
    parser.error("Expected a minimum-k8s-net-elektro checkout")
config = json.loads(config_file.read_text())
route_file = root / "infrastructure/admin/routes.yaml"
route = yaml.safe_load(route_file.read_text())
if route.get("kind") != "HTTPRoute" or route["metadata"]["name"] != "administration":
    parser.error("Unexpected base HTTPRoute; review the handoff manually")
filters = [{"type": "RequestHeaderModifier", "requestHeaderModifier": {
    "remove": ["Forwarded", "X-Forwarded-Host", "X-Forwarded-Uri", "X-Forwarded-Method",
               "X-Forwarded-Path", "X-Auth-Request-Redirect"],
    "set": [{"name": "X-Forwarded-Proto", "value": "https"}],
}}]
for rule in route["spec"]["rules"]:
    if rule.get("filters") not in (None, filters):
        parser.error("Existing Hubble filters differ; merge forwarding-header sanitization manually")
    rule["filters"] = filters
    rule["timeouts"] = {"request": "0s", "backendRequest": "0s"}
expected = {
    "hubble_backend_service": "heimdall",
    "hubble_backend_namespace": "authn-admin",
    "hubble_backend_port": 4456,
}
for key in expected:
    if key not in config:
        parser.error(f"Base checkout does not support the Hubble handoff: {key}")
config.update(expected)
config_file.write_text(json.dumps(config, indent=2) + "\n")
route_file.write_text(yaml.safe_dump(route, sort_keys=False))
subprocess.run(["python3", str(generator), "generate"], cwd=root, check=True)
subprocess.run(["python3", str(generator), "check"], cwd=root, check=True)
subprocess.run(["git", "diff", "--", "config/cluster.json", "clusters/lan/cluster-settings.yaml",
                "infrastructure/admin/routes.yaml"], cwd=root, check=True)
print("Prepared backend settings and forwarding-header/streaming configuration. Review, commit and push these three base files.")
