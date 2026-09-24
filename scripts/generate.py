#!/usr/bin/env python3
"""Generate the routes, proxy config and OIDC callbacks from config/sites.json."""
import argparse
import json
from pathlib import Path
import re
import sys

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "apps/site-controller"))
from render import render


def generate():
    sites = json.loads((ROOT / "config/sites.json").read_text())
    assert len({s["host"] for s in sites}) == len(sites), "Duplicate hostname"
    for site in sites:
        assert re.fullmatch(r"[a-z][a-z0-9-]*", site["name"])
        suffix = "${ADMIN_DOMAIN}" if site["scope"] == "administration" else "${DOMAIN}"
        assert site["scope"] in ("applications", "administration")
        assert site["host"] == site["name"] + "." + suffix or re.fullmatch(
            r"[a-z0-9-]+\." + re.escape(suffix), site["host"])
        assert (re.fullmatch(r"[a-z0-9.-]+\.svc\.cluster\.local:[0-9]+", site["upstream"])
                or site["name"] == "permissions" and site["upstream"] == "127.0.0.1:9090")

    routes = []
    all_routes = [{"name": "authentik-login", "host": "auth.${DOMAIN}", "scope": "applications"}] + sites
    for site in all_routes:
        admin = site["scope"] == "administration"
        routes.append({"apiVersion": "gateway.networking.k8s.io/v1", "kind": "HTTPRoute",
                       "metadata": {"name": site["name"], "namespace": "authn-admin" if admin else "authn"},
                       "spec": {"parentRefs": [{"name": "internal", "namespace": "gateway-system",
                                                "sectionName": "admin-https" if admin else "apps-https"}],
                                "hostnames": [site["host"]], "rules": [{"backendRefs": [
                                    {"name": "authn-edge", "namespace": "authn", "port": 80}]}]}})
    result = render(sites)
    return {
        "apps/edge/" + key: value for key, value in result.items() if key != "cluster-sites.yaml"
    } | {
        "apps/authentik/cluster-sites.yaml": result["cluster-sites.yaml"],
        "apps/site-controller/seed-sites.json": json.dumps(sites, indent=2) + "\n",
        "infrastructure/routes/routes.yaml": yaml.safe_dump_all(routes, sort_keys=False),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    failed = []
    for name, content in generate().items():
        path = ROOT / name
        if args.check:
            if not path.exists() or path.read_text() != content:
                failed.append(name)
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
    if failed:
        sys.exit("Regenerate with python3 scripts/generate.py: " + ", ".join(failed))


if __name__ == "__main__":
    main()
