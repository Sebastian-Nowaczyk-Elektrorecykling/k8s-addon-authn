"""Discover opted-in HTTPRoutes and reconcile runtime SSO configuration.

The controller never grants access and never changes an addon's HTTPRoute.
All Kubernetes writes are confined to authn. No OpenFGA credential is mounted.
"""
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request

from render import render

PREFIX = "authn.elektro.internal/"
REVISION = PREFIX + "revision"
MANAGED = {"app.kubernetes.io/managed-by": "authn-site-controller"}
CORE = "/api/v1/namespaces/authn/"
GATEWAY = "/apis/gateway.networking.k8s.io/"
DNS_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")


def hostname(value):
    return (isinstance(value, str) and len(value) <= 253 and "." in value
            and all(DNS_LABEL.fullmatch(label) for label in value.split(".")))


def matches_hostname(pattern, host):
    # A single wildcard label must also fit the existing wildcard TLS cert.
    return pattern == host or (pattern.startswith("*.") and host.split(".", 1)[1] == pattern[2:])


def namespace_allowed(listener, namespace):
    allowed = listener.get("allowedRoutes", {})
    kinds = allowed.get("kinds", [{"kind": "HTTPRoute"}])
    if not any(k.get("kind") == "HTTPRoute" and k.get("group", "gateway.networking.k8s.io")
               == "gateway.networking.k8s.io" for k in kinds):
        return False
    policy = allowed.get("namespaces", {})
    source = policy.get("from", "Same")
    if source == "All":
        return True
    if source == "Same":
        return namespace["metadata"]["name"] == "gateway-system"
    if source != "Selector":
        return False
    labels = namespace["metadata"].get("labels", {})
    selector = policy.get("selector", {})
    if any(labels.get(k) != v for k, v in selector.get("matchLabels", {}).items()):
        return False
    for item in selector.get("matchExpressions", []):
        key, op, values = item["key"], item["operator"], item.get("values", [])
        if not {"In": key in labels and labels[key] in values,
                "NotIn": key not in labels or labels[key] not in values,
                "Exists": key in labels, "DoesNotExist": key not in labels}.get(op, False):
            return False
    return True


def route_site(route, namespaces, services, gateway):
    meta, spec = route["metadata"], route["spec"]
    ns, annotations = meta["namespace"], meta.get("annotations", {})
    hosts = spec.get("hostnames", [])
    if len(hosts) != 1 or not hostname(hosts[0]):
        raise ValueError("one exact lowercase hostname is required")
    host = hosts[0]
    parents = spec.get("parentRefs", [])
    if len(parents) != 1:
        raise ValueError("one explicit Gateway listener is required")
    parent = parents[0]
    if (parent.get("name") != "internal" or parent.get("namespace", ns) != "gateway-system"
            or parent.get("group", "gateway.networking.k8s.io") != "gateway.networking.k8s.io"
            or parent.get("kind", "Gateway") != "Gateway" or parent.get("port", 443) != 443):
        raise ValueError("parent must be gateway-system/internal on HTTPS port 443")
    listener = next((x for x in gateway["spec"]["listeners"] if x["name"] == parent.get("sectionName")), {})
    if (listener.get("protocol") != "HTTPS" or listener.get("port") != 443
            or not matches_hostname(listener.get("hostname", ""), host)
            or not namespace_allowed(listener, namespaces[ns])):
        raise ValueError("hostname or namespace is not allowed by the selected HTTPS listener")
    rules = spec.get("rules", [])
    if len(rules) != 1 or set(rules[0]) - {"matches", "backendRefs"}:
        raise ValueError("one catch-all rule without filters is required")
    rule = rules[0]
    matches = rule.get("matches", [{"path": {"type": "PathPrefix", "value": "/"}}])
    if matches != [{"path": {"type": "PathPrefix", "value": "/"}}]:
        raise ValueError("only a catch-all PathPrefix / match is supported")
    refs = rule.get("backendRefs", [])
    if (len(refs) != 1 or refs[0].get("name") != "authn-edge"
            or refs[0].get("namespace", ns) != "authn" or refs[0].get("port") != 80
            or refs[0].get("kind", "Service") != "Service" or refs[0].get("group", "") != ""
            or refs[0].get("weight", 1) != 1 or refs[0].get("filters")):
        raise ValueError("backendRefs must point only to authn/authn-edge port 80")
    name = annotations.get(PREFIX + "backend-service", "")
    port = annotations.get(PREFIX + "backend-port", "")
    if not DNS_LABEL.fullmatch(name) or not re.fullmatch(r"[0-9]{1,5}", port):
        raise ValueError("backend-service and numeric backend-port annotations are required")
    service = services.get((ns, name), {}).get("spec", {})
    if (service.get("type", "ClusterIP") != "ClusterIP" or not service.get("selector")
            or service.get("clusterIP") == "None"
            or not any(p["port"] == int(port) and p.get("protocol", "TCP") == "TCP"
                       for p in service.get("ports", []))
            or (ns, name) == ("authn", "authn-edge")):
        raise ValueError("backend must be a selected ClusterIP Service port in the route namespace")
    native = annotations.get(PREFIX + "native-authorization", "false")
    if native not in ("true", "false"):
        raise ValueError("native-authorization must be true or false")
    title = annotations.get(PREFIX + "title", meta["name"])
    if not 1 <= len(title) <= 100 or any(ord(c) < 32 for c in title):
        raise ValueError("title must be 1..100 printable characters")
    return {"name": meta["name"], "title": title, "host": host, "scope": listener["name"],
            "upstream": f"{name}.{ns}.svc.cluster.local:{int(port)}",
            "native_authorization": native == "true", "source": f"{ns}/{meta['name']}"}


def discover(seeds, routes, namespaces, services, gateway, login_host):
    sites = {s["host"]: dict(s, source="built-in") for s in seeds}
    rejected, candidates = {}, {}
    for route in routes:
        meta = route["metadata"]
        if meta.get("labels", {}).get(PREFIX + "enabled") != "true" or meta.get("deletionTimestamp"):
            continue
        source = f"{meta['namespace']}/{meta['name']}"
        try:
            site = route_site(route, namespaces, services, gateway)
            if site["host"] in sites or site["host"] == login_host:
                raise ValueError("hostname is reserved by a built-in site")
            # Reject overlapping claims, including unmarked routes pointing directly
            # at an app. Rewriting a Flux-owned route here would create a bypass race.
            for other in routes:
                if other is route or other["metadata"].get("deletionTimestamp"):
                    continue
                spec = other.get("spec", {})
                https_listeners = {x["name"] for x in gateway["spec"]["listeners"]
                                   if x.get("protocol") == "HTTPS" and x.get("port") == 443}
                attached = any(p.get("name") == "internal" and p.get("namespace", other["metadata"]["namespace"])
                               == "gateway-system" and p.get("sectionName") in https_listeners | {None}
                               for p in spec.get("parentRefs", []))
                if attached and (not spec.get("hostnames") or any(
                        h == site["host"] or h.startswith("*.") and site["host"].endswith(h[1:])
                        for h in spec["hostnames"])):
                    raise ValueError("another HTTPRoute claims this hostname on internal")
            candidates[site["host"]] = site
        except (ValueError, KeyError, TypeError) as error:
            rejected[source] = str(error)
    # Bound the generated ConfigMap size; keep selection deterministic at capacity.
    for host, site in sorted(candidates.items()):
        if len(sites) >= 100:
            rejected[site["source"]] = "site capacity reached (100 including built-ins)"
        else:
            sites[host] = site
    return dict(sorted(sites.items())), rejected


class Kubernetes:
    def __init__(self):
        self.credentials = Path("/var/run/secrets/kubernetes.io/serviceaccount")
        self.context = ssl.create_default_context(cafile=str(self.credentials / "ca.crt"))

    def call(self, method, path, body=None, optional=False):
        headers = {"Authorization": "Bearer " + (self.credentials / "token").read_text().strip(),
                   "Content-Type": "application/merge-patch+json" if method == "PATCH" else "application/json"}
        req = urllib.request.Request("https://kubernetes.default.svc" + path, method=method,
                                     headers=headers, data=None if body is None else json.dumps(body).encode())
        try:
            with urllib.request.urlopen(req, context=self.context, timeout=15) as response:
                return json.load(response)
        except urllib.error.HTTPError as error:
            if optional and error.code == 404:
                return None
            raise RuntimeError(f"Kubernetes {method} {path.split('?')[0]}: HTTP {error.code}") from None

    def items(self, path):
        items, cursor = [], ""
        while True:
            query = urllib.parse.urlencode({"limit": 500, "continue": cursor})
            page = self.call("GET", path + "?" + query)
            items.extend(page["items"])
            cursor = page.get("metadata", {}).get("continue", "")
            if not cursor:
                return items

    def reconcile(self, collection, kind, name, field, desired):
        current = self.call("GET", collection + name, optional=True)
        if current and current["metadata"].get("labels", {}).get("app.kubernetes.io/managed-by") != "authn-site-controller":
            raise ValueError(f"refusing to adopt unmanaged {kind}/{name}")
        if current and current.get(field) == desired:
            return
        body = {"apiVersion": "v1" if kind == "ConfigMap" else "gateway.networking.k8s.io/v1beta1",
                "kind": kind, "metadata": {"name": name, "namespace": "authn", "labels": MANAGED}, field: desired}
        if current:
            body["metadata"]["resourceVersion"] = current["metadata"]["resourceVersion"]
        self.call("PUT" if current else "POST", collection + name if current else collection, body)

    def rollout(self, name, revision):
        path = "/apis/apps/v1/namespaces/authn/deployments/" + name
        current = self.call("GET", path, optional=True)
        if current and current["spec"]["template"]["metadata"].get("annotations", {}).get(REVISION) != revision:
            # This manager preserves an added annotation across Flux reconciliation.
            self.call("PATCH", path + "?fieldManager=flux-client-side-apply", {
                "spec": {"template": {"metadata": {"annotations": {REVISION: revision}}}}})


def reconcile(api, seeds, settings):
    routes = api.items(GATEWAY + "v1/httproutes")
    namespaces = {n["metadata"]["name"]: n for n in api.items("/api/v1/namespaces")}
    services = {(s["metadata"]["namespace"], s["metadata"]["name"]): s for s in api.items("/api/v1/services")}
    gateway = api.call("GET", GATEWAY + "v1/namespaces/gateway-system/gateways/internal")
    sites, rejected = discover(seeds, routes, namespaces, services, gateway, "auth." + settings["DOMAIN"])
    generated = render(list(sites.values()))
    for filename, content in generated.items():
        for key, value in settings.items():
            content = content.replace("${" + key + "}", value)
        generated[filename] = content
    blueprint = generated.pop("cluster-sites.yaml")
    revision = hashlib.sha256(json.dumps(generated, sort_keys=True).encode()).hexdigest()
    generated["revision"] = revision
    # Two controller-owned maps: Flux never writes their data or owns their lifecycle.
    api.reconcile(CORE + "configmaps/", "ConfigMap", "authn-runtime-blueprints", "data", {"cluster-sites.yaml": blueprint})
    api.reconcile(CORE + "configmaps/", "ConfigMap", "authn-runtime", "data", generated)
    api.reconcile(CORE + "configmaps/", "ConfigMap", "authn-discovery-status", "data",
                  {"rejected.json": json.dumps(rejected, sort_keys=True)})
    source_namespaces = sorted({s["source"].split("/")[0] for s in sites.values()
                                if s["source"] != "built-in" and not s["source"].startswith("authn/")})
    # An empty from list is not valid. With no addons retain an authn-only grant.
    api.reconcile(GATEWAY + "v1beta1/namespaces/authn/referencegrants/", "ReferenceGrant",
                  "authn-discovered-routes", "spec", {
                      "from": [{"group": "gateway.networking.k8s.io", "kind": "HTTPRoute", "namespace": n}
                               for n in source_namespaces or ["authn"]],
                      "to": [{"group": "", "kind": "Service", "name": "authn-edge"}]})
    api.rollout("authentik-worker", hashlib.sha256(blueprint.encode()).hexdigest())
    api.rollout("authn-edge", revision)
    return rejected


def main():
    settings = {k: os.environ[k] for k in ("DOMAIN", "ADMIN_DOMAIN", "CLUSTER_DNS_IP")}
    if not hostname("auth." + settings["DOMAIN"]) or not hostname("auth." + settings["ADMIN_DOMAIN"]):
        raise ValueError("invalid domain settings")
    ipaddress.IPv4Address(settings["CLUSTER_DNS_IP"])
    raw = Path("/config/seed-sites.json").read_text()
    for key, value in settings.items():
        raw = raw.replace("${" + key + "}", value)
    seeds = json.loads(raw)
    api, previous = Kubernetes(), None
    while True:
        try:
            rejected = reconcile(api, seeds, settings)
            if rejected != previous:
                print(json.dumps({"rejected_routes": rejected}), flush=True)
                previous = rejected
            Path("/tmp/ready").touch()
        except (OSError, ValueError, KeyError, TypeError, RuntimeError) as error:
            Path("/tmp/ready").unlink(missing_ok=True)
            print(f"reconciliation failed: {type(error).__name__}: {error}", flush=True)
        time.sleep(30)


if __name__ == "__main__":
    main()
