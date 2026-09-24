"""Route admission, reconciliation and generated SSO configuration contracts."""
import copy
import json
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "apps/site-controller"))
import controller


class DiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.route = {"metadata": {"name": "budget", "namespace": "budget", "labels": {
            controller.PREFIX + "enabled": "true"}, "annotations": {
                controller.PREFIX + "backend-service": "budget", controller.PREFIX + "backend-port": "8080",
                controller.PREFIX + "title": "Budget"}},
            "spec": {"parentRefs": [{"name": "internal", "namespace": "gateway-system", "sectionName": "apps-https"}],
                     "hostnames": ["budget.internal"], "rules": [{"backendRefs": [
                         {"name": "authn-edge", "namespace": "authn", "port": 80}]}]}}
        self.namespaces = {"budget": {"metadata": {"name": "budget", "labels": {"route-scope": "applications"}}}}
        self.services = {("budget", "budget"): {"metadata": {"namespace": "budget", "name": "budget"},
                         "spec": {"selector": {"app": "budget"}, "ports": [{"port": 8080}]}}}
        self.gateway = {"spec": {"listeners": [
            {"name": "apps-https", "port": 443, "protocol": "HTTPS", "hostname": "*.internal",
             "allowedRoutes": {"namespaces": {"from": "Selector", "selector": {"matchLabels": {"route-scope": "applications"}}}}},
            {"name": "http", "port": 80, "protocol": "HTTP", "hostname": "*.internal"}]}}
        self.seeds = [{"name": "home", "host": "home.internal", "scope": "applications", "upstream": "heimdall.authn.svc.cluster.local:80"}]

    def discover(self, routes=None):
        return controller.discover(self.seeds, [self.route] if routes is None else routes,
                                   self.namespaces, self.services, self.gateway, "auth.internal")

    def test_opt_in_site_uses_only_its_namespace_service(self):
        sites, errors = self.discover()
        self.assertEqual(errors, {})
        self.assertEqual(sites["budget.internal"]["upstream"], "budget.budget.svc.cluster.local:8080")
        self.assertEqual(sites["budget.internal"]["source"], "budget/budget")
        self.route["metadata"]["labels"].clear()
        self.assertNotIn("budget.internal", self.discover()[0])

    def test_unsafe_route_shapes_are_not_registered(self):
        changes = [
            lambda r: r["spec"].update(hostnames=["*.internal"]),
            lambda r: r["spec"].update(hostnames=["auth.internal"]),
            lambda r: r["spec"].update(hostnames=["home.internal"]),
            lambda r: r["spec"].update(hostnames=["budget.internal; return 200;"]),
            lambda r: r["spec"].update(hostnames=["budget.evil.example"]),
            lambda r: r["spec"]["parentRefs"][0].update(sectionName="http"),
            lambda r: r["spec"]["rules"][0]["backendRefs"][0].update(name="budget"),
            lambda r: r["spec"]["rules"][0]["backendRefs"][0].update(filters=[{"type": "RequestHeaderModifier"}]),
            lambda r: r["spec"]["rules"][0].update(filters=[{"type": "RequestRedirect"}]),
            lambda r: r["spec"]["rules"][0].update(matches=[{"path": {"type": "PathPrefix", "value": "/app"}}]),
            lambda r: r["metadata"]["annotations"].update({controller.PREFIX + "backend-service": "other.other.svc"}),
            lambda r: r["metadata"]["annotations"].update({controller.PREFIX + "backend-port": "9999"}),
        ]
        for change in changes:
            with self.subTest(change=change):
                route = copy.deepcopy(self.route); change(route)
                sites, errors = self.discover([route])
                self.assertEqual(set(sites), {"home.internal"})
                self.assertIn("budget/budget", errors)

    def test_direct_route_collision_rejects_registration_but_http_redirect_does_not(self):
        other = copy.deepcopy(self.route); other["metadata"]["name"] = "direct"
        other["metadata"]["labels"].clear()
        other["spec"]["rules"][0]["backendRefs"] = [{"name": "budget", "port": 8080}]
        self.assertNotIn("budget.internal", self.discover([self.route, other])[0])
        other["spec"]["parentRefs"][0]["sectionName"] = "http"
        other["spec"]["hostnames"] = ["*.internal"]
        self.assertIn("budget.internal", self.discover([self.route, other])[0])

    def test_namespace_and_external_service_restrictions(self):
        self.namespaces["budget"]["metadata"]["labels"].clear()
        self.assertNotIn("budget.internal", self.discover()[0])
        self.namespaces["budget"]["metadata"]["labels"]["route-scope"] = "applications"
        self.services[("budget", "budget")]["spec"]["type"] = "ExternalName"
        self.assertNotIn("budget.internal", self.discover()[0])

    def test_new_site_and_removal_reconcile_all_allowlists_without_granting_anything(self):
        fixture = self

        class API:
            data, rollouts = {}, {}
            def items(self, path):
                if path.endswith("httproutes"): return routes
                if path.endswith("namespaces"): return list(fixture.namespaces.values())
                if path.endswith("services"): return list(fixture.services.values())
                raise AssertionError(path)
            def call(self, method, path):
                self_path = controller.GATEWAY + "v1/namespaces/gateway-system/gateways/internal"
                if method != "GET" or path != self_path: raise AssertionError(path)
                return fixture.gateway
            def reconcile(self, collection, kind, name, field, desired):
                self.data[name] = desired
            def rollout(self, name, revision):
                self.rollouts[name] = revision

        api, routes = API(), [self.route]
        settings = {"DOMAIN": "internal", "ADMIN_DOMAIN": "admin.internal", "CLUSTER_DNS_IP": "10.43.0.10"}
        controller.reconcile(api, self.seeds, settings)
        initial = api.rollouts.copy()
        data = api.data["authn-runtime"]
        self.assertIn("budget.internal", json.loads(data["sites.json"]))
        self.assertIn("server_name budget.internal;", data["nginx.conf"])
        self.assertIn('"budget.internal"', data["oauth2-proxy.cfg"])
        blueprint = api.data["authn-runtime-blueprints"]["cluster-sites.yaml"]
        self.assertIn("matching_mode: strict\n          url: https://budget.internal/oauth2/callback", blueprint)
        self.assertIn("authorization_code", blueprint)
        self.assertEqual(api.data["authn-discovered-routes"]["from"][0]["namespace"], "budget")
        controller.reconcile(api, self.seeds, settings)
        self.assertEqual(initial, api.rollouts)
        routes.clear()
        controller.reconcile(api, self.seeds, settings)
        self.assertNotIn("budget.internal", api.data["authn-runtime"]["sites.json"])
        self.assertNotIn("budget.internal", api.data["authn-runtime-blueprints"]["cluster-sites.yaml"])
        self.assertNotEqual(initial, api.rollouts)


if __name__ == "__main__":
    unittest.main()
