"""Loopback-only authentication and OpenFGA authorization for the edge proxy."""
import hashlib
import json
import os
import re
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

CONFIG = Path(os.environ.get("AUTHN_CONFIG", "/config"))
SECRETS = Path(os.environ.get("AUTHN_SECRETS", "/secrets"))
STATE = Path(os.environ.get("AUTHN_STATE", "/state"))
OPENFGA_URL = os.environ.get("OPENFGA_URL", "http://openfga.authn.svc.cluster.local:8080")
COOKIE = "__Host-cluster_sso"
PRINCIPAL = re.compile(r"(?:user|agent):[A-Za-z0-9_.@-]{1,200}\Z")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


OPENER = urllib.request.build_opener(NoRedirect)


def request(url, headers, data=None):
    req = urllib.request.Request(url, headers=headers, data=data)
    try:
        with OPENER.open(req, timeout=5) as response:
            return response.status, response.headers, response.read(1024 * 1024)
    except urllib.error.HTTPError as error:
        return error.code, error.headers, b""


def upstream_cookie(raw):
    # Keep native application sessions, but never disclose the SSO session.
    return "; ".join(part.strip() for part in raw.split(";")
                     if part.strip() and not part.strip().split("=", 1)[0].startswith(COOKIE))


def authenticate(headers, site):
    token = headers.get("X-Cluster-Token", "")
    authorization = headers.get("Authorization", "")
    if not site.get("native_authorization") and authorization:
        if token or not authorization.startswith("Bearer "):
            return None
        token = authorization[7:]
    if token:
        if not re.fullmatch(r"[A-Za-z0-9_-]{43,128}", token):
            return None
        registry = json.loads((SECRETS / "agents.json").read_text())
        digest = hashlib.sha256(token.encode()).hexdigest()
        entry = registry.get(digest, {})
        principal = entry.get("principal", "")
        if (not principal.startswith("agent:") or not PRINCIPAL.fullmatch(principal)
                or entry.get("expires_at", 0) <= time.time()):
            return None
        return principal
    raw_cookie = headers.get("Cookie", "")
    if not raw_cookie:
        return None
    status, response_headers, _ = request(
        "http://127.0.0.1:4180/oauth2/auth", {"Cookie": raw_cookie})
    if status == 401 or status == 403:
        return None
    if status != 202:
        raise RuntimeError("session service unavailable")
    # This header comes from a fresh loopback call, never from the caller.
    subject = response_headers.get("X-Auth-Request-User", "")
    principal = "user:" + subject
    return principal if PRINCIPAL.fullmatch(principal) else None


def authorize(headers, identity_only=False):
    host = headers.get("X-Original-Host", "")
    sites = json.loads((CONFIG / "sites.json").read_text())
    if host not in sites:
        return 403, {}, b""
    principal = authenticate(headers, sites[host])
    if principal is None:
        return 401, {}, b""
    if identity_only:
        return 200, {"Content-Type": "application/json"}, json.dumps({"principal": principal}).encode()
    state = json.loads((STATE / "openfga.json").read_text())
    if not all(re.fullmatch(r"[0-9A-Z]{26}", state.get(key, ""))
               for key in ("store_id", "model_id")):
        raise ValueError("authorization state is not initialized")
    data = json.dumps({
        "authorization_model_id": state["model_id"],
        "tuple_key": {"user": principal, "relation": "can_access", "object": "clustersite:" + host},
        "consistency": "HIGHER_CONSISTENCY",
    }).encode()
    status, _, body = request(
        OPENFGA_URL + "/stores/" + state["store_id"] + "/check",
        {"Content-Type": "application/json",
         "Authorization": "Bearer " + (SECRETS / "openfga-token").read_text().strip()}, data)
    if status != 200:
        raise RuntimeError("authorization service unavailable")
    if json.loads(body).get("allowed") is not True:
        return 403, {}, b""
    return 204, {"X-Cluster-Principal": principal,
                 "X-Upstream-Cookie": upstream_cookie(headers.get("Cookie", ""))}, b""


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/healthz":
            status, headers, body = 200, {}, b"ok\n"
        elif self.path not in ("/check", "/identity"):
            status, headers, body = 404, {}, b""
        else:
            try:
                status, headers, body = authorize(self.headers, self.path == "/identity")
            except (OSError, ValueError, KeyError, TypeError, RuntimeError):
                # Fail closed without logging credentials or response bodies.
                status, headers, body = 503, {}, b"Authorization unavailable\n"
        self.send_response(status)
        for name, value in headers.items():
            self.send_header(name, value)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        pass


if __name__ == "__main__":
    ThreadingHTTPServer(("127.0.0.1", 9080), Handler).serve_forever()
