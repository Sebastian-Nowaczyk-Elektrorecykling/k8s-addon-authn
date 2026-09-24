"""Loopback-only permissions UI. The OpenFGA API key never leaves the server."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import urllib.parse

import authorizer

HOST = os.environ.get("PERMISSIONS_HOST", "permissions.admin.internal")
ASSETS = Path(__file__).resolve().parent
DISCOVERY = Path(os.environ.get("AUTHN_DISCOVERY", "/discovery"))


def catalog():
    return json.loads((authorizer.CONFIG / "sites.json").read_text())


def fga(action, data):
    state = json.loads((authorizer.STATE / "openfga.json").read_text())
    if not all(re.fullmatch(r"[0-9A-Z]{26}", state.get(key, "")) for key in ("store_id", "model_id")):
        raise RuntimeError("OpenFGA has not been initialized")
    if action == "write":
        data = dict(data, authorization_model_id=state["model_id"])
    status, _, body = authorizer.request(
        authorizer.OPENFGA_URL + "/stores/" + state["store_id"] + "/" + action,
        {"Authorization": "Bearer " + (authorizer.SECRETS / "openfga-token").read_text().strip(),
         "Content-Type": "application/json"}, json.dumps(data).encode())
    if status != 200:
        raise RuntimeError("OpenFGA request failed")
    return json.loads(body) if body else {}


def grants(host):
    result, cursor = [], ""
    while True:
        page = fga("read", {"tuple_key": {"object": "clustersite:" + host, "relation": "member"},
                            "page_size": 100, "continuation_token": cursor, "consistency": "HIGHER_CONSISTENCY"})
        result.extend(t["key"]["user"] for t in page.get("tuples", []))
        cursor = page.get("continuation_token", "")
        if not cursor:
            return sorted(result)


def membership(action, principal, host):
    if action not in ("grant", "revoke") or not isinstance(principal, str) or not authorizer.PRINCIPAL.fullmatch(principal):
        raise ValueError("Use grant or revoke with user:<OIDC-sub> or agent:<name>.")
    if not isinstance(host, str) or host not in catalog():
        raise ValueError("Select a currently registered site.")
    key = {"user": principal, "relation": "member", "object": "clustersite:" + host}
    desired = action == "grant"
    if (principal in grants(host)) != desired:
        try:
            fga("write", {"writes" if desired else "deletes": {"tuple_keys": [key]}})
        except RuntimeError:
            # Another administrator may have completed the same write concurrently.
            if (principal in grants(host)) != desired:
                raise


class Handler(BaseHTTPRequestHandler):
    def reply(self, status, body, content_type="application/json"):
        raw = json.dumps(body).encode() if content_type == "application/json" else body
        self.send_response(status)
        for name, value in {
            "Content-Type": content_type, "Content-Length": str(len(raw)), "Cache-Control": "no-store",
            "X-Content-Type-Options": "nosniff", "Referrer-Policy": "same-origin",
            "Content-Security-Policy": "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
        }.items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(raw)

    def handle_request(self, mutation=False):
        try:
            # Only NGINX in this pod can reach 127.0.0.1:9090. It overwrites this
            # principal after authentication. Recheck console access for every call.
            principal = self.headers.get("X-Cluster-Principal", "")
            if not authorizer.PRINCIPAL.fullmatch(principal) or not authorizer.allowed(principal, HOST):
                return self.reply(403, {"error": "Permission to administer sites is required."})
            url = urllib.parse.urlsplit(self.path)
            if mutation:
                if url.path != "/api/membership":
                    return self.reply(404, {"error": "Not found."})
                if (self.headers.get("Origin") != "https://" + HOST
                        or self.headers.get("X-Requested-With") != "authn-permissions"
                        or self.headers.get("Content-Type") != "application/json"
                        or self.headers.get("Transfer-Encoding")):
                    return self.reply(403, {"error": "A same-origin JSON request is required."})
                size = int(self.headers.get("Content-Length", "0"))
                if not 0 < size <= 4096:
                    return self.reply(413, {"error": "Invalid request size."})
                data = json.loads(self.rfile.read(size))
                if not isinstance(data, dict) or set(data) != {"action", "principal", "host"}:
                    raise ValueError("Expected action, principal and host.")
                membership(data["action"], data["principal"], data["host"])
                # Log grant changes, never credentials or request headers.
                print(json.dumps({"actor": principal, **data}), flush=True)
                return self.reply(200, {"ok": True})
            if url.path == "/api/catalog":
                return self.reply(200, {"principal": principal, "console_host": HOST,
                                       "sites": list(catalog().values()),
                                       "rejected": json.loads((DISCOVERY / "rejected.json").read_text())})
            if url.path == "/api/grants":
                host = urllib.parse.parse_qs(url.query).get("host", [""])[0]
                if host not in catalog():
                    raise ValueError("Select a currently registered site.")
                return self.reply(200, {"principals": grants(host)})
            assets = {"/": ("index.html", "text/html; charset=utf-8"),
                      "/app.js": ("app.js", "text/javascript; charset=utf-8"),
                      "/style.css": ("style.css", "text/css; charset=utf-8")}
            if url.path in assets:
                filename, mime = assets[url.path]
                return self.reply(200, (ASSETS / filename).read_bytes(), mime)
            self.reply(404, {"error": "Not found."})
        except ValueError as error:
            self.reply(400, {"error": str(error)})
        except (OSError, KeyError, TypeError, RuntimeError):
            self.reply(503, {"error": "Permission service unavailable. Check the site controller and OpenFGA."})

    def do_GET(self):
        self.handle_request()

    def do_POST(self):
        self.handle_request(mutation=True)

    def log_message(self, *_):
        pass


if __name__ == "__main__":
    ThreadingHTTPServer(("127.0.0.1", 9090), Handler).serve_forever()
