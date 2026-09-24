# Dynamic addon sites

`config/sites.json` supplies the built-in sites. Addons register themselves by
publishing an opted-in HTTPRoute. OpenFGA uses the existing generic `clustersite`
model for every hostname; it has no separate create-site operation. Site
discovery maintains routing and OAuth configuration. Permission changes write
or delete `member` tuples in the existing store and pinned model.

## Add an addon

Assume the addon already has a `budget` Service on port `80` in namespace
`budget`. Add the label to that namespace's existing manifest and include this
HTTPRoute in the addon's Flux target:

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: budget
  labels:
    elektro.internal/route-scope: applications
---
apiVersion: gateway.networking.k8s.io/v1
kind: HTTPRoute
metadata:
  name: budget
  namespace: budget
  labels:
    authn.elektro.internal/enabled: "true"
  annotations:
    authn.elektro.internal/title: Budget
    authn.elektro.internal/backend-service: budget
    authn.elektro.internal/backend-port: "80"
spec:
  parentRefs:
    - name: internal
      namespace: gateway-system
      sectionName: apps-https
  hostnames:
    - budget.${DOMAIN}
  rules:
    - backendRefs:
        - name: authn-edge
          namespace: authn
          port: 80
```

Use the addon's Flux `postBuild.substituteFrom` for `cluster-settings`, or
replace `${DOMAIN}` with the real domain when applying manually. The backend
annotation is the Service's port, not its Pod targetPort. The Service must be a
non-headless ClusterIP Service with a selector in the route's own namespace.

For an administrative addon, use namespace scope `administration`, listener
`admin-https`, and a host under `${ADMIN_DOMAIN}`. Other existing HTTPS listeners
can be used when their hostname and namespace selector permit the route. DNS
and TLS must already cover that listener's domain. The controller does not
create new Gateway listeners or certificates.

The controller discovers this route on its next 30-second poll, creates a
ReferenceGrant allowing its namespace to reach only `authn-edge`, and updates
the proxy allowlist, backend mapping and strict authentik callback. New
backends are derived from validated Service metadata, never from request
headers or arbitrary URL annotations. Neither route discovery nor a domain
suffix grants access.

The Gateway backend **must** be `authn-edge`. Putting the app Service in
`backendRefs` bypasses SSO and OpenFGA. Update/remove an old direct route in the
addon's Git source as part of migration; the controller never rewrites
Flux-owned routes. It reports a conflicting route rather than claiming to
secure it. Only explicitly marked routes are discovered.

Supported routes have one exact lowercase hostname, one HTTPS listener on
`gateway-system/internal:443`, and one catch-all rule to the edge. Omit matches
or use exactly `PathPrefix /`. Path routing, filters, weighted backends and
cross-namespace application backends are rejected. The catalog is bounded to
100 sites including built-ins to keep generated ConfigMaps within Kubernetes
size limits. `/oauth2/*`, `/authn/identity` and `/_authn_check` are reserved by
the edge.

If an application needs its own `Authorization` header, add
`authn.elektro.internal/native-authorization: "true"`. Agents must then use
`X-Cluster-Token`; the native header is forwarded separately. Keep the default
`false` for ordinary browser applications.

## Grant permissions visually

After the new version reconciles, bootstrap the first permissions administrator
using the subject from `https://home.internal/authn/identity`:

```bash
python3 scripts/access.py grant user:SUBJECT permissions.admin.internal
```

Open `https://permissions.admin.internal`. Select a site to inspect all its
current direct grants, paste a `user:<OIDC-sub>` or `agent:<name>`, then choose
**Grant access**. Use **Revoke** to remove it. The search field filters names and
hostnames; rejected routes appear below the site list with their reason.

This page is an administrative console. Its site grant permits managing all
registered sites, including admission of other permission administrators.
It does not give ordinary users a way to request or approve their own grants.
Authentik still manages accounts, MFA and identity; this page uses verified
subjects, not email addresses. It does not create agent credentials.

The console's backend listens only on loopback within the edge pod. NGINX
authenticates the session and overwrites the caller principal before proxying;
the console rechecks its OpenFGA administrator grant on every request. Writes
require same-origin JSON requests. The browser never receives the native
OpenFGA credential and cannot call arbitrary OpenFGA API methods through this
UI. Successful changes are logged by the `permissions` container.

The OpenFGA Playground remains disabled. Upstream documents it as a local
prototyping tool with no OIDC support and recommends against production use:
[Using the OpenFGA Playground](https://openfga.dev/docs/getting-started/setup-openfga/playground).

The CLI uses the same live catalog:

```bash
python3 scripts/access.py sites
python3 scripts/access.py grant user:SUBJECT budget.internal
python3 scripts/access.py revoke user:SUBJECT budget.internal
```

For example, a grant writes:

```json
{"user": "user:SUBJECT", "relation": "member", "object": "clustersite:budget.internal"}
```

No authorization-model migration or OpenFGA store recreation is needed.

## Reconciliation, upgrades and removal

Flux installs the controller before authentik and the edge. The controller owns
`authn-runtime`, `authn-runtime-blueprints`, `authn-discovery-status` and
`authn-discovered-routes` in `authn`. These runtime resources are not declared
in Git; Flux does not overwrite their data. The controller has read access to
HTTPRoutes, namespaces and Services, and to the existing Gateway. Its writes
are confined to runtime ConfigMaps/ReferenceGrants and rollout patches on the
edge and authentik worker in `authn`; it does not mount OpenFGA credentials.

Changed configuration rolls the edge pod and, when callbacks change, the
authentik worker. Init containers wait for the expected projected config
revision. The edge takes a consistent startup snapshot; its authorizer keeps
reading the live catalog so removed hosts fail closed. The worker's rollout
annotation is excluded from Helm drift correction, and the edge's annotation
uses Flux's supported field manager.

Allow a few minutes for discovery, ConfigMap projection, pod restarts and
blueprint application. New logins can fail until authentik has applied the
callback. The single edge replica uses `Recreate`: changes briefly interrupt
traffic and existing WebSockets. Batch route changes when practical. This
version does not provide uninterrupted hot reload or HA.

To upgrade an existing installation, merge the change into its tracked branch
and wait for Flux to reconcile the new `authn-site-controller` stage before
testing. Existing databases, grants, credentials and object names are
preserved. The old `authentik-blueprints` ConfigMap may remain because that
Flux stage has pruning disabled; the new worker mounts only
`authn-runtime-blueprints`. Do not edit the runtime maps manually.

```bash
kubectl -n flux-system get kustomizations -l app.kubernetes.io/part-of=authn-addons
kubectl -n authn logs deployment/authn-site-controller --tail=50
kubectl -n authn get configmap authn-discovery-status -o yaml
kubectl -n authn rollout status deployment/authentik-worker
kubectl -n authn rollout status deployment/authn-edge
kubectl -n budget get httproute budget -o yaml
```

Check the route's current `Accepted=True` and `ResolvedRefs=True` conditions
and the authentik blueprint status. Sign in without a site grant and expect
403; grant the site and retry, then revoke it and check that new requests fail.
Also test an ordinary user's inability to open the permissions page. The local
test suite exercises discovery, real NGINX and OpenFGA, but does not replace
this cluster acceptance or an actual authentik browser login.

Deleting an addon HTTPRoute removes its runtime site and callback on the next
successful reconcile. Removing only the opt-in label leaves the route pointed
at the edge, which rejects its unregistered host. Existing OpenFGA tuples are
retained so a temporary Git rollback does not destroy permissions. **Reusing
the same hostname inherits those retained grants.** Revoke them before reuse;
the CLI permits revocation for removed hosts. API or reconciliation failures
mark the controller unready and are retried. Existing configuration may remain
active; inspect its logs rather than assuming a pending update has applied.

Runtime configuration is reproducible from Git and current routes. Preserve
the OpenFGA database/state and authentik secrets as described in
[operations](operations.md). The administrator CLI remains the recovery path
if every console administrator is revoked.
