# Operations and acceptance

## Traffic and trust

The existing Gateway terminates private-CA HTTPS and sends declared hosts to
nginx. For protected applications, a loopback-only adapter validates either
an oauth2-proxy session or an expiring agent credential, then checks OpenFGA.
A positive decision is required; timeouts, malformed replies, missing state,
and API failures deny access. The adapter and oauth2-proxy have no externally
reachable Service or Kubernetes service-account token. Identity comes from a
fresh session check or the agent registry, never caller-supplied user headers.

The IdP must remain reachable before authentication. `auth.internal` exposes
native authentik login, OIDC, and user APIs; authentik enforces native API RBAC.
Its admin UI path is blocked there, while the administrative hostname adds the
OpenFGA gate. This does not replace authentik API permissions. `/oauth2/*` on
each site serves login/callback/logout, and `/authn/identity` exposes only the
verified caller's principal. Neither is an application-backend bypass.

Cookies use Secure, HttpOnly, host-only `__Host-` names. Each site performs its
own OIDC handshake, reusing the authentik login. There is no parent-domain
`.internal` cookie. Strict callback allowlists, PKCE, nonce checking, issuer
checking, and private-CA verification are enabled. Explicit OIDC endpoints
avoid a startup discovery loop through the edge. Deep links currently return
to the site's root after login; revisit the original URL afterward.
Identity discovery returns directly to `/authn/identity`, which works before
any site grant exists. The authentik provider explicitly permits only the
`authorization_code` grant used by oauth2-proxy; refresh and machine grants
are not enabled on this provider.

Kubernetes administrators and in-cluster workloads with network access are
trusted. This add-on protects LAN HTTP routes, not the cluster's tenant
boundary. ClusterIP services remain reachable inside the cluster. Apply
appropriate network/admission policies before hosting untrusted workloads,
and prevent others from publishing competing direct routes. PostgreSQL and
OpenFGA retain native credentials. Native application permissions remain
independent of site grants.

## First-run acceptance

```bash
kubectl -n flux-system get kustomizations -l app.kubernetes.io/part-of=authn-addons
kubectl -n authn get helmrelease,pods,clusters.postgresql.cnpg.io,pvc
kubectl -n authn get httproutes,referencegrants
kubectl -n authn-admin get httproutes
```

Check current-generation Ready conditions and each route's `Accepted=True`
and `ResolvedRefs=True` on the intended Gateway listener.

1. With a fresh browser session, request Hubble/Longhorn. Expect an HTTPS
   login redirect, not a backend page. No direct `hubble-test` route may remain.
2. Log in without a grant. Expect 403. Check `/authn/identity` for your subject.
3. Grant only `home.internal`. Verify Heimdall works and admin sites still
   return 403. Configure/restrict Heimdall's native settings before other users.
4. Add the intended admin grants. Verify Hubble/Longhorn work and authentik
   administration still requires its native administrator permissions/session.
5. Revoke a site while signed in. New requests must fail. Existing long-lived
   connections, such as WebSockets, retain their initial decision until closed.
6. Issue an agent token and grant one site. Test missing/invalid credentials
   (401), granted access, other sites (403), token expiry, and revocation.
7. Test Garage with the real SDK: uploads/downloads, multipart if needed,
   path-style addressing, native SigV4, and the unsigned site-token header.
   Test site authorization separately from invalid S3 signatures. OpenFGA's
   external API similarly requires its native key and a site credential.
8. Confirm previous network/storage components remain Ready.

SMTP, external directories, MFA enrollment policies, Heimdall tiles/native
accounts, and backup destinations remain operator choices. Public authentik
self-enrollment is not enabled. Configure these deliberately before rollout.

## Sessions, credentials, and recovery

Proxy sessions expire after one hour without refresh. Disabling an authentik
account may leave an issued proxy session usable until expiry. Revoke its
OpenFGA grants too for immediate denial of new requests. Logging out of one
site does not clear another site's host-only cookie or necessarily end the
IdP session. Configure your desired authentik session/MFA policy separately.

Runtime resources initialized outside Git:

| Resource in `authn` | Contents |
| --- | --- |
| `authn-secrets` Secret | authentik key, bootstrap password/email, OIDC/cookie secrets, OpenFGA API key |
| `authn-agents` Secret | Token digests, principal IDs, expirations |
| `authn-openfga-state` ConfigMap | Store ID, pinned model ID/hash |
| `authn-ca` ConfigMap | Public root CA only |
| `authn-runtime` ConfigMap | Controller-generated live site catalog and edge configuration |
| `authn-runtime-blueprints` ConfigMap | Controller-generated strict OIDC callback blueprint |
| `authn-discovery-status` ConfigMap | Rejected addon routes and reasons |
| `authentik-db-app`, `openfga-db-app` Secrets | CNPG-generated database credentials |

Preserve the authentik secret key: hashed subjects and their grants depend on
it. Setup never rotates existing secrets. Env-based secret changes require
rolling the affected pods. Projected agent-registry updates may take about
two minutes; revoke site grants for immediate denial, or restart `authn-edge`
to force a fresh registry. `revoke-agent` removes all credentials for the agent.
A new token can share an existing agent principal; remove the old digest only
after migrating the caller, using Kubernetes resource-version concurrency
protection to avoid losing another operator's updates.

Keep a cluster-admin kubeconfig for break-glass access. `scripts/access.py`
uses a temporary localhost-only port-forward and the native API key; it does
not depend on SSO working. If the state ConfigMap is lost, `access.py init`
recovers a uniquely named `cluster-sites` store with the same model, and refuses
ambiguous stores or incompatible existing models.

## Changes and upgrades

For addon sites, use the [dynamic HTTPRoute contract](dynamic-sites.md) in the
addon's repository. No change to this repository is required. For built-in
sites, edit `config/sites.json`, run `python3 scripts/generate.py`, and commit
the generated files. Both paths feed the controller's live configuration.
The controller rolls the edge and authentik worker when their configuration
changes; verify the blueprint status before trying a new callback. Every new
site still needs an explicit grant, using the permissions page or CLI.

Ordinary hosts use `applications`/`apps-https`; admin tools use
`administration`/`admin-https`. Keep native `Authorization` forwarding only
where needed. Do not derive upstream URLs from arbitrary request headers.
For forks change `bootstrap/source.yaml` and commit before attaching Flux.
For domain changes update base DNS/TLS/settings first and migrate full-domain
OpenFGA tuples to the new names.

Pin new chart/image versions, read upstream upgrade notes, run validation,
and back up state before upgrading. OpenFGA runs its database migration before
its server starts. Model changes require reviewing both `model.fga` and
`model.json`, followed by `python3 scripts/access.py init --upgrade-model`.
The old model remains available; a reviewed change to the state ConfigMap can
restore its ID if compatible. The edge never implicitly uses the latest model.

## Backups, CA changes, and removal

The baseline has one instance and one Longhorn replica per database/volume.
It is not HA and configures no backups. Back up both PostgreSQL databases,
the Heimdall PVC, runtime Secrets, OpenFGA state, and the base CA. Installed
Velero/Barman operators alone do not make a recovery solution. Authentik
users/providers/signing keys/policies live in PostgreSQL. Use external icon
URLs; add persistent/object storage before relying on uploaded authentik files
or custom templates stored in its otherwise ephemeral containers.

The base repository renews the Gateway leaf certificate. After changing its
root CA, rerun setup to refresh `authn-ca`, restart `authn-edge` to reload the
trust bundle, and redistribute the public CA to clients. Setup never reads or
copies the private CA key.

For removal, remove external routes first, suspend reconciliation, and back
up state. Stateful stages do not prune and deleting Flux Kustomizations orphans
resources. Deleting namespaces/PVCs/CNPG clusters can still destroy their data.
Do not delete the shared Gateway, base settings, or storage operators owned by
other repositories.

## Troubleshooting

- **OAuth callback says `invalid_request`:** authentik rejects authorization
  requests when the provider has no enabled grant types. Older revisions of
  this repository omitted `grant_types`; new authentik providers default to
  an empty list. Update to the fixed blueprint and let Flux and authentik
  reconcile it. To repair an existing provider immediately, run the following
  using your administrator kubeconfig (no password or token is printed):

  ```bash
  kubectl -n authn exec deployment/authentik-worker -c worker -- ak shell -c \
    'from authentik.providers.oauth2.models import OAuth2Provider; p = OAuth2Provider.objects.get(client_id="cluster-sites"); p.grant_types = ["authorization_code"]; p.save(update_fields=["grant_types"]); print("Enabled authorization_code for cluster-sites")'
  ```

  Start a fresh login at `https://home.internal/oauth2/start?rd=/authn/identity`
  instead of refreshing the failed callback URL. The database repair takes
  effect without a pod restart. If the error persists, inspect authentik server
  logs for the rejected parameter; a callback `invalid_request` is an IdP
  request-validation error, not an OpenFGA site denial.
- **Flux not Ready:** inspect conditions and named prerequisites; do not remove
  dependencies to conceal missing operators.
- **OIDC callback/provider errors:** inspect authentik worker/blueprint status,
  the default signing certificate, exact callback hostnames, and the OIDC
  client secret. Defaults must initialize before the blueprint can reconcile.
- **TLS failures:** compare `authn-ca` with the Gateway issuer and client trust;
  do not turn verification off.
- **403 after login:** check `/authn/identity`, the exact hostname tuple, and the
  pinned model/store IDs.
- **500/503:** check OpenFGA, its API key/state, and oauth2-proxy connectivity.
  Dependency failures deliberately deny access.
- **S3 signature failure:** check path-style endpoint, region, Host header,
  native credentials, and absence of `X-Cluster-Token` from `SignedHeaders`.

Edge access logs and proxy auth logs are disabled to avoid recording sensitive
query strings. The permissions container logs successful changes with actor,
action, principal and hostname; it never logs the native API credential. Add
central log retention and a reviewed audit/metrics setup with your monitoring stack.
