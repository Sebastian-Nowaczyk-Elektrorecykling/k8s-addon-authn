# Operations

## Access and credentials

The initial human is an instance administrator in ZITADEL and is the first entry
in the administrative browser allowlist. These are separate controls: ZITADEL's
native console checks its own IAM roles; OAuth2 Proxy checks the allowlist for
Hubble, Longhorn, Garage, Heimdall and OpenFGA routes.

To add another browser administrator, create/invite a human in ZITADEL, verify
their email, and update Secret `authn-admin/authn-admin-access`, key `emails`
(one exact email per line). Use a private file and `kubectl create secret
--from-file --dry-run=client -o yaml | kubectl apply --server-side
--field-manager=authn-bootstrap -f -`. Restart `authn-admin/oauth2-proxy` after
changes so the running process uses the new list. Do not use `email_domains=["*"]`.
Removing an allowlist entry denies the next session validation after that restart.

The one-hour browser session stores minimal identity data in an encrypted,
Secure, HttpOnly cookie scoped to `.admin.internal`. There is no refresh token.
Heimdall validates it with OAuth2 Proxy on each protected request, with no identity
cache. Invalid sessions, unavailable OAuth2 Proxy, unknown routes and failed
checks do not reach the application. If ZITADEL is temporarily unavailable,
existing unexpired local sessions can continue; new login fails. ZITADEL-side
session revocation is therefore not instantaneous at these applications.
To invalidate every proxy session immediately, rotate the cookie secret and
restart OAuth2 Proxy.

The login endpoints are deliberately public: an unauthenticated user must be able
to reach the issuer, authorize/token endpoints and login UI. ZITADEL Console is
an OIDC application with native administrator authorization, not an unprotected
proxy bypass. The alias is registered with ZITADEL's instance-domain API by its
official provider, which also registers console callback URLs. Login V2 uses
`auth.internal` for the shared login.

## Secret inventory and recovery

| Namespace / Secret | Purpose |
| --- | --- |
| authn-system / zitadel-masterkey | Decrypts persisted ZITADEL data; preserve with the database |
| authn-system / zitadel-domain-provisioner | RSA key for the System API domain administrator; only its public certificate is mounted into ZITADEL |
| authn-system / authn-provisioner, authn-provisioner-pat | Chart-created deployment identity with IAM_OWNER; not an application agent |
| authn-system / zitadel-login-service-key (chart-generated name) | Login UI service authentication; confirm actual name in the installed release |
| authn-system / zitadel-db-app, zitadel-db-ca | CNPG-managed database credentials and CA |
| authn-admin / openfga-db-app, openfga-db-ca | CNPG-managed database credentials and CA |
| authn-admin / openfga-api-credentials | OpenFGA pre-shared API key in `keys` |
| authn-admin / oauth2-proxy-credentials | OIDC client ID/secret and cookie encryption key |
| authn-admin / authn-admin-access | Temporary exact-email administrator allowlist |
| authn-system / tfstate-default-zitadel | OpenTofu state, including the OIDC client secret |

Back up both PostgreSQL databases, the master key, login/provisioning credentials,
OAuth client/cookie credentials, allowlist, and OpenTofu state together.
`.state/` contains a copy of the public cluster CA, initial administrator email
and initial password. Protect it and delete the initial password only after
updating the provisioning workflow to no longer require that file.
Temporary PAT/key/client-secret files are removed when the provisioning script exits.

Existing Secrets are reused. Bootstrap refuses to invent a new ZITADEL master
key if its database already exists. Recover the original key instead.
Do not run `tofu destroy`: identity resources have `prevent_destroy` guards.

The initial machine key and PAT expire on **2027-09-01**; the System API
certificate is generated for one year. Rotate/revoke deployment credentials
through ZITADEL and update the corresponding Secrets before expiry. Revoke the
bootstrap PAT when provisioning is finished if it is not needed for subsequent
changes; future provisioning then requires a replacement administrator credential.

The public CA ConfigMap is copied from the base CA during bootstrap. After a
planned CA rotation, rerun `initialize-secrets.sh`, restart OAuth2 Proxy, and
redistribute the public CA to clients. TLS verification is never disabled.

## OAuth2 Proxy waiting for Secrets

The `admin-access` volume mounts Secret `authn-admin/authn-admin-access`, with
an `emails` key containing one administrator email per line. Bootstrap creates
it in `initialize-secrets.sh`, before applying the Flux source. Existing
allowlists are preserved. It is separate from `oauth2-proxy-credentials`, which
can only be created after ZITADEL's OIDC client has been provisioned.

If the pod reports `FailedMount: secret "authn-admin-access" not found`, the
initial Secret setup is incomplete. Earlier versions created the allowlist
only after identity provisioning, so an interrupted provisioning stage left
this volume missing too. Applying the Flux YAML alone does not create either
Secret.

From the original bootstrap checkout, retain `.state/`, pull the current `main`,
and rerun bootstrap with the same initial administrator email:

```bash
git pull --ff-only
bash scripts/bootstrap.sh --admin-email you@example.com
kubectl -n authn-admin get secret authn-admin-access oauth2-proxy-credentials
kubectl -n authn-admin rollout status deployment/oauth2-proxy --timeout=5m
```

Use the actual administrator email. To repair only the missing allowlist and
initial Secrets, run `bash scripts/initialize-secrets.sh --admin-email
you@example.com`. If OIDC credentials are also missing, finish bootstrap; do not
substitute placeholder client credentials. If bootstrap fails, resolve the
first reported error before waiting for proxy readiness. Keep the allowlist
volume required and retain the exact-email access restriction.

## Acceptance checks

Run `scripts/check.sh` from a machine using the cluster DNS. Then check:

1. Each HTTPRoute is Accepted with resolved backends. Both identity discovery
   endpoints return the expected issuer. ZITADEL Console stays on
   `zitadel.admin.internal` and completes its native login.
2. A fresh browser visiting Hubble or Longhorn redirects to ZITADEL. After login,
   both work without another credential prompt. Hubble live flows and Longhorn
   WebSocket updates continue; exercise a harmless Longhorn read operation.
3. A verified ordinary user who is absent from the allowlist cannot reach either
   GUI. A machine access token alone also cannot enter these browser routes.
4. Stop/restart an SSO proxy during a maintenance window and confirm protected
   routes fail closed. No direct Hubble response should appear during recovery.
   Check with a fresh connection; existing streams are not retroactively revoked.
5. Requests without cookies receive 401 for JSON/API requests; browser navigation
   receives a login redirect. Forged identity/forwarding headers do not grant access.
6. Unsafe methods require a matching `Origin: https://<route-host>`, in addition
   to a valid session. WebSocket and SSE behavior must be checked on the real gateway.

These live tests need your deployed cluster. Repository CI checks rendering,
schemas and the actual Heimdall binary against controlled identity/upstream
servers; it does not claim to exercise ZITADEL login against a live cluster.

## Native APIs and service boundaries

`openfga.admin.internal` adds the browser SSO gate **and retains OpenFGA's
pre-shared bearer-token requirement**. Use an authenticated browser session plus
the API key for administrative HTTP calls; unsafe methods also need a matching
Origin. Application SDKs should use the private OpenFGA Service and an explicitly
added network-policy allow rule. No SDK is redirected to a browser login.
The gRPC port is not exposed by the allow policy.

Garage's installed chart does not configure an Admin API token. Its SSO route
provides the existing administrative listener (for example `/health` and
`/metrics`); Garage's own disabled/authenticated management operations remain
disabled/authenticated. To enable management operations, configure a Garage
admin token in the storage repository following Garage's documentation. This
add-on does not weaken Garage authentication or modify its StatefulSet.
The endpoint is an API, not a newly installed Garage GUI.

S3, PostgreSQL, DNS, Kubernetes, Hubble Relay, operator webhooks and internal
metrics retain their native protocols. No browser SSO is inserted into SQL, S3
Signature V4, DNS, gRPC or Kubernetes client traffic. CNPG, Velero, Flux and
cert-manager do not install web administration UIs in the two reference repos.

The policies protect selected GUI/backend endpoints. They are not a complete
cluster zero-trust policy. Cilium policies are additive; an administrator adding a
broader allow policy can change the boundary. Kubernetes administrators and
authorized port-forward users retain their native cluster authority.

## Upgrades and removal

Chart/application versions are pinned in HelmReleases; the Helm and CRD schema
versions used for validation match the reference cluster. Review upstream release
notes, update pins, validate, and perform live acceptance checks after upgrades.
PostgreSQL image selection follows the already pinned CNPG operator's default.

The database and namespace Flux Kustomizations do not prune. All child
Kustomizations use `deletionPolicy: Orphan`. The ingress guards also disable
pruning. Removing the add-on's root reconciliation is therefore not a database
deletion or a way to reopen Hubble. Retained workloads may continue running until
an administrator deliberately removes them.

The supplied topology uses one instance of each database and application to fit
the base single-node installation. It is not highly available. Storage's Barman
and Velero installations do not themselves create backups for these databases;
configure and verify backups before treating this as durable identity
infrastructure.
