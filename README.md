# Cluster authentication and site authorization

FluxCD add-on for the existing
[network cluster](https://github.com/Sebastian-Nowaczyk-Elektrorecykling/minimum-k8s-net-elektro)
and [storage add-on](https://github.com/Sebastian-Nowaczyk-Elektrorecykling/k8s-addon-storage).
It installs **authentik, OpenFGA, Heimdall, and oauth2-proxy**, with SSO and
per-site authorization in front of new and existing HTTP services.

The existing `gateway-system/internal` Cilium Gateway terminates TLS. This
repository has a separate `authn-addons` Flux source and namespaces. It reuses
`DOMAIN`, `ADMIN_DOMAIN`, and `CLUSTER_DNS_IP` from the base repository's
`flux-system/cluster-settings` ConfigMap. It does not bootstrap Flux again or
replace the existing network/storage releases.

## Routes

Default names when the base domain is `internal`:

| URL | Purpose | Access |
| --- | --- | --- |
| `https://auth.internal` | authentik login, OIDC, user self-service | authentik's native authentication/permissions; login needs no OpenFGA grant |
| `https://home.internal` | Heimdall dashboard | SSO or agent token, plus an explicit site grant |
| `https://s3.internal` | Existing Garage S3 API, path-style addressing | Site grant plus native Garage SigV4 credentials |
| `https://authentik.admin.internal` | authentik administration | Site grant plus native authentik administrator permissions |
| `https://hubble.admin.internal` | Existing Hubble UI | Site grant |
| `https://longhorn.admin.internal` | Existing Longhorn UI | Site grant |
| `https://openfga.admin.internal` | OpenFGA management API | Site grant plus native OpenFGA API key |
| `https://permissions.admin.internal` | Visual site permissions | Explicit administrator site grant |

The administrative suffix never grants privileges by itself. OpenFGA is an
API, not a dashboard; its unauthenticated development playground is disabled.
The permissions page lists registered sites and their users/agents, and supports
granting and revoking access. Its OpenFGA credential stays on the server.
CNPG, Barman, Velero, Flux controllers, DNS, PostgreSQL, and Hubble Relay do not
have browser interfaces to publish. Garage's administration API is not enabled
by the prerequisite repository, so no nonfunctional route is added for it.

## Install

Requirements: healthy prerequisite repositories, at least one schedulable
worker/hybrid, free Longhorn capacity, Python 3.11+, `kubectl`, and an
administrator kubeconfig. Trust the base cluster's public CA and use its LAN
DNS. The baseline uses two `5Gi` database volumes and a `1Gi` Heimdall volume,
with one instance of each application/database. No Helm CLI is needed on the
cluster; the existing Flux Helm controller installs the chart.

Remove any temporary unauthenticated Hubble route with **the base repository's**
`scripts/hubble-route.py remove` first. Setup refuses overlapping routes,
including wildcard routes, so an old direct route cannot take precedence.

From the published `main` branch:

```bash
git clone https://github.com/Sebastian-Nowaczyk-Elektrorecykling/k8s-addon-authn.git
cd k8s-addon-authn
kubectl config current-context
# On k3s, set KUBECONFIG=/etc/rancher/k3s/k3s.yaml with appropriate permissions.
python3 scripts/setup.py --email your-admin@example.com
```

Setup checks dependencies, creates random credentials only when absent, copies
only the public CA certificate, attaches this repository to Flux, waits for
reconciliation, and initializes the OpenFGA store/model. Rerunning preserves
credentials, databases, agents, and grants. `--preflight-only` checks without
writing. `kubectl apply -k bootstrap` is an alternative only after namespaces,
secrets, and CA configuration have been prepared. Do not recursively apply the
whole repository.

**No site access is granted automatically.** Complete the first login before
admitting ordinary users.

## First administrator and ordinary users

1. Retrieve the initial password locally:

   ```bash
   kubectl -n authn get secret authn-secrets \
     -o jsonpath='{.data.bootstrap-password}' | base64 -d
   ```

2. Sign in as `akadmin` at `https://auth.internal`. Change its password and
   enroll MFA. The supplied bootstrap email belongs to this initial account.
3. Open `https://home.internal/authn/identity`. Complete login; it returns you
   directly to this endpoint. Copy the returned `user:<subject>`. This endpoint
   reveals only the caller's verified identity and does not need a site grant.
4. Grant the operator the necessary sites, substituting that subject:

   ```bash
   python3 scripts/access.py grant user:SUBJECT \
     home.internal authentik.admin.internal hubble.admin.internal longhorn.admin.internal \
     permissions.admin.internal
   ```

5. Open `https://authentik.admin.internal/if/admin/` to manage users. This
   hostname may require its own native authentik login in addition to SSO;
   cookies cannot reliably be shared across the single-label `.internal`
   suffix. Its site grant never replaces native administrator permissions.
6. Set up and restrict Heimdall's native administrator/settings before granting
   other people `home.internal`. Add the routes above as dashboard tiles.
   Heimdall has its own users/settings; site grants do not create native
   accounts or filter its displayed tiles.

Create ordinary accounts through authentik; this repository enables no public
self-enrollment. Users obtain their principal from `/authn/identity`, and an
operator grants individual sites:

```bash
python3 scripts/access.py grant user:SUBJECT home.internal
python3 scripts/access.py revoke user:SUBJECT home.internal
```

Identity uses the stable OIDC **`sub`**, not email, username, supplied identity
headers, or group names. oauth2-proxy also uses `sub` for its otherwise-required
email field; email claims are not authorization credentials. Every request
needs an explicit OpenFGA `member` tuple, checked through `can_access` with a
pinned authorization model and higher consistency.

## Dynamic addon sites and visual permissions

Addon sites no longer need an entry in `config/sites.json`. In the addon's
repository, label its HTTPRoute `authn.elektro.internal/enabled: "true"`, declare
the backend Service/port in annotations, and point the route at
`authn/authn-edge:80`. The site controller polls every 30 seconds and maintains
the live catalog, proxy configuration, exact OAuth callbacks and ReferenceGrant.
See the [complete HTTPRoute example and rollout steps](docs/dynamic-sites.md).

New sites appear automatically at `https://permissions.admin.internal` and in
`python3 scripts/access.py sites`. OpenFGA does not require a separate object
creation step: granting a user/agent writes a `member` relationship to
`clustersite:<hostname>`. Discovery itself grants nobody access.

On the permissions page, choose a site, paste `user:<OIDC-sub>` or `agent:<name>`,
and click **Grant access**. Existing grants have **Revoke** buttons. Obtain user
subjects from `/authn/identity`; the page does not synchronize the authentik
user directory. Access to the permissions page permits managing every site,
so grant `permissions.admin.internal` only to trusted administrators. Keep the
CLI and an administrator kubeconfig for recovery.

An ordinary HTTPRoute pointing directly at an application bypasses this edge;
it is not protected just because OpenFGA contains a hostname. The addon must
use the documented route contract. Existing built-in sites remain seed entries
in `config/sites.json`.

## Agents and service accounts

Agents use random, expiring credentials without a browser. Only the SHA-256
digest, principal, and expiry are stored in `authn-agents`. A token alone grants
no site access.

```bash
python3 scripts/access.py create-agent backup --days 30 --output /secure/path/backup.token
python3 scripts/access.py grant agent:backup s3.internal
# Revoke a grant immediately, or revoke every token for this agent:
python3 scripts/access.py revoke agent:backup s3.internal
python3 scripts/access.py revoke-agent backup
```

Keep credential files outside Git. Send the token as `X-Cluster-Token`.
Ordinary sites also accept `Authorization: Bearer <token>`. For **S3 and the
OpenFGA API**, use `X-Cluster-Token` so `Authorization` remains available for
SigV4 or the native OpenFGA API key. Invalid machine credentials receive 401,
not a browser redirect. Agent tokens and SSO cookies are stripped before
forwarding; native authorization is preserved only on explicitly configured
native APIs, including those two built-in APIs.

Garage clients need endpoint `https://s3.internal`, path-style addressing,
region `garage`, and a separately provisioned Garage access key/bucket. Add
`X-Cluster-Token` **after signing**, without putting it in SigV4 `SignedHeaders`,
because the proxy removes it before forwarding. Presigned URLs still need a
site credential/session. Clients unable to supply this header can use the
existing internal Garage Service from trusted cluster workloads with native
S3 credentials. `/oauth2/*` and `/authn/identity` are reserved external paths;
do not use `oauth2` or `authn` as S3 bucket names on this endpoint.

## Layout and reconciliation

| Path | Responsibility |
| --- | --- |
| `bootstrap/`, `clusters/lan/` | Separate Flux attachment and dependency graph |
| `infrastructure/databases/` | Two CNPG databases using `longhorn-cnpg` |
| `apps/authentik/` | Official Helm release and declarative OIDC blueprint |
| `apps/openfga/` | Persistent OpenFGA, migrations, authenticated API |
| `apps/heimdall/` | Persistent dashboard using `longhorn` |
| `apps/edge/` | nginx, oauth2-proxy, authorization adapter, and permissions console |
| `apps/site-controller/` | HTTPRoute discovery and runtime SSO configuration |
| `infrastructure/routes/` | Gateway routes and narrowly scoped ReferenceGrant |
| `config/sites.json` | Built-in seed sites; addon sites are discovered from HTTPRoutes |
| `openfga/` | Human-readable model and executable API model |
| `scripts/`, `tests/` | Setup, grants/tokens, generation, validation |

Database reconciliation waits for `storage-cnpg` and `storage-classes`.
Applications follow databases; the edge follows applications, DNS, and PKI;
routes follow the edge, gateway, Longhorn, and Garage. Stateful stages use
`prune: false`; Flux Kustomizations use `deletionPolicy: Orphan`.

| Component | Pin |
| --- | --- |
| authentik chart/application | `2026.8.3` |
| OpenFGA | `v1.21.0` |
| oauth2-proxy | `v7.15.4` |
| Heimdall LinuxServer image | `v2.8.3-ls364` |
| nginx | `1.30.5-alpine` |
| Authorization adapter runtime | `python:3.13.15-alpine` |

Inspected prerequisite revisions: network
`41126b04c18c18a3c192843e18b05cda8843c700`, storage
`f11ddf0910058ff7c336e52fabb18ea9e838d988`.

## Validate and operate

Install Python 3.11+, Helm `3.19.0`, Kustomize `5.7.1`, kubeconform `0.7.0`, and
the pinned oauth2-proxy/OpenFGA binaries. Live proxy tests need nginx with its
`http_auth_request` module.

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements-dev.txt
python3 scripts/generate.py --check
python3 scripts/validate.py
python3 -m unittest discover -s tests -v
```

Set `OPENFGA` and `NGINX` to binary paths if absent from `PATH`. Those integration
suites skip when the binaries are missing; CI requires them. Validation builds
all Flux targets, renders the actual Helm chart, checks Kubernetes/pinned CRD
schemas, and validates OAuth2 configuration. Tests exercise a real OpenFGA
server and nginx routing, grants/revocation, spoofed identities, credential
stripping, and fail-closed errors. They do not deploy a Kubernetes cluster or
complete an actual authentik browser login.

See [operations and acceptance](docs/operations.md) for rollout checks, native
permissions, session expiry, backups, CA rotation, adding sites, and recovery.
The [original requirements](docs/requirements.md) are preserved.

Upstream: [authentik Kubernetes](https://docs.goauthentik.io/install-config/install/kubernetes/),
[blueprints](https://docs.goauthentik.io/customize/blueprints/),
[oauth2-proxy configuration](https://oauth2-proxy.github.io/oauth2-proxy/configuration/overview/),
[OpenFGA modeling](https://openfga.dev/docs/modeling/getting-started),
[Heimdall container](https://docs.linuxserver.io/images/docker-heimdall/).
