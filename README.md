# k8s-addon-authn

FluxCD add-on for ZITADEL SSO on a cluster already running
[minimum-k8s-net-elektro](https://github.com/Sebastian-Nowaczyk-Elektrorecykling/minimum-k8s-net-elektro)
and [k8s-addon-storage](https://github.com/Sebastian-Nowaczyk-Elektrorecykling/k8s-addon-storage).

It deploys ZITADEL with its Login UI, OAuth2 Proxy, Heimdall, and an authenticated
OpenFGA server. It reuses the existing Cilium Gateway, private CA, internal DNS,
Longhorn and CloudNativePG operator. **No OpenFGA store, authorization model or
relationship tuples are included.** Fine-grained authorization and agent delegation
are a later step.

## Routes

| URL | Purpose | Access |
| --- | --- | --- |
| `https://auth.internal` | Shared login, OIDC discovery and identity APIs | Native ZITADEL flows; login endpoints must be reachable before login |
| `https://zitadel.admin.internal/ui/console` | ZITADEL administration | Native ZITADEL SSO and IAM roles |
| `https://sso.admin.internal/oauth2/start` | Administrative browser-session helper | Public start/callback/logout endpoints only |
| `https://hubble.admin.internal` | Hubble UI | Admin SSO |
| `https://longhorn.admin.internal` | Longhorn GUI | Admin SSO |
| `https://openfga.admin.internal` | OpenFGA administrative HTTP API | Admin SSO plus the native OpenFGA API key; no playground |
| `https://garage.admin.internal/health` | Garage administrative listener | Admin SSO; existing Garage token restrictions remain |
| `https://heimdall.admin.internal/.well-known/health` | Proxy management health | Admin SSO |

The administrative SSO gate initially permits only exact, verified email
addresses in a Kubernetes Secret. Signing in as an ordinary user does not grant
administrative access. Business permissions are not encoded into identity tokens.

S3, SQL, DNS, Kubernetes and internal operator services keep their native
authentication/protocols and are not published through a browser-login proxy.
The reference repositories install no separate CNPG, Velero, Flux or
cert-manager GUI. See the [service boundaries](docs/operations.md#native-apis-and-service-boundaries).

## Install

Use a machine with the cluster's LAN DNS, kubeconfig and trusted private CA.
Required tools: `kubectl`, `jq`, `openssl`, `curl`, and OpenTofu 1.12.6.
The base domain is `internal`,
Gateway is `gateway-system/internal`, and base Flux dependency names are used
as deployed by the two repositories.

```bash
git clone https://github.com/Sebastian-Nowaczyk-Elektrorecykling/k8s-addon-authn.git
cd k8s-addon-authn
bash scripts/bootstrap.sh --admin-email you@example.com
```

Use your real administrator email. Bootstrap:

1. Checks base/storage readiness and preserves or creates the initial Secrets,
   including the administrator email allowlist before any proxy pod is deployed.
2. Applies the Flux source and root Kustomization; creates two CNPG databases,
   the identity service, private API and SSO infrastructure.
3. Uses the official ZITADEL provider to register the console domain, initial
   human administrator and confidential OIDC web client with the exact callback.
   Provisioning state lives in an RBAC-protected Kubernetes Secret.
4. Creates the proxy's OIDC credentials, then waits for all add-on
   Kustomizations to reconcile.

The initial password is written to `.state/bootstrap-admin-password`, never to
Git or stdout. Change it on first login and enroll MFA. Public registration is
disabled. Reruns preserve existing master/API/cookie keys and the allowlist.
Protect and back up the credentials listed in [operations](docs/operations.md).

This add-on creates the Hubble and Longhorn SSO routes through the shared
administration listener. Hubble's UI and Service are supplied by the base Cilium
installation. After bootstrap, verify the routes:

```bash
bash scripts/check.sh
```

For a different secret-management workflow, create the documented Secrets before
`kubectl apply -k bootstrap`, then run the provisioning stage. Applying YAML alone
cannot generate an OIDC client inside an identity provider that has not started.
Absent credentials leave protected workloads pending or denying access.
If OAuth2 Proxy reports a missing Secret, follow the
[bootstrap recovery steps](docs/operations.md#oauth2-proxy-waiting-for-secrets).

## Layout and versions

| Component | Chart | Application |
| --- | --- | --- |
| ZITADEL and Login | 10.0.6 | v4.15.3 |
| OAuth2 Proxy | 10.7.0 | v7.15.3 |
| Heimdall | 0.16.22 | v0.17.22 |
| OpenFGA | 0.3.14 | v1.20.0 |
| ZITADEL provisioning provider | — | 3.8.6 |

`bootstrap/` installs the Flux source/root; `clusters/lan/` defines dependency
ordering; `infrastructure/` contains releases, routes, databases and ingress
guards; `provisioning/` contains declarative identity configuration.

Databases and ingress guards are retained on removal. The default is a single
replica suitable for the existing single-node cluster, not an HA installation.
Database backup destinations/schedules are not configured by this add-on.

## Validate

```bash
python3 -m pip install -r requirements-dev.txt
bash scripts/install-validation-tools.sh  # Linux/amd64; or install the pinned tools yourself
export PATH="$PWD/.cache/bin:$PATH"
python3 scripts/validate.py
python3 -m unittest discover -s tests -v
tofu -chdir=provisioning init -backend=false
tofu -chdir=provisioning validate
```

CI renders every Flux path and the pinned upstream charts, validates native and
custom-resource schemas, checks route ownership and exposure, and exercises the
real Heimdall binary for successful forwarding, anonymous denial, forged headers,
identity outages and write-origin checks. Live browser login, gateway routing and
streaming acceptance checks are documented separately.

[Design and integration references](docs/design.md) ·
[Operations, recovery and acceptance checks](docs/operations.md)
