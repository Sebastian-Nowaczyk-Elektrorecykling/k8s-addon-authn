#!/usr/bin/env bash
set -Eeuo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
[[ -s .state/ca.crt ]] || { echo 'Run initialize-secrets.sh to copy the public CA certificate.' >&2; exit 1; }
kubectl -n flux-system wait kustomizations -l app.kubernetes.io/part-of=authn-addons \
  --for=condition=Ready --timeout=60s
backend=$(kubectl -n administration get httproute administration -o json |
  jq -r '.spec.rules[0].backendRefs[0] | [.namespace, .name, (.port|tostring)] | join("/")')
[[ $backend == authn-admin/heimdall/4456 ]] || { echo "Hubble handoff incomplete: $backend; see docs/hubble-handoff.md" >&2; exit 1; }
for domain in auth.internal zitadel.admin.internal; do
  issuer=$(curl --fail --silent --show-error --max-time 15 --cacert .state/ca.crt \
    "https://$domain/.well-known/openid-configuration" | jq -er .issuer)
  [[ $issuer == "https://$domain" ]] || { echo "Unexpected issuer for $domain" >&2; exit 1; }
done
for app in hubble longhorn openfga garage heimdall; do
  url="https://$app.admin.internal/"
  status=$(curl --silent --show-error --max-time 15 --cacert .state/ca.crt \
    -H 'Accept: text/html' -o /dev/null -w '%{http_code}' "$url")
  [[ $status == 302 || $status == 303 || $status == 307 ]] || { echo "$url: expected sign-in redirect, got $status" >&2; exit 1; }
  status=$(curl --silent --show-error --max-time 15 --cacert .state/ca.crt \
    -H 'Accept: application/json' -H 'X-Authenticated-Subject: forged' \
    -o /dev/null -w '%{http_code}' "$url")
  [[ $status == 401 ]] || { echo "$url: unauthenticated API request returned $status, expected 401" >&2; exit 1; }
  echo "$url rejects anonymous access."
done
echo 'Complete the browser and outage checks in docs/operations.md.'
