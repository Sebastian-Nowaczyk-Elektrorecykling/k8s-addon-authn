#!/usr/bin/env bash
set -Eeuo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
[[ -s .state/ca.crt ]] || { echo 'Run initialize-secrets.sh to copy the public CA certificate.' >&2; exit 1; }
kubectl -n flux-system wait kustomizations -l app.kubernetes.io/part-of=authn-addons \
  --for=condition=Ready --timeout=60s
if ! kubectl -n authn-admin get httproute authenticated-administration -o json |
  jq -e '
    . as $route |
    (.spec.hostnames | index("hubble.admin.internal") != null) and
    (.spec.rules | length > 0) and
    all(.spec.rules[];
      (.backendRefs | length > 0) and
      all(.backendRefs[];
        .name == "heimdall" and .port == 4456 and
        (.namespace // $route.metadata.namespace) == "authn-admin")) and
    any(.status.parents[]?;
      .controllerName == "io.cilium/gateway-controller" and
      .parentRef.name == "internal" and
      .parentRef.namespace == "gateway-system" and
      .parentRef.sectionName == "admin-https" and
      any(.conditions[]?; .type == "Accepted" and .status == "True" and
          .observedGeneration == $route.metadata.generation) and
      any(.conditions[]?; .type == "ResolvedRefs" and .status == "True" and
          .observedGeneration == $route.metadata.generation))
  ' >/dev/null; then
  echo 'The administration route must serve Hubble through Heimdall and have current Accepted/ResolvedRefs conditions on admin-https.' >&2
  exit 1
fi
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
