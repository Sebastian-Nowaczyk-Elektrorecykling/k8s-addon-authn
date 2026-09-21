#!/usr/bin/env bash
set -Eeuo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
if [[ ${1:-} == --help ]]; then
  echo 'Usage: scripts/bootstrap.sh --admin-email you@example.com'
  echo 'Requires kubectl, jq, openssl, curl and OpenTofu; uses the current kubeconfig.'
  exit 0
fi
[[ $# == 2 && $1 == --admin-email ]] || { echo 'Use --help.' >&2; exit 1; }
admin_email=$2
for tool in kubectl jq openssl curl tofu; do command -v "$tool" >/dev/null; done
echo "Installing authn add-ons into context: $(kubectl config current-context)"
kubectl -n flux-system wait kustomization/gateway kustomization/cilium \
  kustomization/storage-cnpg kustomization/storage-classes --for=condition=Ready --timeout=5m
bash scripts/initialize-secrets.sh
kubectl apply -k bootstrap
kubectl -n flux-system wait gitrepository/authn-addons --for=condition=Ready --timeout=5m
kubectl -n flux-system wait kustomization/authn-addons --for=condition=Ready --timeout=5m
kubectl -n flux-system wait kustomization/authn-zitadel kustomization/authn-openfga \
  kustomization/authn-identity-routes --for=condition=Ready --timeout=30m
bash scripts/provision-zitadel.sh --admin-email "$admin_email"
kubectl -n flux-system annotate kustomization/authn-oauth2-proxy \
  reconcile.fluxcd.io/requestedAt="$(date -u +%s)" --overwrite >/dev/null
kubectl -n flux-system wait kustomizations -l app.kubernetes.io/part-of=authn-addons \
  --for=condition=Ready --timeout=30m
echo 'Authn add-ons reconciled. Verify the SSO routes with bash scripts/check.sh.'
echo 'Initial administrator password: .state/bootstrap-admin-password (change it at first login).'
