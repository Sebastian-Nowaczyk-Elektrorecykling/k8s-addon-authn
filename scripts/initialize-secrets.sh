#!/usr/bin/env bash
set -Eeuo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
umask 077
for tool in kubectl jq openssl; do command -v "$tool" >/dev/null; done
mkdir -p .state
chmod 700 .state
task_tmp=$(mktemp -d .state/secrets-XXXXXX)
trap 'rm -rf -- "$task_tmp"' EXIT
kubectl apply -k infrastructure/namespaces
# RBAC/network errors are errors; only an actual NotFound permits creation.
existing=$(kubectl -n authn-system get secret zitadel-masterkey --ignore-not-found -o name)
if [[ -z $existing ]]; then
  database=$(kubectl -n authn-system get cluster.postgresql.cnpg.io zitadel-db --ignore-not-found -o name)
  [[ -z $database ]] || { echo 'Database already exists but masterkey is missing. Restore the original Secret; do not generate a new key.' >&2; exit 1; }
  openssl rand -hex 16 | tr -d '\n' > "$task_tmp/masterkey"
  kubectl -n authn-system create secret generic zitadel-masterkey --from-file=masterkey="$task_tmp/masterkey"
fi
existing=$(kubectl -n authn-system get secret zitadel-domain-provisioner --ignore-not-found -o name)
if [[ -z $existing ]]; then
  openssl req -x509 -newkey rsa:3072 -sha256 -nodes -days 365 \
    -subj /CN=authn-domain-provisioner \
    -keyout "$task_tmp/tls.key" -out "$task_tmp/tls.crt" 2>/dev/null
  kubectl -n authn-system create secret tls zitadel-domain-provisioner \
    --key="$task_tmp/tls.key" --cert="$task_tmp/tls.crt"
fi
existing=$(kubectl -n authn-admin get secret openfga-api-credentials --ignore-not-found -o name)
if [[ -z $existing ]]; then
  openssl rand -hex 32 | tr -d '\n' > "$task_tmp/keys"
  kubectl -n authn-admin create secret generic openfga-api-credentials --from-file=keys="$task_tmp/keys"
fi
# Copy only the CA certificate. Never copy the CA signing key.
kubectl -n cert-manager get secret internal-ca -o json |
  jq -er '.data["tls.crt"]' | base64 -d > "$task_tmp/ca.crt"
openssl x509 -in "$task_tmp/ca.crt" -checkend 0 -noout >/dev/null
kubectl -n authn-admin create configmap authn-internal-ca \
  --from-file=ca.crt="$task_tmp/ca.crt" --dry-run=client -o yaml |
  kubectl apply --server-side --field-manager=authn-bootstrap -f -
cp "$task_tmp/ca.crt" .state/ca.crt
echo 'Required Secrets exist; existing keys were preserved.'
