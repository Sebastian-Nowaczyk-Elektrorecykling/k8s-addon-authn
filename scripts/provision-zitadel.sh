#!/usr/bin/env bash
set -Eeuo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
[[ $# == 2 && $1 == --admin-email ]] || { echo 'Usage: scripts/provision-zitadel.sh --admin-email you@example.com' >&2; exit 1; }
admin_email=$2
umask 077
for tool in kubectl jq curl openssl tofu; do command -v "$tool" >/dev/null; done
mkdir -p .state
chmod 700 .state
task_tmp=$(mktemp -d "$PWD/.state/provision-XXXXXX")
trap 'rm -rf -- "$task_tmp"' EXIT
[[ -f .state/ca.crt ]] || { echo 'Run initialize-secrets.sh --admin-email with the initial administrator email first.' >&2; exit 1; }
existing=$(kubectl -n authn-admin get secret authn-admin-access --ignore-not-found -o name)
[[ -n $existing ]] || { echo 'Missing authn-admin/authn-admin-access. Run initialize-secrets.sh --admin-email with the initial administrator email first.' >&2; exit 1; }
# Pin inputs on the first run so rerunning bootstrap cannot rename the owner.
if [[ -f .state/admin-email ]]; then
  [[ $(cat .state/admin-email) == "$admin_email" ]] || { echo 'Administrator differs from the previous bootstrap; use the console for additional users.' >&2; exit 1; }
else
  printf '%s' "$admin_email" > .state/admin-email
fi
if [[ ! -f .state/bootstrap-admin-password ]]; then
  printf 'Aa1!%s' "$(openssl rand -hex 24)" > .state/bootstrap-admin-password
fi
kubectl -n authn-system get secret authn-provisioner-pat -o json |
  jq -er '.data.pat' | base64 -d > "$task_tmp/provisioner.pat"
kubectl -n authn-system get secret zitadel-domain-provisioner -o json |
  jq -er '.data["tls.key"]' | base64 -d > "$task_tmp/domain.key"
# Keep credentials out of curl arguments and terminal output.
printf 'Authorization: Bearer %s\n' "$(cat "$task_tmp/provisioner.pat")" > "$task_tmp/headers"
curl --fail --silent --show-error --max-time 30 --cacert .state/ca.crt \
  -H @"$task_tmp/headers" https://auth.internal/admin/v1/instances/me > "$task_tmp/instance.json"
instance_id=$(jq -er '.instance.id' "$task_tmp/instance.json")
# SSL_CERT_FILE is honored by the Go TLS stack in the official provider.
export SSL_CERT_FILE="$PWD/.state/ca.crt"
export TF_VAR_provisioner_pat_file="$task_tmp/provisioner.pat"
export TF_VAR_domain_key_file="$task_tmp/domain.key"
export TF_VAR_instance_id="$instance_id"
export TF_VAR_admin_email="$admin_email"
export TF_VAR_admin_password_file="$PWD/.state/bootstrap-admin-password"
kubeconfig_path=${KUBECONFIG:-$HOME/.kube/config}
[[ $kubeconfig_path != *:* ]] || { echo 'Use a single kubeconfig file for the OpenTofu Kubernetes state backend.' >&2; exit 1; }
tofu -chdir=provisioning init -input=false \
  -backend-config="config_path=$kubeconfig_path" \
  -backend-config="config_context=$(kubectl config current-context)"
tofu -chdir=provisioning apply -input=false -auto-approve
tofu -chdir=provisioning output -json oauth2_proxy > "$task_tmp/client.json"
jq -erj '.client_id' "$task_tmp/client.json" > "$task_tmp/client-id"
jq -erj '.client_secret' "$task_tmp/client.json" > "$task_tmp/client-secret"
existing=$(kubectl -n authn-admin get secret oauth2-proxy-credentials --ignore-not-found -o json)
if [[ -n $existing ]]; then
  jq -er '.data["cookie-secret"]' <<< "$existing" | base64 -d > "$task_tmp/cookie-secret"
else
  openssl rand -base64 32 | tr -d '\n' > "$task_tmp/cookie-secret"
fi
kubectl -n authn-admin create secret generic oauth2-proxy-credentials \
  --from-file=client-id="$task_tmp/client-id" --from-file=client-secret="$task_tmp/client-secret" \
  --from-file=cookie-secret="$task_tmp/cookie-secret" --dry-run=client -o yaml |
  kubectl apply --server-side --field-manager=authn-bootstrap -f -
deployment=$(kubectl -n authn-admin get deployment oauth2-proxy --ignore-not-found -o name)
if [[ -n $deployment ]]; then kubectl -n authn-admin rollout restart "$deployment"; fi
echo 'ZITADEL domain, initial administrator and OAuth application provisioned.'
