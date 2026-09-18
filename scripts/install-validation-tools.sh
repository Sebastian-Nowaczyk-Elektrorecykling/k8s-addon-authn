#!/usr/bin/env bash
# Pinned Linux/amd64 tools for CI or local validation. No cluster access.
set -Eeuo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."
mkdir -p .cache/bin
cd .cache/bin
download() {
  local url=$1 file=$2 checksum=$3
  curl -fsSL --retry 3 --max-time 60 "$url" -o "$file"
  printf '%s  %s\n' "$checksum" "$file" | sha256sum -c -
}
download https://get.helm.sh/helm-v3.19.0-linux-amd64.tar.gz helm.tgz \
  a7f81ce08007091b86d8bd696eb4d86b8d0f2e1b9f6c714be62f82f96a594496
tar --no-same-owner -xzf helm.tgz --strip-components=1 linux-amd64/helm
download https://github.com/kubernetes-sigs/kustomize/releases/download/kustomize%2Fv5.7.1/kustomize_v5.7.1_linux_amd64.tar.gz kustomize.tgz \
  ea375e7372f9aa029129d4b2d16c66b7750b7f1213c4f66f910d981c895818d8
tar --no-same-owner -xzf kustomize.tgz kustomize
download https://github.com/yannh/kubeconform/releases/download/v0.7.0/kubeconform-linux-amd64.tar.gz kubeconform.tgz \
  c31518ddd122663b3f3aa874cfe8178cb0988de944f29c74a0b9260920d115d3
tar --no-same-owner -xzf kubeconform.tgz kubeconform
download https://github.com/dadrus/heimdall/releases/download/v0.17.22/heimdall_v0.17.22_linux_amd64.tar.gz heimdall.tgz \
  666940f2336cb3878829a43a7f66d570441ba6d3c6e6e5ba5aadf833b4f0b63a
tar --no-same-owner -xzf heimdall.tgz heimdall
download https://github.com/opentofu/opentofu/releases/download/v1.12.6/tofu_1.12.6_linux_amd64.zip tofu.zip \
  5dc43da4f750f33873dc25e94587128709e819e544b7be9016b255316153c3a8
unzip -o -q tofu.zip tofu
chmod 755 helm kustomize kubeconform heimdall tofu
if [[ -n ${GITHUB_PATH:-} ]]; then printf '%s\n' "$PWD" >> "$GITHUB_PATH"; fi
