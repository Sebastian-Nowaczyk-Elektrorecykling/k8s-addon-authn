#!/usr/bin/env bash
# Linux amd64 developer/CI tooling. Installs only into this checkout's .cache.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
mkdir -p .cache/bin .cache/downloads
download() { curl --fail --silent --show-error --location --retry 3 "$1" -o ".cache/downloads/$2"; }
download https://get.helm.sh/helm-v3.19.0-linux-amd64.tar.gz helm.tgz
tar --no-same-owner -xzf .cache/downloads/helm.tgz -C .cache/bin --strip-components=1 linux-amd64/helm
download https://github.com/kubernetes-sigs/kustomize/releases/download/kustomize%2Fv5.7.1/kustomize_v5.7.1_linux_amd64.tar.gz kustomize.tgz
tar --no-same-owner -xzf .cache/downloads/kustomize.tgz -C .cache/bin kustomize
download https://github.com/yannh/kubeconform/releases/download/v0.7.0/kubeconform-linux-amd64.tar.gz kubeconform.tgz
tar --no-same-owner -xzf .cache/downloads/kubeconform.tgz -C .cache/bin kubeconform
download https://github.com/openfga/openfga/releases/download/v1.21.0/openfga_1.21.0_linux_amd64.tar.gz openfga.tgz
tar --no-same-owner -xzf .cache/downloads/openfga.tgz -C .cache/bin openfga
download https://github.com/oauth2-proxy/oauth2-proxy/releases/download/v7.15.4/oauth2-proxy-v7.15.4.linux-amd64.tar.gz oauth2.tgz
tar --no-same-owner -xzf .cache/downloads/oauth2.tgz -C .cache/bin --strip-components=1
echo "Add this checkout's .cache/bin to PATH before validation."
