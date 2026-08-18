#!/bin/sh
set -eu

chart_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
tmp_dir=$(mktemp -d)
trap 'rm -rf "$tmp_dir"' EXIT

helm template test "$chart_dir" >"$tmp_dir/default.yaml"
helm template test "$chart_dir" -f "$chart_dir/ci/host-whitelist-values.yaml" >"$tmp_dir/enabled.yaml"

count() { grep -cF -- "$1" "$2" || true; }
assert_count() {
  [ "$(count "$1" "$2")" -eq "$3" ] || {
    echo "expected $3 occurrences of $1 in $2" >&2
    exit 1
  }
}

assert_count 'name: host-whitelist' "$tmp_dir/default.yaml" 0
assert_count '/etc/cloudflare-exporter/hosts.yaml' "$tmp_dir/default.yaml" 0
assert_count 'configMap:' "$tmp_dir/default.yaml" 0
assert_count 'name: host-whitelist' "$tmp_dir/enabled.yaml" 2
assert_count 'volumes:' "$tmp_dir/enabled.yaml" 1
assert_count 'volumeMounts:' "$tmp_dir/enabled.yaml" 1
assert_count 'mountPath: /etc/cloudflare-exporter' "$tmp_dir/enabled.yaml" 1
assert_count 'readOnly: true' "$tmp_dir/enabled.yaml" 1
assert_count 'configMap:' "$tmp_dir/enabled.yaml" 1
assert_count 'name: cloudflare-exporter-hosts' "$tmp_dir/enabled.yaml" 1
assert_count 'key: hosts.yaml' "$tmp_dir/enabled.yaml" 1
assert_count 'path: hosts.yaml' "$tmp_dir/enabled.yaml" 1
assert_count 'mode: 0444' "$tmp_dir/enabled.yaml" 1
assert_count 'kind: ConfigMap' "$tmp_dir/enabled.yaml" 0
