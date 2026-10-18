#!/usr/bin/env bash
set -Eeuo pipefail
# Dalfox v3.2.4: pinned, fixed SHA256 from official GitHub release v3.2.4.
# https://github.com/hahwul/dalfox/releases/tag/v3.2.4
version='v3.2.4'
sha256='c11cfd2f8261973f0a2a2a1eba5a147ce77712a29acfa6343f9847fb8bb7eca2'
asset="dalfox-${version}-linux-x86_64-musl.tar.gz"
url="https://github.com/hahwul/dalfox/releases/download/${version}/${asset}"
dir="${RUNNER_TEMP:-/tmp}/devsecops-dalfox"
mkdir -p "$dir/bin" "$dir/extract"
curl --fail --location --retry 3 --retry-delay 2 --connect-timeout 20 --max-time 180 --silent --show-error \
  "$url" --output "$dir/$asset"
echo "${sha256}  $dir/$asset" | sha256sum --check --status || {
  echo 'FEHLER: Dalfox SHA256 stimmt nicht überein.' >&2; exit 2;
}
tar -xzf "$dir/$asset" -C "$dir/extract"
binary="$(find "$dir/extract" -type f -name dalfox -print -quit)"
if [[ -z "$binary" ]]; then echo 'FEHLER: Dalfox-Binary fehlt im Archiv.' >&2; exit 2; fi
install -m 0755 "$binary" "$dir/bin/dalfox"
"$dir/bin/dalfox" --version
if [[ -n "${GITHUB_PATH:-}" ]]; then echo "$dir/bin" >> "$GITHUB_PATH"; fi
if [[ -n "${GITHUB_ENV:-}" ]]; then echo "DALFOX_BIN=$dir/bin/dalfox" >> "$GITHUB_ENV"; fi
