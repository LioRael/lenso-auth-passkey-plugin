#!/usr/bin/env bash
set -euo pipefail

cargo_bin="${LENSO_CARGO_BIN:-cargo}"
repository_root="$(git rev-parse --show-toplevel)"
package_flags=(--locked)

if [[ "${LENSO_PACKAGE_ALLOW_DIRTY:-0}" == "1" ]]; then
  package_flags+=(--allow-dirty)
fi

"$cargo_bin" package --quiet "${package_flags[@]}" \
  -p lenso-capability-passkey-auth

metadata="$($cargo_bin metadata --no-deps --format-version=1)"
target_directory="$(python3 -c \
  'import json, sys; print(json.load(sys.stdin)["target_directory"])' \
  <<<"$metadata")"
capability_version="$(python3 -c \
  'import json, sys; name = sys.argv[1]; print(next(package["version"] for package in json.load(sys.stdin)["packages"] if package["name"] == name))' \
  lenso-capability-passkey-auth <<<"$metadata")"
plugin_version="$(python3 -c \
  'import json, sys; name = sys.argv[1]; print(next(package["version"] for package in json.load(sys.stdin)["packages"] if package["name"] == name))' \
  lenso-auth-passkey-plugin <<<"$metadata")"

capability_source="$repository_root/crates/lenso-capability-passkey-auth"
source_patch="patch.crates-io.lenso-capability-passkey-auth.path=\"$capability_source\""

# Cargo must resolve the unpublished Capability while it creates the Plugin
# archive. --no-verify is limited to this archive-creation step; the normalized
# archive is compiled, tested, and linted below.
"$cargo_bin" --config "$source_patch" package --quiet \
  "${package_flags[@]}" --no-verify -p lenso-auth-passkey-plugin

capability_archive="$target_directory/package/lenso-capability-passkey-auth-$capability_version.crate"
plugin_archive="$target_directory/package/lenso-auth-passkey-plugin-$plugin_version.crate"
verification_root="$(mktemp -d "${TMPDIR:-/tmp}/lenso-passkey-packages.XXXXXX")"

cleanup() {
  rm -r "$verification_root"
}
trap cleanup EXIT

tar -xzf "$capability_archive" -C "$verification_root"
tar -xzf "$plugin_archive" -C "$verification_root"

capability_package="$verification_root/lenso-capability-passkey-auth-$capability_version"
plugin_package="$verification_root/lenso-auth-passkey-plugin-$plugin_version"

[[ -f "$capability_package/Cargo.toml" ]]
[[ -f "$plugin_package/Cargo.toml" ]]

package_patch="patch.crates-io.lenso-capability-passkey-auth.path=\"$capability_package\""
plugin_manifest="$plugin_package/Cargo.toml"

# Regenerate the archive-local lockfile against the normalized Capability
# manifest. This reproduces the dependency graph crates.io consumers receive,
# rather than mixing the workspace's Git dependencies with registry packages.
"$cargo_bin" --config "$package_patch" generate-lockfile \
  --manifest-path "$plugin_manifest"
"$cargo_bin" --config "$package_patch" check --quiet --locked --all-targets \
  --manifest-path "$plugin_manifest"
"$cargo_bin" --config "$package_patch" test --quiet --locked \
  --manifest-path "$plugin_manifest"
"$cargo_bin" clippy --config "$package_patch" --quiet --locked --all-targets \
  --manifest-path "$plugin_manifest" -- -D warnings
