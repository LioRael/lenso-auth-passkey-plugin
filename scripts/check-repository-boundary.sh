#!/usr/bin/env bash
set -euo pipefail

forbidden='lenso-platform-|lenso-module-auth|HostBuilder|HostLinkedModule|ModuleManifest|lenso module install|platform_core|platform_module'

if rg -n "$forbidden" Cargo.toml crates README.md docs --glob '!**/generated.rs'; then
  echo "legacy Lenso framework dependency or API found in passkey source" >&2
  exit 1
fi

if rg -n 'CREATE TABLE (users|sessions|organizations|roles|permissions)' crates/lenso-auth-passkey-plugin/migrations; then
  echo "passkey Plugin crossed an external identity, session, Organization, or RBAC boundary" >&2
  exit 1
fi

if rg -n 'allow_subdomains\(true\)|allow_any_port\(true\)' crates/lenso-auth-passkey-plugin/src; then
  echo "passkey RP policy widened origins or ports" >&2
  exit 1
fi

printf 'repository boundary is passkey-only and vNext-only\n'
