#!/usr/bin/env bash
# Focused native tests/lints and no_std feature checks. Run from any directory.
set -euo pipefail
cd "$(dirname "$0")/../.."

for features in '' sha256 ed25519 sha256,ed25519; do
  args=(--no-default-features)
  if [[ -n "$features" ]]; then args+=(--features "$features"); fi
  cargo test --locked -p xila-package-verification "${args[@]}"
  cargo clippy --locked -p xila-package-verification --all-targets "${args[@]}" -- -D warnings
  for target in ${VERIFICATION_TARGETS:-wasm32-unknown-unknown wasm32-wasip1 thumbv7em-none-eabi}; do
    cargo check --locked -p xila-package-verification --target "$target" "${args[@]}"
  done
done
cargo fmt -p xila-package-verification -- --check
RUSTDOCFLAGS='-D warnings' cargo doc --locked -p xila-package-verification --all-features --no-deps
