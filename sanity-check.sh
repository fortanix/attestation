#!/usr/bin/env bash

set -xe

script_dir=$(dirname "$(realpath "${BASH_SOURCE[0]})")")

# Run builds for all binaries, examples, and run all tests
cargo build --bins --all-features
cargo build --examples
cargo test --all-features

cargo clippy --workspace --all-targets --all-features -- -D warnings \
  || echo "Please correct any changes requested by \"cargo clippy\" to resolve linting issues"

# Run a sanity check on formatting
cargo fmt --check --all --verbose \
  || echo "Please run \"cargo fmt --all\" at repo root to resolve formatting issues"
