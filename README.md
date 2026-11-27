# Fortanix Attestation

## NVIDIA evidence with musl

Enable the `nvml-ext` Cargo feature on `attestation` or `client` to collect NVIDIA GPU
evidence in a separate process. For example, to build the TDX attestation client
for musl, run:

```bash
cargo build -p client --example attestation-client-tdx --features nvml-ext --target x86_64-unknown-linux-musl
```

The attestation library builds and embeds `nvml-ext` for
`x86_64-unknown-linux-gnu`. On the first NVIDIA evidence request in each
process, the library saves it as `nvml-ext-*` in the current working directory
and reuses that executable for later requests. The working directory must be
writable and allow execution. The embedded helper needs the x86-64 GNU dynamic
loader and the NVIDIA driver's NVML shared library at runtime.

To build the helper by itself, run the following from the workspace root.

```bash
cargo build -p nvml-ext --target x86_64-unknown-linux-gnu
```

The helper accepts the raw 32-byte attestation nonce on standard input and
writes a JSON array of GPU evidence to standard output. To try a standalone
build from its output directory, pipe in a nonce.

```bash
head -c 32 /dev/urandom | ./nvml-ext
```

## Clippy

Please run

```bash
cargo clippy --workspace --all-targets --all-features -- -D warnings
```

at the repository [root](.) prior to creating a PR, so that
all lint checks are complete.

## Formatting

Please run

```bash
cargo fmt --all
```

at the repository [root](.) prior to creating a PR, so that
all code formatting is consistent.

## Sanity Check

Please run [sanity-check.sh](./sanity-check.sh) prior to making
any pull requests, to make sure that all features and tests compile
and run correctly.

# Contributing

We gratefully accept bug reports and contributions from the community.
By participating in this community, you agree to abide by [Code of Conduct](./CODE_OF_CONDUCT.md).
All contributions are covered under the Developer's Certificate of Origin (DCO).

## Developer's Certificate of Origin 1.1

By making a contribution to this project, I certify that:

(a) The contribution was created in whole or in part by me and I
have the right to submit it under the open source license
indicated in the file; or

(b) The contribution is based upon previous work that, to the best
of my knowledge, is covered under an appropriate open source
license and I have the right under that license to submit that
work with modifications, whether created in whole or in part
by me, under the same open source license (unless I am
permitted to submit under a different license), as indicated
in the file; or

(c) The contribution was provided directly to me by some other
person who certified (a), (b) or (c) and I have not modified
it.

(d) I understand and agree that this project and the contribution
are public and that a record of the contribution (including all
personal information I submit with it, including my sign-off) is
maintained indefinitely and may be redistributed consistent with
this project or the open source license(s) involved.

# License

This project is primarily distributed under the terms of the Mozilla Public License (MPL) 2.0, see [LICENSE](./LICENSE) for details.
