# Attestation tool

Building:

```
cargo build --release --example tdreport_tool --features tdx-guest
```
The resulting binary will be available at `attestation/target/release/examples`.

Running:

1. Copy the binary to the TDX guest VM.

For example:
```
scp target/release/examples/tdreport_tool <username>@<vm-ip>:
```

2. Log in to the VM

3. Run the tool.

```
chmod +x tdreport_tool
./tdreport_tool
```

After running the tool, a `tdreport.bin` file is generated. This `tdreport.bin` then can be placed under `data/` directory, and used by the test case.