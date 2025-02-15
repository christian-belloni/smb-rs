# Pure Rust SMB Client
This is the first version of a pure Rust SMB client. Currently, the client provides basic functionalities (authentication, file transfer, info query/set) for SMB3.1.1 dialect only.

## Roadmap
- [x] Async support (top priority).
- [ ] Older SMB dialects.
- [ ] Additional compression/encryption/signing algorithms.
- [ ] Performance tuning.
- [ ] More CLI options.
- [ ] System tests.

## CLI Usage
The smb-cli crate implements a simple CLI for the SMB client.
- It supports copying a file from a remote SMB server to a local machine.
    ```sh
    cargo run --features async -- -u LocalAdmin -p 123456 copy "\\\\172.16.204.149\MyShare\ntoskrnl.exe" ./test.exe
    ```
- And querying information about a file or a directory:
    ```sh
    cargo run --features async -- -u LocalAdmin -p 123456 info "\\\\172.16.204.149\MyShare\ntoskrnl.exe"  # file
    cargo run --features async -- -u LocalAdmin -p 123456 info "\\\\172.16.204.149\MyShare"  # directory
    ```
- View additional options:
    ```sh
    cargo run -- --help
    ```
- Note: The `sync` feature is also available for the CLI, but no major advantages are used in the current version.