# smb-rs: The SMB2 Client in Rust

[![Build](https://github.com/AvivNaaman/smb-rs/actions/workflows/build.yml/badge.svg)](https://github.com/AvivNaaman/smb-rs/actions/workflows/build.yml)
[![Crates.io](https://img.shields.io/crates/v/smb)](https://crates.io/crates/smb)
[![Docs.rs](https://docs.rs/smb/badge.svg)](https://docs.rs/smb)

This project is the first rust implementation of [SMB2 & 3](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/5606ad47-5ee0-437a-817e-70c366052962) client -- the protocol that powers Windows file sharing and remote services. The project is designed to be a library, but also includes a CLI tool for basic operations.

While most current implementations are mostly bindings to C libraries (such as libsmb2, samba, or windows' own libraries), this project is a full implementation in Rust, with no dependencies on C libraries!

## Getting started
Running the project is as simple as:
```sh
cargo run -- --help
```
Check out the `info` and the `copy` sub-commands for more information.

For advanced usage, and crate usage, see the [Advanced Usage](#advanced-usage) section.
## Features
### General
- ✅ Full SMB 2.X & 3.X support.
- ✅ Async + Multi-threaded + Single-threaded backends.
- ✅ Compression + Encryption support.
- ✅ SMB over QUIC support.
- ✅ Cross-platform (Windows, Linux, MacOS).

You are welcome to see the project's roadmap in the [GitHub Project](https://github.com/users/AvivNaaman/projects/2).

### Algorithm Support
| Type            | Algorithm    |     | Feature Name           |
| --------------- | ------------ | --- | ---------------------- |
| **Signing**     | *            |     | `sign`                 |
| Signing         | HMAC_SHA256  | ✅   | `sign_hmac`            |
| Signing         | AES-128-GCM  | ✅   | `sign_gmac`            |
| Signing         | AES-128-CCM  | ✅   | `sign_cmac`            |
| **Encryption**  | *            |     | `encrypt`              |
| Encryption      | AES-128-CCM  | ✅   | `encrypt_aes128ccm`    |
| Encryption      | AES-128-GCM  | ✅   | `encrypt_aes128gcm`    |
| Encryption      | AES-256-CCM  | ✅   | `encrypt_aes256ccm`    |
| Encryption      | AES-256-GCM  | ✅   | `encrypt_aes256gcm`    |
| **Compression** | *            |     | `compress`             |
| Compression     | LZ4          | ✅   | `compress_lz4`         |
| Compression     | Pattern_V1   | 🟡   | `compress_pattern_v1`* |
| Compression     | LZNT1        | ❌   |                        |
| Compression     | LZ77         | ❌   |                        |
| Compression     | LZ77+Huffman | ❌   |                        |

> [!NOTE] 
> Some of SMB's suported compression algorithms are missing, since no proper crates are available for them.

## Advanced Usage
### Using the library
Check out the `Connection` struct, exported from the `smb` crate, to initiate a connection to an SMB server:
```rust
use smb::Connection;
let connection = Connection::build(Default::default());
connection.connect("10.0.0.1:445").await?;
let session = connection.authenticate(&"user", "password".to_string()).await?;
let tree = session.tree_connect("share").await?;
let file = tree.create("file.txt", ...).await?;
```

### Switch Threading model
The project supports async, multi-threaded, and single-threaded backends. The `async` backend is the default one, but you can enable the other backends by using the following features:
- `async`: Enables the async backend (default)
- `single_threaded`: Enables the single-threaded backend. *Must disable default features.*
- `multi_threaded`: Enables the multi-threaded backend. *Must disable default features.*

For example, to enable the multi-threaded backend, you can run:
```sh
cargo run --no-default-feature --features "multi_threaded,sign,encrypt,compress" -- --help
```
If you're using the crate, you can enable the features in your `Cargo.toml` file:
```toml
[dependencies]
smb = { version = "0.1", features = ["multi_threaded", "sign", ...], no-default-features = true }
```