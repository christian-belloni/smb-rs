# Pure Rust SMB Client
This project is the first full-rust implementation of a SMB client, currently supporting SMB 3.1.1.
## Getting started
Running the project is as simple as:
```sh
cargo run --features async -- --help
```
Check out the `info` and the `copy` sub-commands for more information.

For advanced usage, see the [Advanced Usage](#advanced-usage) section.
## Features
### General
- ✅ SMB 3.1.1 dialect support.
- ✅ Async/Multi-threaded/Single-threaded backends.
- ✅ File & Directory read/write/information operations. 
- ✅ Compression & Encryption support.
- ✅ Windows, Linux & MacOS support.
- ✅ CLI tool for basic operations.

You are welcome to see the project's roadmap in the [GitHub Project](https://github.com/users/AvivNaaman/projects/2).

### Algorithm Support matrix
| Type            | Algorithm    | Supported | Feature Name          |
| --------------- | ------------ | --------- | --------------------- |
| **Signing**     | All          | -         | `sign`                |
| Signing         | HMAC_SHA256  | ✅         | `sign_hmac`           |
| Signing         | AES-128-GCM  | ✅         | `sign_gmac`           |
| Signing         | AES-128-CCM  | ✅         | `sign_cmac`           |
| **Encryption**  | All          | -         | `encrypt`             |
| Encryption      | AES-128-CCM  | ✅         | `encrypt_aes128ccm`   |
| Encryption      | AES-128-GCM  | ✅         | `encrypt_aes128gcm`   |
| Encryption      | AES-256-CCM  | ✅         | `encrypt_aes256ccm`   |
| Encryption      | AES-256-GCM  | ✅         | `encrypt_aes256gcm`   |
| **Compression** | All          | -         | `compress`            |
| Compression     | LZ4          | ✅         | `compress_lz4`        |
| Compression     | Pattern_V1   | ✅         | `compress_pattern_v1` |
| Compression     | LZNT1        | ❌         |                       |
| Compression     | LZ77         | ❌         |                       |
| Compression     | LZ77+Huffman | ❌         |                       |


## Advanced Usage
To build the project, run the following command:
```sh
cargo build --features async
```
The project supports async, multi-threaded, and single-threaded backends. The `async` backend is the recommended one, but you can enable the other backends by using the following features:
- `async`: Enables the async backend.
- `single_threaded`: Enables the single-threaded backend.
- `multi_threaded`: Enables the multi-threaded backend.