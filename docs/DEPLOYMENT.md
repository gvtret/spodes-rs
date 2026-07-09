# spodes-rs Deployment Guide

## Overview

`spodes-rs` is a Rust crate providing a full DLMS/COSEM stack. This guide describes how to integrate the library into your project and configure it for electricity metering devices.

## Requirements

- **Rust:** >= 1.85 (edition 2021)
- **OS:** Linux, macOS, Windows (any)
- **Network:** TCP/UDP ports 4059/4065 (standard DLMS ports) or serial port for HDLC

## Quick Start

### Adding the dependency

```toml
# Cargo.toml
[dependencies]
spodes-rs = { git = "https://github.com/gvtret/spodes-rs", branch = "main" }
# or path dependency for local development:
# spodes-rs = { path = "../spodes-rs" }
```

### Minimal example (client)

```rust
use spodes_rs::obis::ObisCode;
use spodes_rs::session::ClientSession;
use spodes_rs::transport::wrapper::Wrapper;
use spodes_rs::transport::{NetworkTransport, PhysicalTransport};
use std::net::TcpStream;
use std::io;

struct TcpTransport(TcpStream);

impl NetworkTransport for TcpTransport {}

impl PhysicalTransport for TcpTransport {
    fn send(&mut self, data: &[u8]) -> io::Result<()> {
        use std::io::Write;
        self.0.write_all(data)
    }
    fn receive(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        use std::io::Read;
        self.0.read(buf)
    }
}

fn main() -> io::Result<()> {
    let stream = TcpStream::connect("192.168.1.100:4059")?;
    let transport = TcpTransport(stream);
    let link = Wrapper::new(transport, 1000, 4059);
    let mut session = ClientSession::new(link);

    // Read serial number (OBIS 0.0.96.1.0.255, attribute 2)
    let serial = ObisCode::new(0, 0, 96, 1, 0, 0xFF);
    match session.get(1, serial, 2) {
        Ok(response) => println!("Response: {response:?}"),
        Err(e) => eprintln!("Error: {e}"),
    }
    Ok(())
}
```

## Transport Configuration

### TCP (IEC 62056-47 wrapper)

Standard transport for DLMS/COSEM over TCP. Uses the wrapper sub-layer with an 8-byte header.

```text
Port: 4059 (standard DLMS TCP port)
Wrapper header:
  version (2) + source_wPort (2) + dest_wPort (2) + length (2)
```

### HDLC (IEC 62056-46)

HDLC framing for serial lines or TCP. Works over any `PhysicalTransport`.

```text
Addresses: client (1), server (1)
Checksum: CRC-16 CCITT
Frame format: flag + address + control + information + fcs + flag
```

### UDP (IEC 62056-47 wrapper)

For connectionless transmission. Uses the same wrapper header as TCP.

```text
Port: 4065 (standard DLMS UDP port)
Limitation: one request -> one response per datagram
```

## Security Configuration

### Security Suite 0 (AES-GCM-128)

Basic suite without PKI. AES-128-GCM encryption, GMAC authentication.

```rust
use spodes_rs::security::{SecuritySuite, SecurityPolicy, AuthMechanism};

let suite = SecuritySuite::Suite0;
let policy = SecurityPolicy::AuthenticatedEncryption;
let mechanism = AuthMechanism::HlsGmac; // mechanism 5
```

### Security Suite 1 (ECDH-ECDSA-P256)

With PKI. ECDH key agreement on curve P-256, ECDSA signatures.

```rust
let suite = SecuritySuite::Suite1;
let policy = SecurityPolicy::AuthenticatedEncryption;
let mechanism = AuthMechanism::HlsEcdsa; // mechanism 7
```

### GOST Suite (R 1323565.1)

Russian profile. Kuznyechik-CMAC (mechanism 8) or GOST 34.10 (mechanism 10).

```rust
let suite = SecuritySuite::Gost; // suite 9
let policy = SecurityPolicy::AuthenticatedEncryption;
let mechanism = AuthMechanism::HlsGostCmac; // mechanism 8
```

## Server Setup

### RequestDispatcher

Request dispatcher — server side handling GET/SET/ACTION requests.

```rust
use spodes_rs::classes::data::Data;
use spodes_rs::obis::ObisCode;
use spodes_rs::server::RequestDispatcher;
use spodes_rs::types::CosemDataType;

let mut server = RequestDispatcher::new();

// Register objects
let obis = ObisCode::new(1, 0, 1, 8, 0, 0xFF); // active energy
server.add(Box::new(Data::new(obis, CosemDataType::DoubleLongUnsigned(123_456))));

// Handle request
let response = server.dispatch(&request_bytes)?;
```

### Association LN

Association setup for access control.

```rust
use spodes_rs::classes::association_ln::{
    AssociationLn, AssociationLnConfig, AuthenticationMechanism
};

let assoc = AssociationLn::new(AssociationLnConfig {
    logical_name: ObisCode::new(0, 0, 40, 0, 0, 255),
    version: AssociationLnVersion::Version1,
    authentication_mechanism: AuthenticationMechanism::HlsSha256,
    // ...
});
```

## SPODUS/IVEK Integration

For IVEK concentrator operation, use the `spodus` module:

```rust
use spodes_rs::spodus::node::Concentrator;
use spodes_rs::spodus::catalog;

// Create IVEK object catalog
let clock = catalog::clock();
let sap = catalog::sap_assignment(sap_list);
let sec = catalog::security_setup(obis, 0, client_st, server_st);
```

## Testing

```bash
# All tests
cargo test

# Unit tests only
cargo test --lib

# Integration tests
cargo test --test spodus_integration

# Doc tests
cargo test --doc

# Clippy
cargo clippy --all-targets -- -D warnings

# Format check
cargo fmt --check

# Generate documentation
cargo doc --no-deps
```

## Monitoring

### Logging

The library does not use logging frameworks. For debugging, it is recommended to:

1. Enable `RUST_LOG=debug` for trace output
2. Use `env_logger` or `tracing` in your application

### Metrics

For performance monitoring:

- Number of processed requests (GET/SET/ACTION)
- Request response time
- Number of authentication errors
- Association state

## Security

### Recommendations

1. **Use Security Suite 1 or 2** for production environments
2. **Enable authentication** (mechanism 5..10) for all connections
3. **Regularly rotate keys** for encryption and authentication
4. **Monitor invocation counter** — it must increase monotonically
5. **Use GOST profile** for R 1323565.1 compliance

### Known Limitations

- The library does not implement physical transport (you need your own `PhysicalTransport`)
- SN associations (class 12) are not implemented (LN only)
- Some legacy classes (Register table, Compact data) are missing

## Examples

See the `examples/` directory:

- `client_session` — client via in-memory transport
- `server_dispatch` — server with request dispatcher
- `tcp_client` / `tcp_server` — TCP examples
- `udp_client` — UDP example
- `hls_handshake` — HLS handshake
- `spodus_concentrator` — IVEK concentrator
- `data_usage` / `register_usage` / `clock_usage` — class examples
