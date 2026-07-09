# spodes-rs Architecture

## Overview

`spodes-rs` is a full DLMS/COSEM stack implementation in Rust for electricity metering systems. The stack complies with international IEC 62056 standards and Russian profiles SPODES (STO 34.01-5.1-006-2023), SPODUS (STO 34.01-5.1-013-2023), and GOST (R 1323565.1).

## Layered Architecture

```text
┌─────────────────────────────────────────────────────────────────┐
│  session (client)      server (dispatcher)      spodus          │  drivers / profiles
├─────────────────────────────────────────────────────────────────┤
│  service    GET/SET/ACTION, ACSE, notifications, ciphering      │  application layer
│  security   suites, policy, HLS mechanisms, ECDH/GOST           │
├─────────────────────────────────────────────────────────────────┤
│  transport  HDLC (62056-46) and wrapper (62056-47)              │  transport layer
├─────────────────────────────────────────────────────────────────┤
│  classes / interface  -  COSEM interface objects                │  object model
│  types (A-XDR/BER)  -  obis                                     │
└─────────────────────────────────────────────────────────────────┘
```

## Layers and Modules

### 1. Object Model

**Modules:** `types`, `obis`, `interface`, `classes`

Responsible for COSEM data representation and serialization.

- **`types`** — COSEM data types (`CosemDataType`) and their A-XDR (BER) serialization. Supported types: null, bool, integer, unsigned, octet-string, visible-string, date, time, array, structure, etc.

- **`obis`** — OBIS object identification codes. Format `A.B.C.D.E.F` identifies each object in a device.

- **`interface`** — `InterfaceClass` trait shared by all COSEM interface classes. Defines methods: `class_id()`, `version()`, `logical_name()`, `attributes()`, `methods()`.

- **`classes`** — 30 implemented interface classes:
  - **Data:** Data (1), Register (3), Extended register (4), Demand register (5), Register activation (6)
  - **Profiles:** Profile generic (7), Clock (8), Script table (9), Schedule (10), Special days table (11)
  - **Access control:** Association LN (15), SAP assignment (17), Security setup (64)
  - **Interfaces:** IEC HDLC Setup (23), IEC Local Port Setup (19), TCP-UDP setup (41), IPv4 (42), IPv6 (48), Push setup (40)
  - **Control:** Activity calendar (20), Register monitor (21), Single action schedule (22), Disconnect control (70), Limiter (71), Arbitrator (68)
  - **Other:** Image transfer (18), Data protection (30), GPRS modem (45), GSM diagnostic (47), MAC address (43)

### 2. Transport Layer

**Module:** `transport`

Abstracts the physical medium and provides APDU framing.

- **`PhysicalTransport`** — physical channel trait (serial, TCP, UDP). Methods: `send()`, `receive()`.

- **`NetworkTransport`** — marker trait for network transports (TCP/UDP). Required for the wrapper sub-layer.

- **`DataLinkLayer`** — data link layer trait. Methods: `send_apdu()`, `receive_apdu()`.

- **HDLC** (`transport::hdlc`) — framing per IEC 62056-46. Works over any `PhysicalTransport` (serial, TCP, UDP).

- **Wrapper** (`transport::wrapper`) — framing per IEC 62056-47. Works only over `NetworkTransport` (TCP/UDP). 8-byte header: version (2) + source wPort (2) + destination wPort (2) + length (2).

### 3. Application Layer

**Modules:** `service`, `security`

Implements xDLMS services and the security model.

#### Services (`service`)

- **GET/SET/ACTION** — normal, block transfer (with datablocks) and WITH-LIST requests/responses
- **ACSE** — association (AARQ/AARE) and release (RLRQ/RLRE)
- **Initiate** — structured InitiateRequest/InitiateResponse
- **Notifications** — DataNotification and EventNotification
- **Errors** — ExceptionResponse and ConfirmedServiceError
- **GBT** — general block transfer
- **Ciphering** — glo-/ded-ciphering and general-glo-/ded-/general-ciphering / general-signing

#### Security (`security`)

- **Security suites** (SecuritySuite): 0 (AES-GCM-128), 1 (ECDH-ECDSA-P256), 2 (ECDH-ECDSA-P384), GOST
- **Security policy** (SecurityPolicy): none, authentication, encryption, authenticated_encryption
- **Authentication mechanisms** (AuthMechanism): 0..10, including GOST HLS (8: CMAC, 9: reserved, 10: GOST 34.10)
- **Key agreement:** ECDH (NIST P-256/P-384) and GOST VKO
- **Digital signatures:** ECDSA and GOST 34.10-2018
- **Hashing:** SHA-256, SHA-384, Streebog-256
- **Access rights** (`access_rights`): ACL model per IEC 62056-5-3, 5.3.7.2.2 — `ObjectListEntry`, `AttributeAccessMode`, `MethodAccessMode`

### 4. Drivers

**Modules:** `session`, `server`

High-level wrappers for client and server operations.

- **`ClientSession`** — blocking client driver. Binds transport, services, and ciphering into round-trip GET/SET/ACTION/associate/release calls.

- **`RequestDispatcher`** — server dispatcher. Routes incoming GET/SET/ACTION APDUs to addressed COSEM objects and returns response APDUs. Supports access rights checking via `set_association()` — when an Association LN is set, all requests are validated against the `object_list` access_rights before dispatch.

### 5. SPODUS Profile

**Module:** `spodus`

IVEK (data concentrator/gateway) information model per STO 34.01-5.1-013-2023.

- **Concentrator** (`spodus::node`) — concentrator node acting as DLMS server for IVC (upstream) and DLMS client for meters (downstream)
- **Catalog** (`spodus::catalog`) — standard objects: Clock, SAP assignment, Security setup, Association LN
- **Appendix A objects:** nameplate, configured meters, direct channel, channel list, discovered meters, access policies, data-exchange tasks, status table, journals, notifications
- **New STO-013 classes:** Table manager (8200), Profile data filter (8201)
- **Transparent pass-through** (`spodus::proxy`) — MeterProxy for accessing individual meters through the concentrator

## Data Flows

### Client Request (GET)

```text
ClientSession::get(class_id, obis, attr_id)
  │
  ├── Builds GetRequest APDU
  ├── Encrypts (if policy != None) via security
  ├── Sends via DataLinkLayer::send_apdu()
  │     └── Wrapper/HDLC frames the APDU
  │           └── PhysicalTransport::send() transmits over the channel
  │
  └── Waits for response via DataLinkLayer::receive_apdu()
        └── Deserializes GetResponse
```

### Server Response

```text
RequestDispatcher::dispatch(apdu_bytes)
  │
  ├── Deserializes incoming APDU
  ├── Looks up target object by class_id + obis
  ├── Calls object method (get/set/action)
  ├── Builds response APDU
  └── Returns response bytes
```

### APDU Ciphering

```text
Encrypt (glo_*_Request):
  ├── SC (Security Control): suite_id || protection_level || key_info
  ├── IC (Invocation Counter): 4 bytes, monotonically increasing
  ├── IV = system_title || IC
  ├── AAD = SC || AK (authenticated encryption) or SC || AK || plaintext (auth only)
  ├── AES-GCM: encrypt(plaintext, key=EK, nonce=IV, aad=AAD)
  └── Result: tag || IC || ciphertext || truncated_tag
```

## Standards Compliance

| Standard | Description | Implementation |
| -------- | ----------- | -------------- |
| IEC 62056-5-3 | DLMS/COSEM application layer | service, session, server |
| IEC 62056-6-2 | COSEM interface classes | classes (30 IC) |
| IEC 62056-46 | HDLC transport | transport::hdlc |
| IEC 62056-47 | TCP/UDP transport (wrapper) | transport::wrapper |
| STO 34.01-5.1-006-2023 | SPODES — meter model | classes, security |
| STO 34.01-5.1-013-2023 | SPODUS — IVEK model | spodus |
| R 1323565.1 | GOST cryptography | security::gost3410, hls, agreement |
| GOST R 34.10-2018 | Elliptic curve digital signatures | security::gost3410 |
| GOST R 34.11-2018 | Streebog hash function | streebog crate |
| GOST R 34.12-2018 | Kuznyechik block cipher | kuznyechik crate |

## Requirements

- **Rust:** >= 1.85 (edition 2021)
- **unsafe:** not used in crate sources
- **feature flags:** not required
- **Dependencies:** serde, aes-gcm, p256/p384, ecdsa, streebog, kuznyechik, num-bigint, rand
