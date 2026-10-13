# Decision 006: Lab Base Images, Subnet, and Network Topology

## Status
Approved

## Context
Phase 4 of SecureMailScope requires an isolated Docker-based lab environment containing Postfix and Dovecot mail servers, a Python client with explicit SSL/TLS parameters, and a dedicated network capture service running tcpdump.

Per Section 11 of `docs/ARCHITECTURE.md` and Prompt 4.1:
1. The lab network must use a fixed subnet `172.28.0.0/24`.
2. Mailserver service must be assigned the fixed IP `172.28.0.10`.
3. Client service must be assigned the fixed IP `172.28.0.20`.
4. Capture service must run in the mailserver network namespace (`network_mode: "service:mailserver"`), capturing classic PCAP files to `lab/captures/<name>.pcap`.
5. Base container images must be pinned by cryptographic digest to guarantee deterministic environment reproducibility across hosts.

## Decision

### 1. Pinned Container Base Images
- **Mailserver (`lab/mailserver`)**:
  - Image: `debian:bookworm-slim`
  - Pinned Digest: `debian@sha256:1a8a211e4f451f165e8a60dbb6be669d0d3839213bc8939c381c850a12e3e2c6`
  - Installed packages: `postfix`, `dovecot-imapd`, `dovecot-pop3d`, `sasl2-bin`, `openssl`, `ca-certificates`.
  - Configured with OpenSSL cipher profiles supporting legacy cipher evaluation (e.g. `SECLEVEL=1` / `SECLEVEL=0` for tests involving TLS 1.0 or 3DES).

- **Client (`lab/client`)**:
  - Image: `python:3.11-slim-bookworm`
  - Pinned Digest: `python@sha256:7f4d22197ae71221f7db19eb0b1f4806a143b879c5dc2ab440056e4c76b1f237`
  - Uses standard library `smtplib` and explicit `ssl.SSLContext` with custom CA trust stores.

- **Capture (`lab/capture`)**:
  - Image: `alpine:3.20`
  - Pinned Digest: `alpine@sha256:b89d633e70d76049409ae0b1b61a40ceb84731849bfbaed3b70f366da39c378d`
  - Installed package: `tcpdump`.
  - Network mode: `service:mailserver` to capture ingress/egress interface traffic on `eth0` with Ethernet framing (Link type 1 / `DLT_EN10MB`).

### 2. Network Topology & IP Allocation
- Bridge Network: `lab`
  - Subnet: `172.28.0.0/24`
  - Gateway: `172.28.0.1`
- Nodes:
  - Mailserver: `172.28.0.10` (Ports: 25, 465, 587, 110, 995, 143, 993)
  - Client: `172.28.0.20`
  - Capture: Shared container network namespace with mailserver

### 3. PCAP Format and Link Type
- Capture command: `tcpdump -i eth0 -w /captures/<ID>.pcap "tcp port 25 or tcp port 465 or tcp port 587"`
- Format: Classic PCAP (magic `0xa1b2c3d4`, microsecond timestamps).
- Link Type: Link type 1 (`DLT_EN10MB` / Ethernet).

## Consequences
- Guarantees byte-identical network capture framing without non-deterministic container IP assignment.
- Ensures all traffic is captured directly at the server interface, preserving exact TCP window parameters, MSS, sequence numbers, and TLS records.
