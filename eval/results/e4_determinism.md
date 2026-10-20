# Experiment E4: Engine Determinism & Bit-Level Reproducibility

**Evaluation Parameters:** 5 independent iterations per capture with fixed organization secret.

**Overall Result:** **100% Deterministic (Zero Bit Variance)**

| Scenario | Runs Evaluated | Result Root Digest | Byte-Identical | Bit Variance |
|---|---|---|---|---|
| A1 | 5 | `43c3e97691692745...` | **YES** | 0 bytes |
| A2 | 5 | `9d3436ffe9022b97...` | **YES** | 0 bytes |
| A3 | 5 | `3f166116c8509248...` | **YES** | 0 bytes |
| baseline | 5 | `9bcf44161151b5b9...` | **YES** | 0 bytes |
| S01a | 5 | `3b452e6f6b26e769...` | **YES** | 0 bytes |
| S01b | 5 | `cb5fa5e0bfd5cf6f...` | **YES** | 0 bytes |
| S02 | 5 | `ca09ea82b43e549e...` | **YES** | 0 bytes |
| S03 | 5 | `93854c086527a95f...` | **YES** | 0 bytes |
| S04 | 5 | `9098e00d12a151c8...` | **YES** | 0 bytes |
| S05 | 5 | `6341fc4157d5f14a...` | **YES** | 0 bytes |
| S06 | 5 | `b162817c11c7a019...` | **YES** | 0 bytes |
| S07 | 5 | `3f166116c8509248...` | **YES** | 0 bytes |
| S08 | 5 | `0d187af38437451a...` | **YES** | 0 bytes |
| S09 | 5 | `b755c7b8fa677f6e...` | **YES** | 0 bytes |
| S10 | 5 | `692a73f2f7b7de33...` | **YES** | 0 bytes |
| S11 | 5 | `3566734c82eb3d5f...` | **YES** | 0 bytes |
| S12 | 5 | `c6874b67f11a45dd...` | **YES** | 0 bytes |
| S13 | 5 | `c1fcedf4cb599163...` | **YES** | 0 bytes |
| S20 | 5 | `e2c2c672d6a5637f...` | **YES** | 0 bytes |
| S21 | 5 | `6ba40c79c29cc705...` | **YES** | 0 bytes |
| S22 | 5 | `a763860fd8c4aeb3...` | **YES** | 0 bytes |
| S23 | 5 | `a7889df7c9f467cb...` | **YES** | 0 bytes |
| S24 | 5 | `9bfc0d5f1d8372af...` | **YES** | 0 bytes |
| S25 | 5 | `cf59badfab959e75...` | **YES** | 0 bytes |
| S30 | 5 | `c433c54ee0abf55e...` | **YES** | 0 bytes |
| S31 | 5 | `62d4a529290decb5...` | **YES** | 0 bytes |
| S32 | 5 | `18ce91689320c3ed...` | **YES** | 0 bytes |
| S33 | 5 | `458030df9361f348...` | **YES** | 0 bytes |
| S34 | 5 | `0af45a2bc9630e42...` | **YES** | 0 bytes |
| S35 | 5 | `43c3e97691692745...` | **YES** | 0 bytes |
| X01 | 5 | `3b452e6f6b26e769...` | **YES** | 0 bytes |
| X02 | 5 | `3b452e6f6b26e769...` | **YES** | 0 bytes |
| X03 | 5 | `3b452e6f6b26e769...` | **YES** | 0 bytes |

### Determinism Enforcement Rules Satisfied

1. **No Wall-Clock Timestamps:** Output JSON files strictly reference integer capture epoch seconds from PCAP record headers.
2. **Canonical JSON Encoding:** Keys sorted alphabetically, separators `(',', ':')`, non-ASCII rejected, floats rejected.
3. **Deterministic Merkle Leaves:** Leaves sorted ascending by raw 32-byte digest before tree aggregation.
