# Experiment E4: Engine Determinism & Bit-Level Reproducibility

**Evaluation Parameters:** 5 independent iterations per capture with fixed organization secret.

**Overall Result:** **100% Deterministic (Zero Bit Variance)**

| Scenario | Runs Evaluated | Result Root Digest | Byte-Identical | Bit Variance |
|---|---|---|---|---|
| A1 | 5 | `341d678b5e8d3643...` | **YES** | 0 bytes |
| A2 | 5 | `e6a77c74045a7462...` | **YES** | 0 bytes |
| A3 | 5 | `fab6ebb04638b0b8...` | **YES** | 0 bytes |
| baseline | 5 | `e52febc345a769ba...` | **YES** | 0 bytes |
| S01a | 5 | `3b452e6f6b26e769...` | **YES** | 0 bytes |
| S01b | 5 | `d5ec179fe3a17c0f...` | **YES** | 0 bytes |
| S02 | 5 | `b44e75abc5dc9224...` | **YES** | 0 bytes |
| S03 | 5 | `cbb3623139895b64...` | **YES** | 0 bytes |
| S04 | 5 | `2b17b615e9ee6fad...` | **YES** | 0 bytes |
| S05 | 5 | `804ec88864505b83...` | **YES** | 0 bytes |
| S06 | 5 | `aeea4323266afd39...` | **YES** | 0 bytes |
| S07 | 5 | `fab6ebb04638b0b8...` | **YES** | 0 bytes |
| S08 | 5 | `65c0d661815cfc15...` | **YES** | 0 bytes |
| S09 | 5 | `d66282c89084e188...` | **YES** | 0 bytes |
| S10 | 5 | `cb13cf0ca99e77cd...` | **YES** | 0 bytes |
| S11 | 5 | `6e28d65638bb65a5...` | **YES** | 0 bytes |
| S12 | 5 | `665121340d635aa9...` | **YES** | 0 bytes |
| S13 | 5 | `c1fcedf4cb599163...` | **YES** | 0 bytes |
| S20 | 5 | `e2c2c672d6a5637f...` | **YES** | 0 bytes |
| S21 | 5 | `0d0ea03836de1386...` | **YES** | 0 bytes |
| S22 | 5 | `a763860fd8c4aeb3...` | **YES** | 0 bytes |
| S23 | 5 | `a7889df7c9f467cb...` | **YES** | 0 bytes |
| S24 | 5 | `f4f524d2cb4d6c87...` | **YES** | 0 bytes |
| S25 | 5 | `cf59badfab959e75...` | **YES** | 0 bytes |
| S30 | 5 | `98d794aa94aaa383...` | **YES** | 0 bytes |
| S31 | 5 | `2d0fc03e558e9e75...` | **YES** | 0 bytes |
| S32 | 5 | `af5dc8917d7907fb...` | **YES** | 0 bytes |
| S33 | 5 | `79d6a89ceb55c4b5...` | **YES** | 0 bytes |
| S34 | 5 | `fbff70bd72d3486f...` | **YES** | 0 bytes |
| S35 | 5 | `341d678b5e8d3643...` | **YES** | 0 bytes |
| X01 | 5 | `3b452e6f6b26e769...` | **YES** | 0 bytes |
| X02 | 5 | `3b452e6f6b26e769...` | **YES** | 0 bytes |
| X03 | 5 | `3b452e6f6b26e769...` | **YES** | 0 bytes |

### Determinism Enforcement Rules Satisfied

1. **No Wall-Clock Timestamps:** Output JSON files strictly reference integer capture epoch seconds from PCAP record headers.
2. **Canonical JSON Encoding:** Keys sorted alphabetically, separators `(',', ':')`, non-ASCII rejected, floats rejected.
3. **Deterministic Merkle Leaves:** Leaves sorted ascending by raw 32-byte digest before tree aggregation.
