# Technical Architecture: LeakLens Forensic Watermarking & Offline DRM

This document specifies the cryptographic and steganographic architecture powering **LeakLens** (formerly SentinelTrace), connecting the v0 engineering implementation to the Framer product representation.

---

## 1. Zero-Width Unicode Steganography Engine

### A. Invisible Character Alphabet
LeakLens embeds arbitrary cryptographic payloads into plain text without adding visible glyphs, changing line lengths, or triggering spell-check flags. It uses the Unicode zero-width space family:

| Character | Code Point | Function in LeakLens |
| :--- | :--- | :--- |
| **Zero-Width Space** | `\u200B` | Binary `0` |
| **Zero-Width Non-Joiner** | `\u200C` | Binary `1` |
| **Zero-Width Joiner** | `\u200D` | Byte/Character Delimiter |
| **Zero-Width No-Break Space** | `\uFEFF` | Payload Header / Sentinel Anchor |

### B. Payload Structure & Cryptographic Signing
Every watermarked document encapsulates a structured JSON payload:
```json
{
  "r": "Alice Smith (USR-8492)",
  "s": "SES-8921-ALPHA",
  "exp": 1732537200,
  "sig": "f4a8b79c3d1e... (HMAC-SHA256)"
}
```

#### Signature Generation
$$\text{Signature} = \text{HMAC-SHA256}(K_{\text{sentinel}}, \text{Recipient} \parallel \text{SessionID} \parallel \text{Expiry} \parallel \text{DocumentHash})$$
Where:
- $K_{\text{sentinel}}$ is the master or tenant-specific secret key (`SENTINEL_SIGNING_KEY`).
- In v0 and local testing, an ephemeral key is generated per process if `SENTINEL_SIGNING_KEY` is omitted. For production deployments, a static KMS-managed key (e.g. AWS KMS, HashiCorp Vault, or Google Cloud KMS) ensures cross-worker verification consistency.

### C. Redundancy & Fragmentation Resilience
To prevent adversaries from defeating the watermark through excerpting, the payload is injected across multiple locations in the document:
1. **Header Anchor**: Following the first punctuation mark or newline.
2. **Body Spread**: Distributed periodically every $N$ paragraphs.
3. **Tail Anchor**: Preceding the final sentence.

Even if an insider leaks only a 2-sentence excerpt, the forensic inspector can recover at least one complete payload block and authenticate the cryptographic signature.

---

## 2. Forensic Leak Inspector Verification Protocol

When an investigator inputs a leaked text snippet into the **Forensic Leak Inspector**:

```
[ Leaked Snippet Input ]
           │
           ▼
[ Regex Filter: Scan for [\u200B\u200C\u200D\uFEFF]+ ]
           │
           ├─ No Zero-Width Characters ──► Return "No Watermark Detected"
           ▼
[ Bitstream Demodulation: Map to Binary 0/1 ]
           │
           ▼
[ JSON Payload Deserialization ]
           │
           ▼
[ HMAC-SHA256 Re-Computation ]
           │
           ├─ Signature Mismatch ────────► Return "Tamper Warning: Invalid Signature"
           ▼
[ Cryptographic Match Confirmed ]
           │
           ▼
[ Display Attribution Card: Leaker Identity, Session ID, Timestamp ]
```

---

## 3. Time-Bounded Offline DRM State Machine

The Offline DRM Access Monitor protects high-value documents stored on local endpoints or viewed offline:

### State Transitions
1. **ONLINE_SYNCHRONIZED**:
   - Client communicates periodically with central KMS.
   - Decryption key resides in memory enclave.
2. **OFFLINE_LEASE_ACTIVE**:
   - Initiated by user disconnecting or toggling offline mode.
   - Hardware monotonic clock counts down the pre-configured lease window ($1 \le t \le 120$ minutes).
   - Dynamic UI displays countdown and `ACCESS GRANTED`.
3. **LEASE_EXPIRED_KEY_SHREDDED**:
   - Monotonic timer reaches `00:00`.
   - Memory auto-zeroing routine wipes the local decryption key from volatile RAM.
   - Document view instantly flips to `ACCESS REVOKED / EXPIRED`.
   - Reconnection to central KMS is required to re-authenticate and request a fresh lease token.
