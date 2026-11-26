// src/utils/steganography.js
/**
 * Zero‑width Unicode mapping for binary steganography
 * 0 -> \u200B (Zero‑Width Space)
 * 1 -> \u200C (Zero‑Width Non‑Joiner)
 * delimiter (if needed) -> \u200D (Zero‑Width Joiner)
 */
const ZW_ZERO = "\u200B";
const ZW_ONE = "\u200C";
const ZW_DELIM = "\u200D";

/**
 * Encode recipient metadata into a plain text string using invisible characters.
 * The payload is `${userId}:${timestamp}` converted to UTF‑16 binary (16‑bit per char).
 * Zero‑width characters are appended after the text (can also be interspersed).
 */
export function encodeWatermark(plainText, userId, timestamp) {
  const payload = `${userId}:${timestamp}`;
  // Convert each character to a 16‑bit binary string
  let bits = "";
  for (let i = 0; i < payload.length; i++) {
    const bin = payload.charCodeAt(i).toString(2).padStart(16, "0");
    bits += bin;
  }
  // Map bits to zero‑width characters
  let zwPayload = "";
  for (const b of bits) {
    zwPayload += b === "0" ? ZW_ZERO : ZW_ONE;
  }
  // Append a delimiter to signal end of payload (optional but helps decoding)
  zwPayload += ZW_DELIM;
  return plainText + zwPayload;
}

/**
 * Decode the hidden metadata from a steganographic text.
 * Returns an object `{ userId, timestamp }` or null if decoding fails.
 */
export function decodeWatermark(stegoText) {
  // Extract only zero‑width characters used for encoding
  const zwChars = [];
  for (const ch of stegoText) {
    if (ch === ZW_ZERO || ch === ZW_ONE || ch === ZW_DELIM) {
      zwChars.push(ch);
    }
  }
  // Remove trailing delimiter if present
  if (zwChars.length && zwChars[zwChars.length - 1] === ZW_DELIM) {
    zwChars.pop();
  }
  // Convert back to bit string
  const bits = zwChars
    .map((c) => (c === ZW_ZERO ? "0" : "1"))
    .join("");
  // Split into 16‑bit chunks
  const chars = [];
  for (let i = 0; i < bits.length; i += 16) {
    const chunk = bits.slice(i, i + 16);
    if (chunk.length < 16) break;
    const code = parseInt(chunk, 2);
    chars.push(String.fromCharCode(code));
  }
  const payload = chars.join("");
  const sepIdx = payload.indexOf(":");
  if (sepIdx <= 0) return null;
  const userId = payload.slice(0, sepIdx);
  const timestamp = payload.slice(sepIdx + 1);
  if (!userId || !timestamp) return null;
  return { userId, timestamp };
}
