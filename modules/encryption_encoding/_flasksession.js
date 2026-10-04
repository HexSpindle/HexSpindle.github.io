// Private helper: the itsdangerous URLSafeTimedSerializer construction the Python ops use
// directly (`itsdangerous.URLSafeTimedSerializer(secret, salt="cookie-session")`), reimplemented
// from the itsdangerous source (signer.py/timed.py/url_safe.py/_json.py):
//  - key derivation: "django-concat" (the library default) -> SHA-1(salt + b"signer" + secret)
//  - signing algorithm: HMAC-SHA1 (the library default)
//  - payload: compact JSON (no sort_keys, separators ",:" ), zlib-deflated when that's shorter,
//    base64url (no padding) encoded, with a "." prefix when compressed
//  - token shape: <payload>.<timestamp>.<signature>, each base64url (no padding); the timestamp is
//    the current Unix time as a minimal big-endian byte string
// Note this mirrors what these specific Python ops do (plain itsdangerous over raw JSON), not
// Flask's own session cookie format, which layers its TaggedJSONSerializer on top - matching the
// Python module's actual (narrower) behavior.
import { encodeUtf8, decodeUtf8, concatBytes, bytesEqual } from '../../core/util.js';

function b64uEncode(u8) {
  let s = '';
  for (let i = 0; i < u8.length; i += 0x8000) s += String.fromCharCode.apply(null, u8.subarray(i, i + 0x8000));
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function b64uDecode(s) {
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  s += '='.repeat((4 - (s.length % 4)) % 4);
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function intToBytes(n) {
  // Big-endian, minimal length (matches itsdangerous' int_to_bytes: pack as u64 BE, strip leading
  // zero bytes).
  if (n === 0) return new Uint8Array([0]);
  const bytes = [];
  let v = BigInt(n);
  while (v > 0n) { bytes.unshift(Number(v & 0xffn)); v >>= 8n; }
  return new Uint8Array(bytes);
}
function bytesToInt(u8) {
  let v = 0n;
  for (const b of u8) v = (v << 8n) | BigInt(b);
  return Number(v);
}

async function deriveKey(secret, salt) {
  const data = concatBytes([encodeUtf8(salt), encodeUtf8('signer'), encodeUtf8(secret)]);
  return new Uint8Array(await crypto.subtle.digest('SHA-1', data));
}

async function hmacSha1(key, msg) {
  const hk = await crypto.subtle.importKey('raw', key, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
  return new Uint8Array(await crypto.subtle.sign('HMAC', hk, msg));
}

// Minimal raw-deflate (zlib) compressor/decompressor via the browser/node built-in CompressionStream
// when available; falls back to "never compress" (always store the uncompressed payload) when it
// isn't, which itsdangerous handles equally correctly (compression is purely a size optimization -
// it only kicks in when the compressed form is shorter, and is always decodable either way).
async function zlibDeflate(bytes) {
  if (typeof CompressionStream === 'undefined') return null;
  const cs = new CompressionStream('deflate');
  const writer = cs.writable.getWriter();
  writer.write(bytes); writer.close();
  const chunks = [];
  const reader = cs.readable.getReader();
  for (;;) { const { done, value } = await reader.read(); if (done) break; chunks.push(value); }
  return concatBytes(chunks);
}
async function zlibInflate(bytes) {
  const ds = new DecompressionStream('deflate');
  const writer = ds.writable.getWriter();
  writer.write(bytes); writer.close();
  const chunks = [];
  const reader = ds.readable.getReader();
  for (;;) { const { done, value } = await reader.read(); if (done) break; chunks.push(value); }
  return concatBytes(chunks);
}

export async function dumpPayload(obj) {
  const json = encodeUtf8(JSON.stringify(obj));
  const compressed = await zlibDeflate(json);
  if (compressed && compressed.length < json.length - 1) {
    return '.' + b64uEncode(compressed);
  }
  return b64uEncode(json);
}

export async function loadPayload(payloadStr) {
  let s = payloadStr;
  let compressed = false;
  if (s.startsWith('.')) { s = s.slice(1); compressed = true; }
  let raw = b64uDecode(s);
  if (compressed) raw = await zlibInflate(raw);
  return JSON.parse(decodeUtf8(raw));
}

export async function sign(obj, secret, salt = 'cookie-session') {
  const payload = await dumpPayload(obj);
  const payloadBytes = encodeUtf8(payload);
  const ts = Math.floor(Date.now() / 1000);
  const tsB64 = b64uEncode(intToBytes(ts));
  const value = concatBytes([payloadBytes, encodeUtf8('.'), encodeUtf8(tsB64)]);
  const key = await deriveKey(secret, salt);
  const sig = await hmacSha1(key, value);
  return decodeUtf8(value) + '.' + b64uEncode(sig);
}

export async function verify(token, secret, maxAge, salt = 'cookie-session') {
  const parts = token.split('.');
  if (parts.length < 3) throw new Error('Invalid signature: malformed token');
  const sigB64 = parts[parts.length - 1];
  const tsB64 = parts[parts.length - 2];
  const payload = parts.slice(0, parts.length - 2).join('.');
  const value = encodeUtf8(payload + '.' + tsB64);
  const key = await deriveKey(secret, salt);
  const expected = await hmacSha1(key, value);
  const sig = b64uDecode(sigB64);
  if (!bytesEqual(expected, sig)) {
    throw new Error('Invalid signature: wrong secret key, or the cookie was tampered with');
  }
  const ts = bytesToInt(b64uDecode(tsB64));
  if (maxAge) {
    const age = Math.floor(Date.now() / 1000) - ts;
    if (age > maxAge) throw new Error(`Signature expired: age ${age} > ${maxAge} seconds`);
  }
  return loadPayload(payload);
}
