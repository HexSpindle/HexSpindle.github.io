import { module } from './_cat.js';
import { A } from '../../core/registry.js';
import { bytesToHex } from '../../core/util.js';

// MD6: Ron Rivest's SHA-3 competition submission (Rivest, Agre, Bailey, Cheng, Crutchfield, Flajolet,
// Gunnels, Kaliski, Lin, Prabhakaran, Prevelakis, Vadhan, Yerukhimovich, "The MD6 Hash Function" -
// NIST SHA-3 submission, 2008). A Merkle-tree-structured hash: the input is split into 512-byte
// (64-word) blocks, each compressed with a fixed-point compression function f() (an 89-word feedback
// shift register run for r rounds, built from a fixed constant array Q, a round-updated constant S
// derived from the irreducible-polynomial mask Sm, and fixed shift-amount tables), with parent
// nodes combining 16-word (c=128-byte) chaining values from up to 64 children per level ("par"
// mode), falling back to sequential chaining ("seq" mode, c=128 bytes of previous state fed back
// alongside each block) once the level count L is exceeded or only one node remains. Each node's
// compression input is prefixed with a control word pair U/V encoding the level, index, round
// count r, level limit L, final-node flag, padding-bit count, key length and digest length, per
// the MD6 spec's node-ID/control-word layout. 64-bit words are represented as [hi,lo] uint32 pairs
// throughout since JS bitwise ops are only 32-bit safe.
//
// Hand-ported from the `md6-hash` npm package (Richienb/md6-hash), itself a from-scratch MD6
// implementation - restructured into this project's conventions, with the key/digest-length
// validation rewritten and the UTF-8-decode step dropped (this op already receives raw bytes).
// Verified against two independent, official-reference-derived vectors from the `md6` Rust crate
// (nabijaczleweli/md6-rs), which hashes via FFI to Rivest's own reference C implementation:
// MD6-256("") = bca38b24a804aa37d821d31af00f5598230122c5bbfc4c4ad5ed40e4258f04ca,
// MD6-512("") = 6b7f33821a2c060ecdd81aefddea2fd3c4720270e18654f4cb08ece49ccb469f8beeee7c831206bd577f9f2630d91779203a9489e47e04df4e6deaa0f8e0c0,
// MD6-256("The lazy fox jumps over the lazy dog") = e45551aae266e1482ac98e24229b3e90dc06177f8fb1a526e9da2cc957197aa -
// all three match this port byte-for-byte.

function xor(x, y) { return [x[0] ^ y[0], x[1] ^ y[1]]; }
function and(x, y) { return [x[0] & y[0], x[1] & y[1]]; }

function shl(x, n) {
  const a = x[0] | 0, b = x[1] | 0;
  if (n >= 32) return [(b << (n - 32)), 0];
  return [((a << n) | (b >>> (32 - n))), (b << n)];
}
function shr(x, n) {
  const a = x[0] | 0, b = x[1] | 0;
  if (n >= 32) return [0, (a >>> (n - 32))];
  return [(a >>> n), ((a << (32 - n)) | (b >>> n))];
}

function toWords(bytes) {
  const out = [];
  for (let i = 0; i < bytes.length; i += 8) {
    out.push([
      ((bytes[i] & 0xff) << 24) | ((bytes[i + 1] & 0xff) << 16) | ((bytes[i + 2] & 0xff) << 8) | (bytes[i + 3] & 0xff),
      ((bytes[i + 4] & 0xff) << 24) | ((bytes[i + 5] & 0xff) << 16) | ((bytes[i + 6] & 0xff) << 8) | (bytes[i + 7] & 0xff),
    ]);
  }
  return out;
}
function fromWords(words) {
  const out = [];
  for (const w of words) {
    out.push((w[0] >> 24) & 0xff, (w[0] >> 16) & 0xff, (w[0] >> 8) & 0xff, w[0] & 0xff,
      (w[1] >> 24) & 0xff, (w[1] >> 16) & 0xff, (w[1] >> 8) & 0xff, w[1] & 0xff);
  }
  return out;
}

function crop(sizeBits, bytes, fromRight) {
  const length = Math.floor((sizeBits + 7) / 8);
  const remain = sizeBits % 8;
  let out = fromRight ? bytes.slice(bytes.length - length) : bytes.slice(0, length);
  if (remain > 0) out[length - 1] &= (0xff << (8 - remain)) & 0xff;
  return out;
}

const Q = [
  [0x7311C281, 0x2425CFA0], [0x64322864, 0x34AAC8E7], [0xB60450E9, 0xEF68B7C1],
  [0xE8FB2390, 0x8D9F06F1], [0xDD2E76CB, 0xA691E5BF], [0x0CD0D63B, 0x2C30BC41],
  [0x1F8CCF68, 0x23058F8A], [0x54E5ED5B, 0x88E3775D], [0x4AD12AAE, 0x0A6D6031],
  [0x3E7F16BB, 0x88222E0D], [0x8AF8671D, 0x3FB50C2C], [0x995AD117, 0x8BD25C31],
  [0xC878C1DD, 0x04C4B633], [0x3B72066C, 0x7A1552AC], [0x0D6F3522, 0x631EFFCB],
];
const T_TAPS = [17, 18, 21, 31, 67, 89];
const RS = [10, 5, 13, 10, 11, 12, 2, 7, 14, 15, 7, 13, 11, 7, 6, 12];
const LS = [11, 24, 9, 16, 15, 9, 27, 15, 6, 2, 29, 8, 15, 5, 31, 9];
const S0 = [0x01234567, 0x89ABCDEF];
const SM = [0x7311C281, 0x2425CFA0];
const N_CONST = 89;

/** The MD6 compression function f(), run for `r` rounds over the n=89+16r word array `N`. Returns
 * the final 16-word (128-byte) chaining value. */
function f(nWords, r) {
  let S = S0.slice();
  const A = nWords.slice();
  for (let j = 0, i = N_CONST; j < r; j++, i += 16) {
    for (let s = 0; s < 16; s++) {
      let x = S.slice();
      x = xor(x, A[i + s - T_TAPS[5]]);
      x = xor(x, A[i + s - T_TAPS[0]]);
      x = xor(x, and(A[i + s - T_TAPS[1]], A[i + s - T_TAPS[2]]));
      x = xor(x, and(A[i + s - T_TAPS[3]], A[i + s - T_TAPS[4]]));
      x = xor(x, shr(x, RS[s]));
      A[i + s] = xor(x, shl(x, LS[s]));
    }
    S = xor(xor(shl(S, 1), shr(S, 63)), and(S, SM));
  }
  return A.slice(A.length - 16);
}

function md6(digestBits, data, key, levels) {
  const b = 512, c = 128, n = N_CONST;
  const d = digestBits;
  let K = key.slice(0, 64);
  const k = K.length;
  while (K.length < 64) K.push(0);
  K = toWords(K);

  const r = Math.max(k ? 80 : 0, 40 + Math.ceil(d / 4));
  const L = levels;
  let ell = 0;

  function mid(B, C, i, p, z) {
    const U = [((ell & 0xff) << 24), i & 0xffffffff];
    const V = [((r & 0xfff) << 16) | ((L & 0xff) << 8) | ((z & 0xf) << 4) | ((p & 0xf000) >> 12),
      (((p & 0xfff) << 20) | ((k & 0xff) << 12) | (d & 0xfff))];
    return f([...Q, ...K, U, V, ...C, ...B], r);
  }

  function par(bytes) {
    const z = bytes.length > b ? 0 : 1;
    let P = 0;
    const msg = bytes.slice();
    while (msg.length < 1 || (msg.length % b) > 0) { msg.push(0); P += 8; }
    const words = toWords(msg);
    const blocks = [];
    for (let off = 0; off < words.length; off += b / 8) blocks.push(words.slice(off, off + b / 8));
    let C = [];
    for (let i = 0; i < blocks.length; i++) {
      const p = i === blocks.length - 1 ? P : 0;
      C = C.concat(mid(blocks[i], [], i, p, z));
    }
    return fromWords(C);
  }

  function seq(bytes) {
    let P = 0;
    const msg = bytes.slice();
    while (msg.length < 1 || (msg.length % (b - c)) > 0) { msg.push(0); P += 8; }
    const words = toWords(msg);
    const blocks = [];
    for (let off = 0; off < words.length; off += (b - c) / 8) blocks.push(words.slice(off, off + (b - c) / 8));
    let C = new Array(16).fill([0, 0]);
    for (let i = 0; i < blocks.length; i++) {
      const p = i === blocks.length - 1 ? P : 0;
      const z = i === blocks.length - 1 ? 1 : 0;
      C = mid(blocks[i], C, i, p, z);
    }
    return fromWords(C);
  }

  let M = Array.from(data);
  do {
    ell++;
    M = ell > L ? seq(M) : par(M);
  } while (M.length !== c);

  return crop(d, M, true);
}

module('MD6', "MD6: Ron Rivest's SHA-3 competition submission, a Merkle-tree-structured hash built from an 89-word feedback-shift compression function. Supports 1-512 bit digests, an optional up-to-64-byte key, and a configurable tree-level limit (L=0 is fully sequential; the default L=64 is effectively a full binary-style tree for all practical message sizes).",
  [
    A.number('Digest size (bits)', 256, 1, 512),
    A.toggle('Key (optional, up to 64 bytes)', '', ['Hex', 'UTF8', 'Latin1', 'Base64'], 'UTF8'),
    A.number('Levels (L)', 64, 0, 255),
  ],
  (data, digestBits, key, levels) => {
    digestBits = Math.floor(digestBits);
    if (digestBits < 1 || digestBits > 512) throw new Error('Digest size must be between 1 and 512 bits');
    if (key.length > 64) throw new Error('Key must be at most 64 bytes');
    const digest = md6(digestBits, data, Array.from(key), Math.floor(levels));
    return bytesToHex(new Uint8Array(digest));
  });
