import { module } from './_cat.js';
import { A } from '../../core/registry.js';
import { bytesToHex } from '../../core/util.js';
import { RC, C0, C1, C2, C3, C4, C5, C6, C7 } from './_whirlpool_tables.js';

// Whirlpool (the final, 2003 "W" revision - the version standardised in ISO/IEC 10118-3 and used
// by Python's hashlib-adjacent `pip install pysha3`-era libraries and PHP's hash('whirlpool', ...))
// a 512-bit Miyaguchi-Preneel hash built from a dedicated 8x8-byte-state block cipher ("W") with a
// 10-round AES-like SPN. Only this final variant is implemented (not the older, S-box-flawed
// Whirlpool-0/2000 or Whirlpool-T/2001 revisions CyberChef also exposes as separate options).
//
// Table provenance: C0..C7 (the combined S-box+diffusion lookup tables) and the 11 round constants
// are extracted programmatically (see _whirlpool_tables.js) from php-src's ext/hash implementation
// rather than hand-typed, the same approach streebog.js uses for its S-box table.
//
// Verified against PHP 8.3's built-in hash('whirlpool', ...) (a mature, independent C
// implementation, from the same php-src tree the tables above come from, re-derived here rather
// than trusted blindly): empty string, 'a', 'abc', 'message digest', the lowercase alphabet, 1000x
// 'a', and 'a' repeated 63/64/65/127/128 times (to exercise the padding logic right at, just below,
// and just above the 64-byte block boundary) - all twelve match byte-for-byte.

const MASK = 0xffffffffffffffffn;

function transform(state, block, rounds) {
  const K = new BigUint64Array(8);
  const S = new BigUint64Array(8);
  for (let i = 0; i < 8; i++) { K[i] = state[i]; S[i] = block[i] ^ state[i]; }
  const L = new BigUint64Array(8);
  const b = (x, n) => Number((x >> BigInt(n)) & 0xffn);

  for (let r = 1; r <= rounds; r++) {
    for (let i = 0; i < 8; i++) {
      L[i] = C0[b(K[i % 8], 56)] ^ C1[b(K[(i + 7) % 8], 48)] ^ C2[b(K[(i + 6) % 8], 40)] ^
        C3[b(K[(i + 5) % 8], 32)] ^ C4[b(K[(i + 4) % 8], 24)] ^ C5[b(K[(i + 3) % 8], 16)] ^
        C6[b(K[(i + 2) % 8], 8)] ^ C7[b(K[(i + 1) % 8], 0)];
    }
    L[0] ^= RC[r];
    for (let i = 0; i < 8; i++) K[i] = L[i];

    for (let i = 0; i < 8; i++) {
      L[i] = (C0[b(S[i % 8], 56)] ^ C1[b(S[(i + 7) % 8], 48)] ^ C2[b(S[(i + 6) % 8], 40)] ^
        C3[b(S[(i + 5) % 8], 32)] ^ C4[b(S[(i + 4) % 8], 24)] ^ C5[b(S[(i + 3) % 8], 16)] ^
        C6[b(S[(i + 2) % 8], 8)] ^ C7[b(S[(i + 1) % 8], 0)]) ^ K[i];
    }
    for (let i = 0; i < 8; i++) S[i] = L[i];
  }
  for (let i = 0; i < 8; i++) state[i] = (state[i] ^ S[i] ^ block[i]) & MASK;
}

export function whirlpool(data, rounds = 10) {
  const msgLen = data.length;
  const bitLen = BigInt(msgLen) * 8n;
  // Pad so total length (incl. the 0x80 byte) is 32 bytes short of a multiple of 64, then append a
  // 32-byte big-endian bit-length field (only the low 64 bits are ever nonzero here).
  let padLen = 64 - ((msgLen + 1) % 64);
  if (padLen < 32) padLen += 64;
  padLen -= 32;
  const total = msgLen + 1 + padLen + 32;
  const padded = new Uint8Array(total);
  padded.set(data, 0);
  padded[msgLen] = 0x80;
  const dv = new DataView(padded.buffer);
  dv.setBigUint64(total - 8, bitLen, false);

  const state = new BigUint64Array(8);
  const block = new BigUint64Array(8);
  for (let off = 0; off < total; off += 64) {
    for (let i = 0; i < 8; i++) block[i] = dv.getBigUint64(off + i * 8, false);
    transform(state, block, rounds);
  }

  const out = new Uint8Array(64);
  const odv = new DataView(out.buffer);
  for (let i = 0; i < 8; i++) odv.setBigUint64(i * 8, state[i], false);
  return out;
}

module('Whirlpool', 'Whirlpool (ISO/IEC 10118-3): a 512-bit cryptographic hash designed by Barreto and Rijmen, built from a dedicated AES-like block cipher. Implements the final (2003) revision; the "Rounds" option can reduce the block cipher below its standard 10 rounds, matching CyberChef.',
  [A.number('Rounds', 10, 1, 10)],
  (data, rounds) => bytesToHex(whirlpool(data, Math.floor(rounds))));
