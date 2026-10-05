import { module } from './_cat.js';
import { A } from '../../core/registry.js';
import { bytesToHex } from '../../core/util.js';
import { SNEFRU_SBOX } from './_snefru_sbox.js';

// Snefru (Ralph Merkle, "A Fast Software One-Way Hash Function", J. Cryptology 3(1), 1990). Only
// the two digest sizes the original spec defines (128 and 256 bits) are implemented; CyberChef's
// underlying library (crypto-api) additionally generalises to arbitrary 32-480 bit digests, which
// isn't part of the published algorithm, so that generalisation is intentionally left out here.
// Rounds (number of main passes over the S-box) can be 2, 4 or 8, as in the original paper and in
// CyberChef's own UI; Merkle's post-Biham/Shamir recommendation is to only ever use 8.
//
// Hand-ported from RHash's librhash/snefru.c (SNEFERU_UPDATE_W macro, the 4-step rotate schedule
// 16/8/16/24 bits, and the big-endian word loads/length field) - an independent, long-maintained C
// implementation; its precomputed S-box table (itself generated from the "Million Random Digits"
// table the original paper specifies) is reused as-is (see _snefru_sbox.js) rather than regenerated
// by hand, the same table-extraction approach streebog.js and whirlpool.js use.
//
// Verified against RHash's `rhash --snefru128/--snefru256` CLI (8-round only, since RHash doesn't
// expose a rounds option) for '', 'a', 'abc', 'message digest', the lowercase alphabet, and several
// lengths straddling the 32/48-byte block boundary - all match byte-for-byte for both digest sizes.
// The 2- and 4-round variants (not offered by RHash) were separately verified against crypto-api
// 0.8.5's own Snefru implementation - the library CyberChef's "Snefru" operation itself calls - for
// the same set of inputs; all match byte-for-byte there too.

function rotr(x, n) { return ((x >>> n) | (x << (32 - n))) >>> 0; }

export function snefru(data, digestBits = 128, rounds = 8) {
  const hashLen = digestBits / 32; // words
  const blockWords = 16 - hashLen;
  const blockBytes = blockWords * 4;

  const msgLen = data.length;
  // Zero-pad any partial final block, then always append one more dedicated all-zero block whose
  // last 8 bytes hold the big-endian 64-bit bit length (matches librhash's rhash_snefru_final).
  const total = Math.ceil(msgLen / blockBytes) * blockBytes + blockBytes;
  const buf = new Uint8Array(total);
  buf.set(data, 0);
  const dv = new DataView(buf.buffer);
  const bitLen = BigInt(msgLen) * 8n;
  dv.setUint32(total - 8, Number((bitLen >> 32n) & 0xffffffffn), false);
  dv.setUint32(total - 4, Number(bitLen & 0xffffffffn), false);

  let hash = new Uint32Array(hashLen);
  const W = new Uint32Array(16);
  const ROTS = [16, 8, 16, 24];

  for (let off = 0; off < total; off += blockBytes) {
    for (let i = 0; i < hashLen; i++) W[i] = hash[i];
    for (let i = 0; i < blockWords; i++) W[hashLen + i] = dv.getUint32(off + i * 4, false);

    let sboxOff = 0;
    for (let pass = 0; pass < rounds; pass++) {
      for (const rot of ROTS) {
        for (let i = 0; i < 16; i++) {
          const sbIdx = sboxOff + ((i << 7) & 0x100) + (W[i] & 0xff);
          const x = SNEFRU_SBOX[sbIdx];
          const prev = (i - 1) & 0xf;
          W[prev] ^= x;
          if (i >= 2) W[prev] = rotr(W[prev], rot);
          W[(i + 1) & 0xf] ^= x;
        }
        W[0] = rotr(W[0], rot);
        W[15] = rotr(W[15], rot);
      }
      sboxOff += 512;
    }

    for (let i = 0; i < hashLen; i++) hash[i] = (hash[i] ^ W[15 - i]) >>> 0;
  }

  const out = new Uint8Array(hashLen * 4);
  const odv = new DataView(out.buffer);
  for (let i = 0; i < hashLen; i++) odv.setUint32(i * 4, hash[i], false);
  return out;
}

module('Snefru', 'Snefru: Ralph Merkle\'s 1990 hash function (128 or 256-bit output). Only 2, 4 or 8 main passes are offered; Merkle recommends 8 (the "secure" revision) after Biham and Shamir\'s differential-cryptanalysis attack on the reduced-round versions.',
  [A.select('Size (bits)', ['128', '256']), A.select('Rounds', ['8', '4', '2'])],
  (data, size, rounds) => bytesToHex(snefru(data, parseInt(size, 10), parseInt(rounds, 10))));
