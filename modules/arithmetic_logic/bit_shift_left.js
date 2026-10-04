import { module } from './_cat.js';
import { A } from '../../core/registry.js';

function bytesToBigInt(u8) { let v = 0n; for (const b of u8) v = (v << 8n) | BigInt(b); return v; }
function bigIntToBytes(v, len) { const out = new Uint8Array(len); for (let i = len - 1; i >= 0; i--) { out[i] = Number(v & 0xffn); v >>= 8n; } return out; }

module('Bit shift left', 'Shifts the whole input left by N bits (carrying across bytes).', [A.number('Amount', 1, 0)],
  (data, n) => {
    if (!data.length) return new Uint8Array(0);
    const bits = BigInt(8 * data.length);
    const v = (bytesToBigInt(data) << BigInt(Math.trunc(n))) & ((1n << bits) - 1n);
    return bigIntToBytes(v, data.length);
  });
