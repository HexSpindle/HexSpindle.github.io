import { module } from './_cat.js';
import { A } from '../../core/registry.js';
import { bytesToHex } from '../../core/util.js';
import { keccakSponge } from './keccak.js';

// SHAKE128/256 extendable-output functions: Keccak sponge with domain byte 0x1F.
// Capacity (in bits) is twice the nominal security strength: SHAKE128 -> 256-bit capacity
// (168-byte rate), SHAKE256 -> 512-bit capacity (136-byte rate).
export function shake(data, capBits, outputBytes) {
  const rate = 200 - capBits / 8;
  return keccakSponge(data, rate, 0x1f, outputBytes);
}

module('Shake', 'SHAKE extendable-output functions.', [A.select('Capacity', ['256', '128']), A.number('Size (bits)', 512, 8)],
  (data, cap, bits) => bytesToHex(shake(data, cap === '128' ? 256 : 512, Math.floor(bits / 8))));
