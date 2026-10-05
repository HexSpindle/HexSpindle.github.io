import { module } from './_cat.js';

// CyberChef's own novelty cipher (no external spec - CyberChef's source is the spec). Each UTF-16
// code unit becomes 16 bits written as 'E' (0) / 'e' (1), matching CetaceanCipherEncode.mjs exactly;
// a literal space in the input passes through unchanged (and CetaceanCipherDecode.mjs special-cases
// a run of 16 E/e's standing for a space - see cetacean_cipher_decode.js).
function toBinary16(code) {
  let s = '';
  for (let i = 15; i >= 0; i--) s += (code >> i) & 1;
  return s;
}

export function cetaceanEncode(input) {
  // Iterate by UTF-16 code unit (as CyberChef's input.split("") does), not by Unicode code point, so
  // a character outside the BMP round-trips as its two surrogate code units.
  let out = '';
  for (let i = 0; i < input.length; i++) {
    const ch = input[i];
    if (ch === ' ') { out += ch; continue; }
    const bits = toBinary16(ch.charCodeAt(0));
    for (const b of bits) out += b === '1' ? 'e' : 'E';
  }
  return out;
}

module('Cetacean Cipher Encode', "Converts any input into Cetacean Cipher, e.g. 'hi' becomes 'EEEEEEEEEeeEeEEEEEEEEEEEEeeEeEEe'.",
  [], (input) => cetaceanEncode(input), { text: true });
