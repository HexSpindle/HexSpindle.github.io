import { module } from './_cat.js';

// Citrix CTX1: a simple XOR-with-running-state obfuscation used to hide Citrix ICA password-field
// hashes (not a real cipher - no key, trivially reversible). Mirrors CyberChef's CitrixCTX1Encode.mjs:
// the input string is first UTF-16LE-encoded (Windows codepage 1200), then each byte is XORed with a
// fixed 0xa5 and the previous output byte, and the result nibble-split into two 'A'-'P' letters.
function utf16leEncode(s) {
  const out = new Uint8Array(s.length * 2);
  for (let i = 0; i < s.length; i++) {
    const code = s.charCodeAt(i);
    out[i * 2] = code & 0xff;
    out[i * 2 + 1] = (code >>> 8) & 0xff;
  }
  return out;
}

export function citrixCtx1Encode(input) {
  const utf16pass = utf16leEncode(input);
  const out = new Uint8Array(utf16pass.length * 2);
  let temp = 0;
  for (let i = 0; i < utf16pass.length; i++) {
    temp = utf16pass[i] ^ 0xa5 ^ temp;
    out[i * 2] = ((temp >>> 4) & 0xf) + 0x41;
    out[i * 2 + 1] = (temp & 0xf) + 0x41;
  }
  return out;
}

module('Citrix CTX1 Encode', 'Encodes strings to Citrix CTX1 password format.', [], (input) => citrixCtx1Encode(input), { text: true });
