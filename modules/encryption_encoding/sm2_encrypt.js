import { module } from './_cat.js';
import { A } from '../../core/registry.js';
import { bytesToHex } from '../../core/util.js';
import { sm2Encrypt, sm2PublicKeyFromXY } from './_sm2.js';

// CyberChef's SM2 Encrypt op takes the public key as two plain hex strings (not a toggleString)
// and always outputs plain lowercase hex (hexC1X + hexC1Y + c3/c2 or c2/c3) - see
// src/core/operations/SM2Encrypt.mjs / src/core/lib/SM2.mjs.
module('SM2 Encrypt', 'Encrypts a message with the SM2 public-key cryptosystem (GB/T 32918), the Chinese national standard elliptic-curve cryptosystem, over the sm2p256v1 curve. Public Key X/Y are each 32 bytes (64 hex characters). Output is C1 || C3 || C2 (or C1 || C2 || C3) as hex.',
  [
    A.string('Public Key X', 'DEADBEEF'),
    A.string('Public Key Y', 'DEADBEEF'),
    A.select('Output Format', ['C1C3C2', 'C1C2C3']),
    A.select('Curve', ['sm2p256v1']),
  ],
  (data, pubX, pubY, format) => {
    pubX = pubX.trim().toLowerCase();
    pubY = pubY.trim().toLowerCase();
    if (pubX.length !== 64 || pubY.length !== 64) throw new Error('Invalid Public Key - Ensure each component is 32 bytes in size and in hex');
    const pub = sm2PublicKeyFromXY(pubX, pubY);
    const ciphertext = sm2Encrypt(pub, data, format);
    return bytesToHex(ciphertext);
  }, { nondeterministic: true });
