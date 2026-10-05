import { module } from './_cat.js';
import { A } from '../../core/registry.js';
import { parseHex, decodeLatin1, bytesToHex } from '../../core/util.js';
import { gostSign } from '../encryption_encoding/_gost_sign.js';

export const ALGORITHMS = ['GOST R 34.12 (Magma, 2015)', 'GOST R 34.12 (Kuznyechik, 2015)'];
const ALGO_INFO = { 'GOST R 34.12 (Magma, 2015)': { algo: 'Magma', blockBytes: 8 }, 'GOST R 34.12 (Kuznyechik, 2015)': { algo: 'Kuznyechik', blockBytes: 16 } };

// CyberChef's "GOST Sign"/"GOST Verify" are not GOST R 34.10 asymmetric digital signatures: they
// delegate to the @wavesenterprise/crypto-gost-js engine's "MAC" mode, i.e. a symmetric,
// shared-key CMAC-style checksum ("imitovstavka", GOST R 34.13-2015 S4.3) computed with a GOST
// block cipher - the same key signs and verifies. Ported from and verified byte-for-byte against
// that engine's processMAC15/signMAC (see ../encryption_encoding/_gost_sign.js for the vectors).
// Scope: only the two GOST R 34.12-2015 ciphers (Magma/Kuznyechik) are supported; the legacy
// GOST 28147-89 (1989) variant, which is selectable per 10 different historical S-box parameter
// sets (E-TEST, E-A, ... D-SC, per RFC 4357), is out of scope.
module('GOST Sign', 'Signs a message with a GOST block cipher in MAC ("imitovstavka") mode: a symmetric CMAC-style checksum computed with a shared key (this is not an asymmetric signature - the same key is used to sign and to verify, see GOST Verify). Only the GOST R 34.12-2015 ciphers (Magma/Kuznyechik) are supported.',
  [
    A.toggle('Key (32 bytes)', '', ['Hex', 'UTF8', 'Latin1', 'Base64'], 'Hex'),
    A.toggle('IV', '', ['Hex', 'UTF8', 'Latin1', 'Base64'], 'Hex'),
    A.select('Input type', ['Raw', 'Hex']),
    A.select('Output type', ['Hex', 'Raw']),
    A.select('Algorithm', ALGORITHMS),
    A.number('MAC length (bits)', 32, 8, 128, 8),
  ],
  (data, key, iv, inp, out, algorithm, macLengthBits) => {
    const { algo, blockBytes } = ALGO_INFO[algorithm];
    if (key.length !== 32) throw new Error('Key must be 32 bytes');
    if (inp === 'Hex') data = parseHex(decodeLatin1(data));
    const macLenBytes = Math.ceil(macLengthBits / 8);
    if (macLenBytes > blockBytes) throw new Error(`MAC length must be at most ${blockBytes * 8} bits for ${algorithm}`);
    if (iv.length && iv.length !== blockBytes) throw new Error(`IV must be ${blockBytes} bytes for ${algorithm} (or empty for the default all-zero IV)`);
    const mac = gostSign(algo, key, data, macLenBytes, iv.length ? iv : null);
    return out === 'Hex' ? bytesToHex(mac) : mac;
  });
