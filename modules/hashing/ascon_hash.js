import { module } from './_cat.js';
import { bytesToHex } from '../../core/util.js';
import { asconHash256 } from './_ascon.js';

// Ascon-Hash256, standardised as part of NIST SP 800-232 (2025): a fixed 256-bit lightweight hash
// selected by NIST's lightweight cryptography competition. See _ascon.js for the permutation/IV
// provenance and verification notes (1025/1025 official NIST KAT vectors pass).
module('Ascon Hash', 'Ascon-Hash256: a 256-bit lightweight cryptographic hash from the Ascon family, standardised in NIST SP 800-232 for constrained devices such as IoT sensors and embedded systems.', [],
  (data) => bytesToHex(asconHash256(data)));
