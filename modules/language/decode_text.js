import { module } from './_cat.js';
import { A } from '../../core/registry.js';
import { ENCODINGS, decodeBytes } from './encode_text.js';

module('Decode text', 'Interprets bytes in a given character encoding and outputs UTF-8 text.', [A.select('Encoding', ENCODINGS)],
  (data, enc) => decodeBytes(data, enc));
