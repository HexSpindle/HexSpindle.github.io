import { module } from './_cat.js';
import { A } from '../../core/registry.js';
import { DELIMS } from '../../core/util.js';

module('A1Z26 Cipher Decode', 'Replaces numbers 1-26 with letters.', [A.select('Delimiter', DELIMS)],
  (t) => (t.match(/\d+/g) || []).map(Number).filter(n => n >= 1 && n <= 26).map(n => String.fromCharCode(n + 64)).join(''), { text: true });
