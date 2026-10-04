import { module } from './_cat.js';
import { A } from '../../core/registry.js';
import { DELIMS, delim } from '../../core/util.js';
import { intToBase } from '../../core/codec.js';

const DIGITS = '0123456789abcdefghijklmnopqrstuvwxyz';

module('To Charcode', 'Converts text to its Unicode character codes in the chosen base.', [A.select('Delimiter', DELIMS), A.number('Base', 16, 2, 36)],
  (t, d, base) => [...t].map(c => intToBase(c.codePointAt(0), DIGITS.slice(0, base))).join(delim(d)), { text: true });
