import { module } from './_cat.js';
import { A } from '../../core/registry.js';

module('Escape Unicode Characters', 'Converts characters to \\uXXXX style escapes.',
  [A.select('Prefix', ['\\u', '%u', 'U+']), A.boolean('Encode all chars', false), A.number('Padding', 4, 1, 8), A.boolean('Uppercase hex', true)],
  (t, prefix, everything, pad, upper) => {
    let out = '';
    for (const c of t) {
      const o = c.codePointAt(0);
      if (everything || o > 127) {
        let h = o.toString(16);
        if (upper) h = h.toUpperCase();
        out += prefix + h.padStart(pad, '0');
      } else out += c;
    }
    return out;
  }, { text: true });
