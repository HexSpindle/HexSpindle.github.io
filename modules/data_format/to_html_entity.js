import { module } from './_cat.js';
import { A } from '../../core/registry.js';

const NAMED = { 38: 'amp', 60: 'lt', 62: 'gt', 34: 'quot', 39: 'apos', 160: 'nbsp', 169: 'copy', 174: 'reg', 8364: 'euro', 8482: 'trade' };

module('To HTML Entity', 'Converts characters to HTML entities.', [A.boolean('Convert all characters', false), A.select('Convert to', ['Named entities', 'Numeric entities', 'Hex entities'])],
  (t, everything, kind) => {
    let out = '';
    for (const c of t) {
      const o = c.codePointAt(0);
      const special = '&<>"\''.includes(c) || o > 127;
      if (!everything && !special) out += c;
      else if (kind === 'Named entities' && o in NAMED) out += `&${NAMED[o]};`;
      else if (kind === 'Hex entities') out += `&#x${o.toString(16)};`;
      else out += `&#${o};`;
    }
    return out;
  }, { text: true });
