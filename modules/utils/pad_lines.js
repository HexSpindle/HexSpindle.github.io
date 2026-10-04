import { module } from './_cat.js';
import { A } from '../../core/registry.js';

module('Pad lines', 'Pads each line to a length with a character.', [A.select('Position', ['Start', 'End']), A.number('Length', 5, 0), A.string('Character', ' ')],
  (t, pos, n, ch) => {
    ch = (ch || ' ')[0];
    const pad = pos === 'Start' ? (l => l.padStart(n, ch)) : (l => l.padEnd(n, ch));
    return t.split('\n').map(pad).join('\n');
  }, { text: true });
