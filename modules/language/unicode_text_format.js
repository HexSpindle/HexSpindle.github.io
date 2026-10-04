import { module } from './_cat.js';
import { A } from '../../core/registry.js';

const MAPS = {
  'Bold (𝐀)': [0x1d400, 0x1d41a], 'Italic (𝐴)': [0x1d434, 0x1d44e], 'Bold Italic': [0x1d468, 0x1d482], 'Script': [0x1d49c, 0x1d4b6],
  'Fraktur': [0x1d504, 0x1d51e], 'Double-struck': [0x1d538, 0x1d552], 'Sans-serif': [0x1d5a0, 0x1d5ba], 'Monospace': [0x1d670, 0x1d68a],
};

function mapLetters(t, fn) {
  return [...t].map(c => {
    const cp = c.codePointAt(0);
    if (cp >= 65 && cp <= 90) return fn(cp - 65, true);
    if (cp >= 97 && cp <= 122) return fn(cp - 97, false);
    return c;
  }).join('');
}

module('Unicode Text Format', 'Re-renders letters in a Unicode mathematical style, or underlines / strikes through text.',
  [A.select('Style', [...Object.keys(MAPS), 'Underline', 'Strikethrough', 'Circled'])],
  (t, style) => {
    if (style === 'Underline') return [...t].map(c => c + '̲').join('');
    if (style === 'Strikethrough') return [...t].map(c => c + '̶').join('');
    if (style === 'Circled') return mapLetters(t, (off, upper) => String.fromCodePoint((upper ? 0x24b6 : 0x24d0) + off));
    const [up, lo] = MAPS[style];
    return mapLetters(t, (off, upper) => String.fromCodePoint((upper ? up : lo) + off));
  }, { text: true });
