import { module } from './_cat.js';
import { A } from '../../core/registry.js';

function square(keyword) {
  const seen = [];
  for (const c of (keyword.toUpperCase().replace(/J/g, 'I') + 'ABCDEFGHIKLMNOPQRSTUVWXYZ')) {
    if (/[A-Z]/.test(c) && !seen.includes(c)) seen.push(c);
  }
  return seen;
}

module('Bifid Cipher Encode', 'Encodes text with the Bifid cipher (5x5 Polybius square, J=I).', [A.string('Keyword', '')],
  (t, keyword) => {
    const sq = square(keyword);
    const letters = [...t.toUpperCase().replace(/J/g, 'I')].filter(c => sq.includes(c));
    const rows = letters.map(c => Math.floor(sq.indexOf(c) / 5));
    const cols = letters.map(c => sq.indexOf(c) % 5);
    const seq = rows.concat(cols);
    const out = [];
    for (let i = 0; i < seq.length; i += 2) out.push(sq[seq[i] * 5 + seq[i + 1]]);
    return out.join('');
  }, { text: true });

export { square };
