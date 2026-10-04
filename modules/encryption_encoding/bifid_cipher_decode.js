import { module } from './_cat.js';
import { A } from '../../core/registry.js';
import { square } from './bifid_cipher_encode.js';

module('Bifid Cipher Decode', 'Decodes the Bifid cipher.', [A.string('Keyword', '')],
  (t, keyword) => {
    const sq = square(keyword);
    const letters = [...t.toUpperCase().replace(/J/g, 'I')].filter(c => sq.includes(c));
    const seq = [];
    for (const c of letters) { const idx = sq.indexOf(c); seq.push(Math.floor(idx / 5), idx % 5); }
    const n = letters.length;
    const rows = seq.slice(0, n), cols = seq.slice(n);
    const out = [];
    for (let i = 0; i < n; i++) out.push(sq[rows[i] * 5 + cols[i]]);
    return out.join('');
  }, { text: true });
