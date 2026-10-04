import { module } from './_cat.js';
import { A } from '../../core/registry.js';

module('Caesar Box Cipher', 'Writes the text in rows of the given box size and reads it by columns.', [A.number('Box height', 1, 1)],
  (t, h) => {
    const w = Math.ceil(t.length / h);
    const padded = t.padEnd(w * h, ' ');
    if (h <= 1) return padded.replace(/\s+$/, '');
    let out = '';
    for (let c = 0; c < w; c++) for (let r = 0; r < h; r++) out += padded[r * w + c];
    return out.replace(/\s+$/, '');
  }, { text: true });
