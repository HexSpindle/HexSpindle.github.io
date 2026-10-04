import { module } from './_cat.js';
import { A } from '../../core/registry.js';

const STD = 'ABCDEFGHIKLMNOPQRSTUWXYZ';
const COMPLETE = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
const ALPHABETS = ['Standard (I=J and U=V)', 'Complete'];

function table(alpha, tr) {
  const a = alpha.startsWith('Standard') ? STD : COMPLETE;
  const sym = tr === '0/1' ? ['0', '1'] : ['A', 'B'];
  const tb = {};
  for (let i = 0; i < a.length; i++) {
    const bits = i.toString(2).padStart(5, '0');
    tb[a[i]] = [...bits].map(b => b === '0' ? sym[0] : sym[1]).join('');
  }
  return tb;
}

module('Bacon Cipher Encode', 'Encodes letters as 5-bit groups of A/B (or 0/1).',
  [A.select('Alphabet', ALPHABETS), A.select('Translation', ['0/1', 'A/B']), A.boolean('Invert translation', false)],
  (t, alpha, tr, invert) => {
    let tb = table(alpha, tr);
    if (invert) {
      const [a, b] = tr === '0/1' ? ['0', '1'] : ['A', 'B'];
      const swap = s => [...s].map(c => c === a ? b : c === b ? a : c).join('');
      tb = Object.fromEntries(Object.entries(tb).map(([k, v]) => [k, swap(v)]));
    }
    const out = [];
    for (let c of t.toUpperCase()) {
      if (alpha.startsWith('Standard')) c = { J: 'I', V: 'U' }[c] ?? c;
      out.push(c in tb ? tb[c] : c);
    }
    return out.join('');
  }, { text: true });

export { table, ALPHABETS };
