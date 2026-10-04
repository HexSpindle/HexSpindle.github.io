import { module } from './_cat.js';
import { A } from '../../core/registry.js';

function unescape(s) { return s.replace(/\\n/g, '\n').replace(/\\t/g, '\t').replace(/\\r/g, '\r'); }

function* combinations(items, r) {
  const n = items.length;
  if (r > n) return;
  const idx = Array.from({ length: r }, (_, i) => i);
  yield idx.map(i => items[i]);
  while (true) {
    let i = r - 1;
    while (i >= 0 && idx[i] === i + n - r) i--;
    if (i < 0) return;
    idx[i]++;
    for (let j = i + 1; j < r; j++) idx[j] = idx[j - 1] + 1;
    yield idx.map(k => items[k]);
  }
}

module('Power Set', 'All subsets of a set.', [A.string('Item delimiter', ',')],
  (t, idl) => {
    idl = unescape(idl);
    const items = t.split(idl);
    const out = [];
    for (let r = 0; r <= items.length; r++) for (const c of combinations(items, r)) out.push(c.join(idl));
    return out.join('\n');
  }, { text: true });
