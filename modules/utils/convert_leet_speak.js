import { module } from './_cat.js';
import { A } from '../../core/registry.js';

const L = { a: '4', e: '3', i: '1', o: '0', s: '5', t: '7', l: '1', g: '9', b: '8', z: '2' };
const R = { '4': 'a', '3': 'e', '1': 'i', '0': 'o', '5': 's', '7': 't', '9': 'g', '8': 'b', '2': 'z', '@': 'a', $: 's', '!': 'i' };

module('Convert Leet Speak', 'Converts text to or from leet speak.', [A.select('Direction', ['To Leet Speak', 'From Leet Speak'])],
  (t, d) => {
    const m = d.startsWith('To') ? L : R;
    return [...t].map(c => m[c.toLowerCase()] ?? c).join('');
  }, { text: true });
