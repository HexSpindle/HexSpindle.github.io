import { module } from './_cat.js';
import { A } from '../../core/registry.js';
import { DELIMS, delim } from '../../core/util.js';

export const MORSE = { A: '.-', B: '-...', C: '-.-.', D: '-..', E: '.', F: '..-.', G: '--.', H: '....', I: '..',
  J: '.---', K: '-.-', L: '.-..', M: '--', N: '-.', O: '---', P: '.--.', Q: '--.-', R: '.-.',
  S: '...', T: '-', U: '..-', V: '...-', W: '.--', X: '-..-', Y: '-.--', Z: '--..',
  1: '.----', 2: '..---', 3: '...--', 4: '....-', 5: '.....', 6: '-....', 7: '--...',
  8: '---..', 9: '----.', 0: '-----', '.': '.-.-.-', ',': '--..--', ':': '---...', '?': '..--..',
  "'": '.----.', '-': '-....-', '/': '-..-.', '(': '-.--.', ')': '-.--.-', '"': '.-..-.', '@': '.--.-.',
  '=': '-...-', '!': '-.-.--', '&': '.-...', ';': '-.-.-.', '+': '.-.-.', _: '..--.-', $: '...-..-' };

module('To Morse Code', 'Translates text into International Morse Code.', [A.select('Format options', ['-/.', '_/.']), A.select('Letter delimiter', DELIMS), A.select('Word delimiter', [...DELIMS, 'Forward slash'], 'Forward slash')],
  (t, fmt, ld, wd) => {
    const [dash] = fmt === '-/.' ? ['-'] : ['_'];
    const words = t.toUpperCase().split(' ').map(w => [...w].filter(c => c in MORSE).map(c => MORSE[c].replace(/-/g, dash)).join(delim(ld)));
    return words.join(delim(wd));
  }, { text: true });
