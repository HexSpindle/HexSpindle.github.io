import { module } from './_cat.js';
import { A } from '../../core/registry.js';

module('To Hex Content', 'Converts special characters to Snort/Suricata-style |hex| content.',
  [A.select('Convert', ['Only special chars', 'Only special chars including spaces', 'All chars'])],
  (data, mode) => {
    const special = (b) => {
      if (mode === 'All chars') return true;
      if (b === 32) return mode.endsWith('spaces');
      return !(b > 32 && b < 127) || '|\\'.includes(String.fromCharCode(b));
    };
    const out = [];
    let run = [];
    for (const b of data) {
      if (special(b)) {
        run.push(b.toString(16).padStart(2, '0'));
      } else {
        if (run.length) { out.push('|' + run.join(' ') + '|'); run = []; }
        out.push(String.fromCharCode(b));
      }
    }
    if (run.length) out.push('|' + run.join(' ') + '|');
    return out.join('');
  });
