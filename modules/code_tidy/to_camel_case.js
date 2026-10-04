import { module } from './_cat.js';
import { A } from '../../core/registry.js';

module('To Camel case', 'Converts identifiers to camelCase (or PascalCase).', [A.boolean('Upper camel case (PascalCase)', false)],
  (t, pascal) => {
    const words = t.split(/[\s_\-]+|(?=[A-Z][a-z])/).filter(Boolean);
    return words.map((w, i) => (i === 0 && !pascal) ? w.toLowerCase() : w[0].toUpperCase() + w.slice(1).toLowerCase()).join('');
  }, { text: true });
