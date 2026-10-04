import { module } from './_cat.js';

module('To Kebab case', 'Converts identifiers to kebab-case.', [],
  (t) => t.replace(/([a-z0-9])([A-Z])/g, '$1-$2').replace(/[\s_]+/g, '-').toLowerCase(), { text: true });
