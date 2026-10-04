import { module } from './_cat.js';

module('To Snake case', 'Converts identifiers to snake_case.', [],
  (t) => t.replace(/([a-z0-9])([A-Z])/g, '$1_$2').replace(/[\s\-]+/g, '_').toLowerCase(), { text: true });
