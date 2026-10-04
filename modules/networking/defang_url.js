import { module } from './_cat.js';

module('Defang URL', 'Makes a URL safe to paste in a report (hxxp, [.] etc).', [],
  (t) => t.replace(/http/gi, 'hxxp').replace(/\./g, '[.]'), { text: true });
