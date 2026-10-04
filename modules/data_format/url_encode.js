import { module } from './_cat.js';
import { A } from '../../core/registry.js';

module('URL Encode', 'Percent-encodes special characters.', [A.boolean('Encode all special chars', false)],
  (t, everything) => {
    if (everything) return [...new TextEncoder().encode(t)].map(b => {
      const c = String.fromCharCode(b);
      return /[A-Za-z0-9\-_.~]/.test(c) ? c : '%' + b.toString(16).toUpperCase().padStart(2, '0');
    }).join('');
    return encodeURIComponent(t)
      .replace(/%2F/g, '/').replace(/%3F/g, '?').replace(/%23/g, '#').replace(/%3A/g, ':').replace(/%40/g, '@')
      .replace(/%26/g, '&').replace(/%3D/g, '=').replace(/%2B/g, '+').replace(/%24/g, '$').replace(/%2C/g, ',')
      .replace(/%5B/g, '[').replace(/%5D/g, ']').replace(/%3B/g, ';');
  }, { text: true });
