import { module } from './_cat.js';
import { A } from '../../core/registry.js';

// In CyberChef, "HTML To Text" itself is a no-op; the actual HTML -> text conversion happens
// implicitly whenever an "html"-typed dish is read as a string, via DishHTML -> Utils.stripHtmlTags
// (removing <script>/<style> blocks and all other tags with regexes, recursively so e.g.
// "<<b>script>" can't survive a single pass) followed by Utils.unescapeHtml (which only
// unescapes &amp; &lt; &gt; &quot; &#x27; &#x2F; &#x60; - a small fixed table, not every named
// entity). We reproduce that exact pipeline directly rather than using DOMParser: a DOM-based
// textContent walk would decode *every* entity (&nbsp;, &copy;, ...) and would need invented
// rules for which elements become newlines, since CyberChef's real algorithm has neither - it is
// a plain regex strip. Matching that regex behaviour (including its quirks, like &nbsp; staying
// literal) is "the actual behaviour" this op is meant to port.
function recursiveRemove(pattern, str) {
  const next = str.replace(pattern, '');
  return next.length === str.length ? next : recursiveRemove(pattern, next);
}

const HTML_CHARS = { '&amp;': '&', '&lt;': '<', '&gt;': '>', '&quot;': '"', '&#x27;': "'", '&#x2F;': '/', '&#x60;': '`' };

module('HTML To Text', 'Strips HTML tags (removing <script>/<style> blocks entirely) and unescapes the small set of HTML entities CyberChef recognises, approximating the page as plain text.',
  [],
  t => {
    let s = recursiveRemove(/<script[^>]*>[\s\S]*?<\/script[^>]*>/gi, t);
    s = recursiveRemove(/<style[^>]*>[\s\S]*?<\/style[^>]*>/gi, s);
    s = recursiveRemove(/<[^>]+>/g, s);
    return s.replace(/&#?x?[a-z0-9]{2,4};/gi, m => HTML_CHARS[m] || m);
  }, { text: true });
