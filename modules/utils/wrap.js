import { module } from './_cat.js';
import { A } from '../../core/registry.js';

// Matches CyberChef's Wrap exactly: a simple fixed-character-count wrap (no word-boundary
// awareness), implemented with the same `.{1,width}` greedy regex. Since `.` never matches a
// line terminator, any existing newlines in the input are silently swallowed by the regex scan
// (they don't start a match and aren't included in one) and every chunk is rejoined with a single
// "\n" - so pre-existing line breaks collapse away rather than being preserved. That is upstream's
// actual (slightly surprising) behaviour, not a port bug.
module('Wrap', "Wraps the input text at a specified number of characters per line, splitting purely by character count (not at word boundaries). Existing line breaks are not preserved - matches CyberChef's Wrap, including that quirk.",
  [A.number('Line width', 64, 1, 65536)],
  (t, width) => {
    if (!t) return '';
    const chunks = t.match(new RegExp(`.{1,${width}}`, 'g'));
    return chunks ? chunks.join('\n') : '';
  }, { text: true });
