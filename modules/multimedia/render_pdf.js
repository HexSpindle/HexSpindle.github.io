import { module } from './_cat.js';
import { A, Html } from '../../core/registry.js';
import { base64Encode, base64Decode, parseHex, decodeLatin1 } from '../../core/util.js';

// CyberChef's own "Render PDF" does not actually parse or rasterise the PDF itself - it checks for
// the "%PDF-" signature and then hands the raw bytes to the browser as a data: URI inside an
// <iframe>, relying on the browser's own built-in PDF viewer (which every major browser has had for
// years) to render the pages. That's a genuinely good, zero-dependency solution - modern native PDF
// viewers are mature full-page renderers in their own right - so this mirrors that approach rather
// than vendoring a separate PDF.js build to reimplement what the browser already does natively.
module('Render PDF', "Displays a PDF's pages using the browser's built-in PDF viewer.",
  [A.select('Input format', ['Raw', 'Base64', 'Hex'])],
  (data, fmt) => {
    if (fmt === 'Base64') data = base64Decode(decodeLatin1(data));
    else if (fmt === 'Hex') data = parseHex(decodeLatin1(data));
    if (decodeLatin1(data.subarray(0, 5)) !== '%PDF-') throw new Error('Input does not appear to be a PDF file.');
    const b64 = base64Encode(data);
    return new Html(`<iframe title="PDF preview" src="data:application/pdf;base64,${b64}" style="width:100%;height:80vh;border:1px solid #8884;background:#fff"></iframe>`);
  }
);
