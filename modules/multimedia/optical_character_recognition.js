import { module } from './_cat.js';
import { A } from '../../core/registry.js';
import { detect } from '../../core/filetypes.js';
import { base64Encode } from '../../core/util.js';

// Unlike every other operation in this app, this one needs the network: it dynamically imports the
// small (~60KB) worker-management glue vendored as _tesseract.mjs (see that file's header), which
// then fetches the actual OCR engine - a multi-megabyte WebAssembly Tesseract core plus a 10MB+
// English trained-data file - from the jsdelivr CDN the first time it runs (the browser then caches
// them via IndexedDB, so repeat use is offline-ish, but the very first run per browser is not).
// Vendoring those pieces was judged impractical: they're large, there's one trained-data file per
// supported language, and they're version-locked to the exact tesseract.js build, so bundling them
// would bloat this otherwise fully offline, dependency-light app for a single operation. This is the
// same "practical middle ground" this app already uses for e.g. DNS over HTTPS (net: true).
const OEM_MODES = ['Tesseract only', 'LSTM only', 'Tesseract/LSTM combined'];
let tesseractPromise = null;
function getTesseract() {
  if (!tesseractPromise) tesseractPromise = import('./_tesseract.mjs').then((m) => m.default.createWorker);
  return tesseractPromise;
}

module('Optical Character Recognition',
  'Extracts text from an image using the Tesseract OCR engine (English only). Requires network access the first time it runs in a browser, to fetch the OCR engine and trained-data file from a CDN (see source comments) - everything else in this app runs fully offline.',
  [A.boolean('Show confidence', true), A.select('OCR engine mode', OEM_MODES, 'LSTM only')],
  async (data, showConfidence, oemChoice) => {
    const mime = (detect(data).map(([, , m]) => m).find((m) => m.startsWith('image/'))) || null;
    if (!mime) throw new Error('Input does not look like a supported image (png, jpg, bmp, pbm).');

    const createWorker = await getTesseract();
    const oem = OEM_MODES.indexOf(oemChoice);
    const image = `data:${mime};base64,${base64Encode(data)}`;
    const worker = await createWorker('eng', oem < 0 ? 1 : oem);
    try {
      const result = await worker.recognize(image);
      const text = result.data.text || '';
      if (showConfidence && typeof result.data.confidence === 'number') {
        return `Confidence: ${result.data.confidence}%\n\n${text}`;
      }
      return text;
    } finally {
      await worker.terminate();
    }
  },
  { net: true }
);
