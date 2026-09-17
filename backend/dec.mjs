import fs from 'fs'; import { PNG } from 'pngjs';
const jsQR = (await import('/tmp/jsqrpack/package/dist/jsQR.js')).default;
const png = PNG.sync.read(fs.readFileSync('/tmp/jsqrpack/acct.png'));
const r = jsQR(new Uint8ClampedArray(png.data), png.width, png.height);
console.log(r ? 'DECODED: '+r.data : 'DECODE FAILED');
