import { module } from './_cat.js';
import { A } from '../../core/registry.js';

function parseIntAuto(s) {
  s = s.trim();
  const neg = s[0] === '-';
  if (neg || s[0] === '+') s = s.slice(1);
  const v = BigInt(s);
  return neg ? -v : v;
}

function egcd(a, b) {
  if (b === 0n) return [a, 1n, 0n];
  const [g, x1, y1] = egcd(b, a % b);
  return [g, y1, x1 - (a / b) * y1];
}

module('Extended GCD', 'Computes gcd(A, B) and the Bézout coefficients X, Y such that A*X + B*Y = gcd(A, B).', [A.string('A', '240'), A.string('B', '46')],
  (t, aS, bS) => {
    const a = parseIntAuto(aS), b = parseIntAuto(bS);
    const [g, x, y] = egcd(a, b);
    return `gcd(${a}, ${b}) = ${g}\n${a} * (${x}) + ${b} * (${y}) = ${g}`;
  }, { text: true });
