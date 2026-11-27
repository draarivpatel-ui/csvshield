import test from 'node:test';
import assert from 'node:assert/strict';
import fc from 'fast-check';
import { findCsvTriggers, parseSafeCsv, sanitizeCell, stringifySafeCsv } from '../src/index.mjs';

const SAFE_TEXT_ALPHABET = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 .,?_';
const triggerArbitrary = fc.constantFrom('=', '+', '-', '@', '\t', '|');
const tailArbitrary = fc.string({
  unit: fc.constantFrom(...SAFE_TEXT_ALPHABET),
  maxLength: 60,
}).map((value) => value + 'x');

test('formula-prefixed cells are always neutralized', () => {
  fc.assert(
    fc.property(triggerArbitrary, tailArbitrary, (trigger, tail) => {
      const cell = trigger + tail;
      assert.equal(sanitizeCell(cell), "'" + cell);
      assert.ok(findCsvTriggers(cell).length > 0);
    }),
    { seed: 20261127, numRuns: 200, endOnFailure: true },
  );
});

test('formulas embedded after arbitrary line breaks are always neutralized', () => {
  const safeNoise = fc.string({ unit: fc.constantFrom(...'abcXYZ019'), maxLength: 32 });
  const separator = fc.constantFrom('\n', '\r', '\r\n');
  fc.assert(
    fc.property(safeNoise, separator, triggerArbitrary, tailArbitrary, (noise, lineBreak, trigger, tail) => {
      const cell = noise + lineBreak + trigger + tail;
      assert.equal(sanitizeCell(cell), noise + lineBreak + "'" + trigger + tail);
      assert.ok(findCsvTriggers(cell).length > 0);
    }),
    { seed: 20261128, numRuns: 200, endOnFailure: true },
  );
});

test('sanitizing arbitrary strings is deterministic and idempotent', () => {
  fc.assert(
    fc.property(fc.string({ maxLength: 160 }), (value) => {
      const once = sanitizeCell(value);
      assert.equal(typeof once, 'string');
      assert.equal(sanitizeCell(once), once);
      assert.equal(sanitizeCell(value), once);
    }),
    { seed: 20261129, numRuns: 200, endOnFailure: true },
  );
});

test('stringified rows keep every generated formula cell neutralized', () => {
  fc.assert(
    fc.property(triggerArbitrary, tailArbitrary, (trigger, tail) => {
      const cell = trigger + tail;
      const csv = stringifySafeCsv([[cell]]);
      assert.deepEqual(parseSafeCsv(csv), [["'" + cell]]);
    }),
    { seed: 20261130, numRuns: 150, endOnFailure: true },
  );
});
