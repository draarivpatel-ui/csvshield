/** RFC 4180 parsing, header defense and DoS bound tests. */
import test from 'node:test';
import assert from 'node:assert/strict';
import { parseSafeCsv, inspectCsv, CsvShieldError } from '../src/index.mjs';

test('parses a simple RFC 4180 document', () => {
  assert.deepEqual(parseSafeCsv('a,b\n1,2\n3,4\n'), [['a', 'b'], ['1', '2'], ['3', '4']]);
});

test('supports both CRLF and LF line endings and a missing final newline', () => {
  assert.deepEqual(parseSafeCsv('a,b\r\n1,2\r\n'), [['a', 'b'], ['1', '2']]);
  assert.deepEqual(parseSafeCsv('a,b\n1,2'), [['a', 'b'], ['1', '2']]);
});

test('respects quoted fields, escaped quotes and embedded newlines', () => {
  const input = 'name,note\r\n"Doe, Jane","line1\nline2"\r\n"a""b",plain\r\n';
  assert.deepEqual(parseSafeCsv(input, { sanitize: false }), [
    ['name', 'note'],
    ['Doe, Jane', 'line1\nline2'],
    ['a"b', 'plain'],
  ]);
});

test('allows custom delimiters including TSV', () => {
  assert.deepEqual(parseSafeCsv('a\tb\n1\t2\n', { delimiter: '\t' }), [['a', 'b'], ['1', '2']]);
  assert.deepEqual(parseSafeCsv('a;b\n1;2\n', { delimiter: ';' }), [['a', 'b'], ['1', '2']]);
});

test('hasHeader emits null-prototype records with sanitized values', () => {
  const records = parseSafeCsv('name,formula\nAlice,=1+1\n', { hasHeader: true });
  assert.equal(records.length, 1);
  assert.equal(Object.getPrototypeOf(records[0]), null);
  assert.deepEqual({ ...records[0] }, { name: 'Alice', formula: "'=1+1" });
});

test('header formulas are sanitized before use as object keys', () => {
  const records = parseSafeCsv('=evil,b\n1,2\n', { hasHeader: true });
  assert.deepEqual({ ...records[0] }, { "'=evil": '1', b: '2' });
});

test('prototype-pollution headers throw by default', () => {
  for (const header of ['__proto__', 'constructor', 'prototype']) {
    assert.throws(
      () => parseSafeCsv(`${header},b\n1,2\n`, { hasHeader: true }),
      (e) => e instanceof CsvShieldError && e.code === 'ERR_CSV_PROTOTYPE',
      header,
    );
  }
});

test('onDangerousHeader skip removes dangerous columns but keeps data safe', () => {
  const records = parseSafeCsv('__proto__,constructor,b\n1,2,3\n', { hasHeader: true, onDangerousHeader: 'skip' });
  assert.deepEqual(records.map((r) => ({ ...r })), [{ b: '3' }]);
  assert.equal(Object.getPrototypeOf(records[0]), null);
  assert.equal({}.polluted, undefined);
});

test('onDangerousHeader prefix renames dangerous columns', () => {
  const records = parseSafeCsv('__proto__,b\n1,2\n', { hasHeader: true, onDangerousHeader: 'prefix' });
  assert.deepEqual(records.map((r) => ({ ...r })), [{ "'__proto__": '1', b: '2' }]);
  assert.equal(Object.getPrototypeOf(records[0]), null);
});

test('duplicate headers obey last, first, skip and throw policies', () => {
  const input = 'a,b,a\n1,2,3\n';
  const plain = (records) => records.map((r) => ({ ...r }));
  assert.deepEqual(plain(parseSafeCsv(input, { hasHeader: true })), [{ a: '3', b: '2' }]);
  assert.deepEqual(plain(parseSafeCsv(input, { hasHeader: true, onDuplicateHeader: 'first' })), [{ a: '1', b: '2' }]);
  assert.deepEqual(plain(parseSafeCsv(input, { hasHeader: true, onDuplicateHeader: 'skip' })), [{ a: '1', b: '2' }]);
  assert.throws(() => parseSafeCsv(input, { hasHeader: true, onDuplicateHeader: 'throw' }), (e) => e.code === 'ERR_CSV_HEADER');
});

test('last duplicate header policy preserves interleaved unrelated columns', () => {
  const plain = (records) => records.map((r) => ({ ...r }));
  assert.deepEqual(plain(parseSafeCsv('a,a,a\n1,2,3\n', { hasHeader: true, onDuplicateHeader: 'last' })), [{ a: '3' }]);
  assert.deepEqual(plain(parseSafeCsv('a,a,b,a\n1,2,3,4\n', { hasHeader: true, onDuplicateHeader: 'last' })), [{ a: '4', b: '3' }]);
  assert.deepEqual(plain(parseSafeCsv('a,b,a,b,a\n1,2,3,4,5\n', { hasHeader: true, onDuplicateHeader: 'last' })), [{ a: '5', b: '4' }]);
});

test('strictColumns rejects ragged rows only when enabled', () => {
  assert.deepEqual(parseSafeCsv('a,b\n1\n', { hasHeader: true }).map((r) => ({ ...r })), [{ a: '1' }]);
  assert.throws(() => parseSafeCsv('a,b\n1\n', { hasHeader: true, strictColumns: true }), (e) => e.code === 'ERR_CSV_COLUMNS');
});

test('skipEmptyLines removes blank rows', () => {
  assert.deepEqual(parseSafeCsv('a,b\n\n1,2\n\n', { skipEmptyLines: true }), [['a', 'b'], ['1', '2']]);
  assert.deepEqual(parseSafeCsv('a,b\n\n1,2\n\n'), [['a', 'b'], [''], ['1', '2'], ['']]);
});

test('relaxed mode tolerates whitespace after a closing quote', () => {
  assert.throws(() => parseSafeCsv('"a" b,c\n'), (e) => e.code === 'ERR_CSV_PARSE');
  assert.deepEqual(parseSafeCsv('"a" ,b\n', { relaxed: true }), [['a', 'b']]);
});

test('malformed CSV produces ERR_CSV_PARSE', () => {
  for (const input of ['"unterminated', 'a"b,c\n', '"a"x,b\n']) {
    assert.throws(() => parseSafeCsv(input), (e) => e.code === 'ERR_CSV_PARSE', input);
  }
});

test('UTF-8 BOM is stripped by default and can be retained', () => {
  assert.deepEqual(parseSafeCsv('﻿a,b\n1,2\n'), [['a', 'b'], ['1', '2']]);
  assert.deepEqual(parseSafeCsv('﻿a,b\n1,2\n', { stripBom: false }), [['﻿a', 'b'], ['1', '2']]);
});

test('Uint8Array input is decoded with strict UTF-8 validation', () => {
  const bytes = new TextEncoder().encode('a,b\n=1,2\n');
  assert.deepEqual(parseSafeCsv(bytes), [['a', 'b'], ["'=1", '2']]);
  assert.throws(() => parseSafeCsv(new Uint8Array([0xc3, 0x28])), (e) => e.code === 'ERR_CSV_ENCODING');
  assert.throws(() => parseSafeCsv(123), (e) => e.code === 'ERR_CSV_OPTION');
});

test('empty input returns an empty matrix or empty record list', () => {
  assert.deepEqual(parseSafeCsv(''), []);
  assert.deepEqual(parseSafeCsv('', { hasHeader: true }), []);
});

test('reject mode reports row, column and header context', () => {
  assert.throws(
    () => parseSafeCsv('name,formula\nAlice,=1\n', { hasHeader: true, mode: 'reject' }),
    (e) => e.code === 'ERR_CSV_FORMULA' && e.row === 2 && e.col === 2 && e.header === 'formula',
  );
});

test('DoS bounds: maxRows, maxColumns, maxCellBytes and maxTotalBytes', () => {
  assert.throws(() => parseSafeCsv('1\n2\n3\n', { maxRows: 2 }), (e) => e.code === 'ERR_CSV_LIMIT' && e.limit === 'maxRows');
  assert.throws(() => parseSafeCsv('a,b,c\n1,2,3\n', { maxColumns: 2 }), (e) => e.code === 'ERR_CSV_LIMIT' && e.limit === 'maxColumns');
  assert.throws(() => parseSafeCsv('abcdef\n', { maxCellBytes: 3 }), (e) => e.code === 'ERR_CSV_LIMIT' && e.limit === 'maxCellBytes');
  assert.throws(() => parseSafeCsv('abcdef\n', { maxTotalBytes: 3 }), (e) => e.code === 'ERR_CSV_LIMIT' && e.limit === 'maxTotalBytes');
});

test('DoS bounds count UTF-8 bytes rather than code units', () => {
  assert.throws(() => parseSafeCsv('éé\n', { maxCellBytes: 3 }), (e) => e.limit === 'maxCellBytes');
});

test('large valid input inside bounds parses successfully', () => {
  const rows = Array.from({ length: 1000 }, (_, i) => `row${i},value${i}`).join('\n');
  assert.equal(parseSafeCsv(rows).length, 1000);
});

test('inspectCsv reports formula and prototype-pollution findings without mutating cells', () => {
  const report = inspectCsv('__proto__,formula\n1,=cmd|calc\n', { hasHeader: true });
  assert.equal(report.safe, false);
  assert.equal(report.findings.length, 2);
  assert.equal(report.findings[0].rule, 'prototype-pollution');
  assert.equal(report.findings[1].rule, 'leading-trigger');
  assert.equal(report.findings[1].header, 'formula');
  assert.equal(report.findings[1].row, 2);
  assert.equal(report.findings[1].col, 2);
});

test('inspectCsv reports safe documents as safe', () => {
  assert.deepEqual(inspectCsv('a,b\n1,2\n'), { safe: true, findings: [] });
});

test('inspectCsv reports formula triggers in header cells', () => {
  const leading = inspectCsv('=evil,b\n1,2\n', { hasHeader: true });
  assert.equal(leading.safe, false);
  assert.equal(leading.findings.length, 1);
  assert.equal(leading.findings[0].row, 1);
  assert.equal(leading.findings[0].col, 1);
  assert.equal(leading.findings[0].rule, 'leading-trigger');
  const obfuscated = inspectCsv('​=evil,b\n1,2\n', { hasHeader: true });
  assert.equal(obfuscated.findings[0].rule, 'obfuscated-trigger');
  const embedded = inspectCsv('"ok\n=evil",b\n1,2\n', { hasHeader: true });
  assert.equal(embedded.findings[0].rule, 'embedded-formula');
  assert.equal(embedded.findings[0].row, 1);
});

test('inspectCsv respects DoS limits and header modes', () => {
  assert.throws(() => inspectCsv('1\n2\n3\n', { maxRows: 2 }), (e) => e.code === 'ERR_CSV_LIMIT');
  const report = inspectCsv('__proto__\n=1\n', { onDangerousHeader: 'skip' });
  assert.equal(report.safe, false);
  assert.equal(report.findings.length, 1);
});

test('sanitize:false disables neutralization for advanced callers', () => {
  assert.deepEqual(parseSafeCsv('a,b\n=1,2\n', { sanitize: false }), [['a', 'b'], ['=1', '2']]);
});

test('parse error details carry the byte index', () => {
  assert.throws(() => parseSafeCsv('a"b\n'), (e) => e.code === 'ERR_CSV_PARSE' && typeof e.value === 'number');
});
