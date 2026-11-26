/** OWASP / CWE-1236 formula-injection neutralization tests for sanitizeCell. */
import test from 'node:test';
import assert from 'node:assert/strict';
import { sanitizeCell, stringifySafeCsv, findCsvTriggers, isSafeNegativeNumberValue } from '../src/index.mjs';

const PREFIX = "'";

function neutralized(value, options) {
  const out = sanitizeCell(value, options);
  assert.equal(out[0], PREFIX, `expected prefix for ${JSON.stringify(value)}`);
  return out;
}

test('all eight OWASP leading triggers are prefixed (CR and LF open a new line)', () => {
  for (const trigger of ['=', '+', '-', '@', '\t', '|']) {
    assert.equal(sanitizeCell(`${trigger}SUM(1+1)`), `${PREFIX}${trigger}SUM(1+1)`, trigger);
  }
  assert.equal(sanitizeCell('\rSUM(1+1)'), '\rSUM(1+1)');
  assert.equal(sanitizeCell('\nSUM(1+1)'), '\nSUM(1+1)');
  assert.equal(sanitizeCell('\r=SUM(1+1)'), `\r${PREFIX}=SUM(1+1)`);
  assert.equal(sanitizeCell('\n=SUM(1+1)'), `\n${PREFIX}=SUM(1+1)`);
});

test('Excel and Google Sheets formula forms are neutralized', () => {
  const vectors = [
    '=1+1',
    '=SUM(A1:A10)',
    '=HYPERLINK("http://example.test","click")',
    '=IMPORTXML("http://example.test","//a")',
    '=WEBSERVICE("http://example.test")',
    '+SUM(1)',
    '-SUM(1)',
    '@SUM(1)',
    '=DDE("cmd";"/c calc";"A0")',
    '=cmd|\'/c calc\'!A0',
    '|calc',
  ];
  for (const vector of vectors) assert.equal(sanitizeCell(vector), `${PREFIX}${vector}`, vector);
});

test('leading whitespace and control-character obfuscation is detected', () => {
  const wrappers = [' ', '   ', ' ', ' ', ' ', '​', ' ', '‮', '⁦', '　', '﻿', '͏', '؜', '᠎', 'ㅤ', '­', '\u0000', '\u001f', '\u007f'];
  for (const wrapper of wrappers) {
    const value = `${wrapper}=1`;
    assert.equal(sanitizeCell(value), `${PREFIX}${value}`, `wrapper ${wrapper.codePointAt(0).toString(16)}`);
    assert.equal(findCsvTriggers(value)[0].rule, 'obfuscated-trigger', wrapper);
  }
  for (const wrapper of ['\r', '\n']) {
    const value = `${wrapper}=1`;
    assert.equal(sanitizeCell(value), `${wrapper}${PREFIX}=1`, wrapper);
    assert.equal(findCsvTriggers(value)[0].rule, 'embedded-formula', wrapper);
  }
});

test('BOM-prefixed formulas cannot bypass the leading-trigger check', () => {
  assert.equal(sanitizeCell('﻿=1'), `${PREFIX}﻿=1`);
  assert.equal(sanitizeCell('﻿﻿+1'), `${PREFIX}﻿﻿+1`);
});

test('zero-width and bidirectional control obfuscation cannot bypass the check', () => {
  for (const invisible of ['​', '‌', '‍', '‎', '‏', '‪', '‬', '‮', '⁦', '⁩', '﻿']) {
    assert.equal(sanitizeCell(`${invisible}@1`), `${PREFIX}${invisible}@1`, invisible);
  }
});

test('CR and LF embedded in a cell are treated as separate formula lines', () => {
  for (const separator of ['\n', '\r', '\r\n']) {
    const value = `safe${separator}=cmd|'/c calc'!A0`;
    const out = sanitizeCell(value);
    assert.equal(out, `safe${separator}${PREFIX}=cmd|'/c calc'!A0`, separator);
    assert.equal(findCsvTriggers(value)[0].rule, 'embedded-formula', separator);
  }
});

test('every line in a multiline cell is neutralized independently', () => {
  const value = '=one\n=two\r=three\r\n+four';
  const out = sanitizeCell(value);
  assert.equal(out, `${PREFIX}=one\n${PREFIX}=two\r${PREFIX}=three\r\n${PREFIX}+four`);
  assert.equal(findCsvTriggers(value).length, 4);
});

test('strip mode removes leading obfuscation and trigger characters', () => {
  assert.equal(sanitizeCell('=1', { mode: 'strip' }), '1');
  assert.equal(sanitizeCell('   =1', { mode: 'strip' }), '1');
  assert.equal(sanitizeCell('﻿=1', { mode: 'strip' }), '1');
  assert.equal(sanitizeCell('@@@1', { mode: 'strip' }), '1');
  assert.equal(sanitizeCell('ok\n=1', { mode: 'strip' }), 'ok\n1');
  assert.equal(sanitizeCell('=1\n=2', { mode: 'strip' }), '1\n2');
});

test('reject mode throws a structured CsvShieldError', () => {
  for (const value of ['=1', '\t@1', 'ok\r\n|1']) {
    assert.throws(
      () => sanitizeCell(value, { mode: 'reject' }),
      (error) => {
        assert.equal(error.name, 'CsvShieldError');
        assert.equal(error.code, 'ERR_CSV_FORMULA');
        assert.equal(error.trigger.length, 1);
        assert.ok(error.rule);
        assert.ok(typeof error.preview === 'string');
        assert.equal(typeof error.toJSON().code, 'string');
        return true;
      },
    );
  }
});

test('custom prefix and mode combination works', () => {
  assert.equal(sanitizeCell('=1', { prefix: 'safe:' }), 'safe:=1');
  assert.equal(sanitizeCell('\t=1', { prefix: '[x]' }), '[x]\t=1');
});

test('unsafe prefixes are rejected so neutralization cannot re-arm a trigger', () => {
  for (const prefix of ['=', '+', '-', '@', '|', '\t', '\r', '\n', ' ', ' ', '​']) {
    assert.throws(() => sanitizeCell('=1', { prefix }), (e) => e.code === 'ERR_CSV_OPTION', JSON.stringify(prefix));
    assert.throws(() => stringifySafeCsv([['=1']], { prefix }), (e) => e.code === 'ERR_CSV_OPTION', JSON.stringify(prefix));
  }
});

test('invisible filler and formatter characters cannot hide a leading trigger', () => {
  for (const wrapper of ['\u000b', '\u000c', '⁡', '⁤', 'ᅠ']) {
    assert.equal(sanitizeCell(`${wrapper}=1`), `${PREFIX}${wrapper}=1`, wrapper.codePointAt(0).toString(16));
    assert.equal(findCsvTriggers(`${wrapper}=1`)[0].rule, 'obfuscated-trigger');
  }
});

test('preserve-numbers keeps finite negative numbers but neutralizes -expressions', () => {
  const safe = ['-1', '-1.5', '-.5', '-1e3', '-1.2E-3', '-0.001'];
  for (const value of safe) {
    assert.equal(sanitizeCell(value, { mode: 'preserve-numbers' }), value, value);
    assert.equal(isSafeNegativeNumberValue(value), true, value);
  }
  const unsafe = ['-1+1', '-SUM(1)', '-1;2', '- 1', '-1abc', '-Infinity', '-NaN', '-1e', '--1'];
  for (const value of unsafe) {
    assert.equal(sanitizeCell(value, { mode: 'preserve-numbers' }), `${PREFIX}${value}`, value);
    assert.equal(isSafeNegativeNumberValue(value), false, value);
  }
});

test('preserveNumbers option enables safe negatives with another mode', () => {
  assert.equal(sanitizeCell('-42', { mode: 'prefix', preserveNumbers: true }), '-42');
  assert.equal(sanitizeCell('-42', { preserveNumbers: true }), '-42');
});

test('plain benign cells pass through untouched', () => {
  for (const value of ['Hello', 'Alice Smith', '123', '3.14', '2026-11-26', 'a,b', '', null, undefined, 42, true, false]) {
    assert.equal(sanitizeCell(value), value === null || value === undefined ? '' : String(value));
  }
});

test('findCsvTriggers reports rule, trigger and escaped preview', () => {
  assert.deepEqual(findCsvTriggers('=1'), [{ rule: 'leading-trigger', trigger: '=', preview: '=1' }]);
  assert.deepEqual(findCsvTriggers('\t@1'), [{ rule: 'leading-trigger', trigger: '\t', preview: '\\t@1' }]);
  assert.deepEqual(findCsvTriggers('ok\n-1'), [{ rule: 'embedded-formula', trigger: '-', preview: 'ok\\n-1' }]);
  assert.deepEqual(findCsvTriggers('safe'), []);
});

test('preview escapes control, BOM and invisible characters', () => {
  const found = findCsvTriggers('\u0000\u001f\u007f﻿=1');
  assert.equal(found[0].preview, '\\0\\u001f\\u007f\\ufeff=1');
  assert.equal(findCsvTriggers('\\\\=1').length, 0);
  assert.equal(findCsvTriggers(' '.repeat(47) + '=1')[0].preview.endsWith('...'), true);
});

test('invalid option shapes throw CsvShieldError with ERR_CSV_OPTION', () => {
  for (const options of [null, 1, 'prefix', [], { mode: 'unsafe' }, { prefix: '' }, { delimiter: '::' }, { delimiter: '"' }, { delimiter: '\r' }, { delimiter: '﻿' }, { maxRows: 0 }, { maxColumns: -1 }, { maxCellBytes: 1.5 }, { maxTotalBytes: Number.MAX_SAFE_INTEGER + 1 }, { onDangerousHeader: 'ignore' }, { onDuplicateHeader: 'merge' }]) {
    assert.throws(() => sanitizeCell('safe', options), (e) => e.code === 'ERR_CSV_OPTION', JSON.stringify(options));
  }
});

test('objects, arrays and functions are rejected as cell values', () => {
  for (const value of [{}, [], () => 1]) {
    assert.throws(() => sanitizeCell(value), (e) => e.code === 'ERR_CSV_OPTION');
  }
});

test('symbols are coerced safely', () => {
  assert.equal(sanitizeCell(Symbol('x')), 'Symbol(x)');
});

test('sanitization is deterministic and idempotent for prefix mode', () => {
  const value = '﻿=cmd|\'/c calc\'!A0\n+2';
  const once = sanitizeCell(value);
  assert.equal(sanitizeCell(once), once);
  for (let i = 0; i < 25; i++) assert.equal(sanitizeCell(value), once);
});
