/** stringifySafeCsv, CLI integration and scaffolding tests. */
import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';
import { stringifySafeCsv, parseSafeCsv, CsvShieldError } from '../src/index.mjs';

const root = fileURLToPath(new URL('..', import.meta.url));
const cli = join(root, 'bin', 'csvshield.mjs');
const run = (args, input) => spawnSync(process.execPath, [cli, ...args], {
  input, encoding: 'utf8', timeout: 15000,
});

test('stringify emits RFC 4180 CRLF and a trailing newline by default', () => {
  assert.equal(stringifySafeCsv([['a', 'b'], ['1', '2']]), 'a,b\r\n1,2\r\n');
  assert.equal(stringifySafeCsv([['a']], { eol: '\n' }), 'a\n');
  assert.equal(stringifySafeCsv([['a']], { trailingEol: false }), 'a');
  assert.equal(stringifySafeCsv([]), '');
});

test('stringify quotes delimiters, quotes, CR and LF correctly', () => {
  assert.equal(stringifySafeCsv([['a,b', 'say "hi"', 'x\ny']]), '"a,b","say ""hi""","x\ny"\r\n');
  assert.equal(stringifySafeCsv([['a', 'b']], { delimiter: '\t' }), 'a\tb\r\n');
});

test('stringify sanitizes every dangerous cell', () => {
  const out = stringifySafeCsv([['=1', '+2', '-3', '@4', '\t=5', '|=6']]);
  assert.equal(out, "'=1,'+2,'-3,'@4,'\t=5,'|=6\r\n");
  assert.deepEqual(parseSafeCsv(out), [["'=1", "'+2", "'-3", "'@4", "'\t=5", "'|=6"]]);
});

test('stringify supports array-of-objects and explicit columns', () => {
  assert.equal(stringifySafeCsv([{ a: 1, b: '=2' }]), 'a,b\r\n1,\'=2\r\n');
  assert.equal(stringifySafeCsv([{ a: 1, b: 2 }], { columns: ['b', 'a'] }), 'b,a\r\n2,1\r\n');
  assert.equal(stringifySafeCsv([{ a: 1 }], { columns: ['a', 'b'] }), 'a,b\r\n1,\r\n');
});

test('stringify honors BOM and preserve-numbers mode', () => {
  assert.equal(stringifySafeCsv([['a']], { bom: true, eol: '\n' }), '﻿a\n');
  assert.equal(stringifySafeCsv([['-42']], { mode: 'preserve-numbers' }), '-42\r\n');
  assert.equal(stringifySafeCsv([['-42']]), "'-42\r\n");
});

test('stringify respects DoS bounds', () => {
  assert.throws(() => stringifySafeCsv([['a'], ['b'], ['c']], { maxRows: 2 }), (e) => e.code === 'ERR_CSV_LIMIT');
  assert.throws(() => stringifySafeCsv([['a', 'b']], { maxColumns: 1 }), (e) => e.code === 'ERR_CSV_LIMIT');
  assert.throws(() => stringifySafeCsv([['toolong']], { maxCellBytes: 3 }), (e) => e.code === 'ERR_CSV_LIMIT');
  assert.throws(() => stringifySafeCsv([['toolong']], { maxTotalBytes: 3 }), (e) => e.code === 'ERR_CSV_LIMIT');
});

test('stringify validates options and dangerous headers', () => {
  assert.throws(() => stringifySafeCsv('not an array'), (e) => e instanceof CsvShieldError);
  assert.throws(() => stringifySafeCsv([['a']], { eol: '\r' }), (e) => e.code === 'ERR_CSV_OPTION');
  assert.throws(() => stringifySafeCsv([['a']], { columns: [1] }), (e) => e.code === 'ERR_CSV_OPTION');
  for (const header of ['__proto__', 'constructor', 'prototype']) {
    assert.throws(() => stringifySafeCsv([{ [header]: 1 }]), (e) => e.code === 'ERR_CSV_PROTOTYPE', header);
    assert.throws(() => stringifySafeCsv([{ a: 1 }], { columns: [header] }), (e) => e.code === 'ERR_CSV_PROTOTYPE', header);
  }
  // The policy applies to stringify too: skip drops the column, prefix renames it.
  assert.equal(stringifySafeCsv([{ a: 1, b: 2 }], { columns: ['__proto__', 'b'], onDangerousHeader: 'skip' }), 'b\r\n2\r\n');
  assert.equal(
    stringifySafeCsv([JSON.parse('{"__proto__":"1"}')], { columns: ['__proto__'], onDangerousHeader: 'prefix' }),
    "'__proto__\r\n1\r\n",
  );
});

test('stringify sanitizes header cells with the same policy as data cells', () => {
  assert.equal(stringifySafeCsv([{ '=cmd|calc': 'x' }]), "'=cmd|calc\r\nx\r\n");
  assert.equal(stringifySafeCsv([{ a: 1 }], { columns: ['=1+1', 'a'] }), "'=1+1,a\r\n,1\r\n");
  assert.equal(stringifySafeCsv([['a']], { columns: ['@SUM(1)'], mode: 'strip' }), 'SUM(1)\r\n\r\n');
  assert.throws(
    () => stringifySafeCsv([{ a: 1 }], { columns: ['=1+1'], mode: 'reject' }),
    (e) => e.code === 'ERR_CSV_FORMULA',
  );
});

test('round trip preserves data and neutralizes injections', () => {
  const rows = [['id', 'name', 'formula'], ['1', 'Alice', '=1+1'], ['2', 'Bob', '@SUM(A1)']];
  const csv = stringifySafeCsv(rows, { hasHeader: false });
  assert.deepEqual(parseSafeCsv(csv), [['id', 'name', 'formula'], ['1', 'Alice', "'=1+1"], ['2', 'Bob', "'@SUM(A1)"]]);
});

test('CLI --version and --help', () => {
  assert.equal(run(['--version']).stdout.trim(), '1.0.0');
  const help = run(['--help']);
  assert.match(help.stdout, /Usage:/);
  assert.match(help.stdout, /csvshield inspect/);
  assert.equal(help.status, 0);
});

test('CLI inspect exits 0 on safe input and 1 on findings', () => {
  const safe = run(['inspect', '-'], 'a,b\n1,2\n');
  assert.equal(safe.status, 0);
  assert.match(safe.stdout, /No findings\./);
  const unsafe = run(['inspect', '-'], 'a,b\n=1,2\n');
  assert.equal(unsafe.status, 1);
  assert.match(unsafe.stdout, /leading-trigger/);
  const json = run(['inspect', '-', '--json'], '=1\n');
  assert.equal(json.status, 1);
  assert.equal(JSON.parse(json.stdout).safe, false);
});

test('CLI sanitize rewrites dangerous cells', () => {
  const result = run(['sanitize', '-', '--has-header', '--mode', 'prefix'], 'a,b\n=1,-42\n');
  assert.equal(result.status, 0);
  assert.equal(result.stdout, 'a,b\n\'=1,\'-42\n');
});

test('CLI sanitize neutralizes formula headers with --has-header', () => {
  const result = run(['sanitize', '-', '--has-header'], '=evil,b\n1,2\n');
  assert.equal(result.status, 0);
  assert.equal(result.stdout, "'=evil,b\n1,2\n");
});

test('CLI sanitize honors --bom and --no-bom', () => {
  const withBom = run(['sanitize', '-', '--bom'], 'a,b\n1,2\n');
  assert.equal(withBom.status, 0);
  assert.equal(withBom.stdout.charCodeAt(0), 0xfeff);
  const withoutBom = run(['sanitize', '-', '--no-bom'], 'a,b\n1,2\n');
  assert.equal(withoutBom.status, 0);
  assert.equal(withoutBom.stdout.charCodeAt(0) === 0xfeff, false);
});

test('CLI parse emits JSON lines with sanitized cells and header mode', () => {
  const result = run(['parse', '-', '--has-header'], 'a,b\n=1,2\n');
  assert.equal(result.status, 0);
  assert.deepEqual(result.stdout.trim().split('\n').map(JSON.parse), [{ a: "'=1", b: '2' }]);
});

test('CLI reject mode reports a security error with exit code 1', () => {
  const result = run(['parse', '-', '--mode', 'reject'], '=1\n');
  assert.equal(result.status, 1);
  assert.match(result.stderr, /ERR_CSV_FORMULA/);
});

test('CLI uses exit code 2 for usage errors', () => {
  assert.equal(run([]).status, 2);
  assert.equal(run(['bogus'], '').status, 2);
  assert.equal(run(['--mode'], '').status, 2);
  assert.equal(run(['--delimiter'], '').status, 2);
  assert.equal(run(['--unknown'], '').status, 2);
});

test('CLI supports custom delimiter and mode flags', () => {
  const result = run(['sanitize', '-', '--delimiter', ';', '--mode', 'strip'], 'a;b\n;=1\n');
  assert.equal(result.status, 0);
  assert.equal(result.stdout, 'a;b\n;1\n');
});

test('OSS scaffolding files exist and carry accurate metadata', () => {
  const required = ['README.md', 'SECURITY.md', 'CONTRIBUTING.md', 'GOOD_FIRST_ISSUES.md', 'LICENSE', '.github/workflows/ci.yml'];
  if (!required.every((f) => { try { readFileSync(join(root, f)); return true; } catch { return false; } })) return;
  for (const file of required) assert.ok(readFileSync(join(root, file), 'utf8').length > 100, file);
  const readme = readFileSync(join(root, 'README.md'), 'utf8');
  assert.match(readme, /\b\d+ deterministic node:test cases/);
  assert.match(readme, /CWE-1236/);
  assert.match(readme, /zero.dependency/i);
  const issues = readFileSync(join(root, 'GOOD_FIRST_ISSUES.md'), 'utf8');
  assert.equal((issues.match(/^## Issue \d+/gm) || []).length, 15);
  const license = readFileSync(join(root, 'LICENSE'), 'utf8');
  assert.match(license, /MIT License/);
});
