# @aarivbuildz/csvshield

Zero-dependency CSV and TSV security toolkit for Node.js. csvshield stops CWE-1236 spreadsheet formula injection and DDE payloads before a CSV ever reaches Excel, LibreOffice, Google Sheets or Numbers. Pure ECMAScript, no runtime dependencies, ESM plus CommonJS plus TypeScript declarations.

## Why

A cell beginning with `=`, `+`, `-`, `@`, a tab, a carriage return, a newline or a pipe can be interpreted as a formula by spreadsheet software. Attackers hide the trigger behind spaces, BOMs, zero-width characters, CR/LF smuggling or quote breaks. csvshield detects those variants and neutralizes them with a configurable policy.

## Install

```sh
npm install @aarivbuildz/csvshield
```

Requires Node.js 18 or newer. The package has no dependencies and no build step at install time.

## Quick start

```js
import { sanitizeCell, stringifySafeCsv, parseSafeCsv, inspectCsv } from '@aarivbuildz/csvshield';

sanitizeCell('=SUM(A1:A9)');        // "'=SUM(A1:A9)"
sanitizeCell('-42', { mode: 'preserve-numbers' }); // "-42"
stringifySafeCsv([{ name: 'Alice', formula: '@SUM(1)' }]);
// "name,formula\r\nAlice,'@SUM(1)\r\n"

parseSafeCsv('name,formula\nAlice,=1\n', { hasHeader: true });
// [{ name: 'Alice', formula: "'=1" }]  (null-prototype record)

inspectCsv('name,formula\nAlice,=1\n');
// { safe: false, findings: [{ row: 2, col: 2, header: 'formula', rule: 'leading-trigger', trigger: '=', preview: '=1' }] }
```

CommonJS:

```js
const { sanitizeCell } = require('@aarivbuildz/csvshield');
```

The `@aarivbuildz/csvshield/core` subpath exposes the same API without the package index re-export layer.

## API

| Function | Purpose |
| --- | --- |
| `sanitizeCell(value, options)` | Neutralize one cell by the selected policy. |
| `stringifySafeCsv(rows, options)` | Sanitize and serialize arrays, arrays of arrays or records to RFC 4180 CSV. |
| `parseSafeCsv(input, options)` | Strict RFC 4180 parse with per-cell sanitization and header defense. |
| `inspectCsv(input, options)` | Audit without modifying cells; returns `{ safe, findings }`. |
| `findCsvTriggers(value, options)` | List trigger findings with escaped previews. |
| `isSafeNegativeNumberValue(value)` | Check whether a value qualifies for the safe-negative exception. |
| `CsvShieldError` | Structured error with `code`, `row`, `col`, `header`, `rule`, `trigger`, `preview` and `toJSON()`. |

### Options

| Option | Default | Description |
| --- | --- | --- |
| `mode` | `'prefix'` | `prefix`, `strip`, `reject` or `preserve-numbers`. |
| `prefix` | `"'"` | Prefix inserted before a dangerous cell. |
| `preserveNumbers` | `false` | Allow finite negative numbers even in prefix mode. |
| `delimiter` | `','` | Single-character field delimiter. |
| `hasHeader` | `false` | Emit null-prototype objects keyed by the first row. |
| `sanitize` | `true` | Disable only for trusted, pre-sanitized input. |
| `onDangerousHeader` | `'throw'` | `throw`, `skip` or `prefix` for `__proto__`, `constructor`, `prototype`. |
| `onDuplicateHeader` | `'last'` | `last`, `first`, `skip` or `throw`. |
| `strictColumns` | `false` | Reject rows whose width differs from the header. |
| `skipEmptyLines`, `relaxed`, `stripBom` | `false`, `false`, `true` | Parser tolerance settings. |
| `eol`, `bom`, `trailingEol`, `columns` | `'\r\n'`, `false`, `true`, inferred | Stringifier settings. |
| `maxRows`, `maxColumns`, `maxCellBytes`, `maxTotalBytes` | 10000, 100, 100000, 5000000 | Deterministic DoS bounds (byte counts use UTF-8). |

## Threat model

csvshield covers the trigger prefixes documented by OWASP for CSV injection: `=`, `+`, `-`, `@`, tab, CR, LF and pipe. It also handles leading whitespace, Unicode spaces, BOMs, zero-width, bidirectional, invisible-filler and formatter controls, repeated triggers, embedded CR/LF smuggling and DDE-shaped payloads such as `=cmd|'/c calc'!A0`. `preserve-numbers` exempts only strict finite negative numeric literals. Object-mode records use `Object.create(null)`, header cells are sanitized by the same policy as data cells, dangerous header names are blocked, skipped or prefixed, and a custom `prefix` may not itself begin with a trigger or ignorable character. `inspectCsv` audits header cells as well as data cells. All inputs are bounded before parsing to prevent memory exhaustion.

Out of scope: URL safety inside hyperlink formulas that no longer begin with a trigger, spreadsheet settings that auto-execute non-prefixed content, and malicious file content that was never parsed by csvshield.

## CLI

```sh
csvshield inspect  [file]   # audit; exit 1 when findings exist (use - for stdin)
csvshield sanitize [file]   # re-emit a neutralized CSV
csvshield parse    [file]   # emit sanitized JSON lines
csvshield --help
csvshield --version
```

Flags: `--delimiter <char>`, `--mode <mode>`, `--has-header`, `--json`, `--bom`, `--no-bom`. Exit codes: 0 success, 1 findings or security error, 2 usage/input error.

## Development

```sh
npm run build   # regenerate cjs/ from src/ without dependencies
npm test        # pretest rebuilds CJS, then runs 222 deterministic node:test cases
```

The ESM source in `src/` is canonical. `scripts/build-cjs.mjs` generates `cjs/`; never hand-edit generated files. Types live in `types/index.d.ts`. See [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md) and [GOOD_FIRST_ISSUES.md](GOOD_FIRST_ISSUES.md) for contribution and reporting details.

## License

MIT. See [LICENSE](LICENSE).
