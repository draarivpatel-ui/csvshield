// One-shot scaffolding generator. Run once via agent-perf-env.sh node scripts/write-docs.mjs.
import { execFileSync } from 'node:child_process';
import { writeFileSync, mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';

const root = fileURLToPath(new URL('..', import.meta.url));
const testOut = execFileSync(process.execPath, ['--test', join(root, 'tests')], { encoding: 'utf8', maxBuffer: 16 * 1024 * 1024 });
const countMatch = testOut.match(/[#\u2139] pass (\d+)/) || testOut.match(/[#\u2139] tests (\d+)/);
if (!countMatch) throw new Error('Could not determine test count');
const testCount = Number(countMatch[1]);
console.log(`Live passing test count: ${testCount}`);

const write = (rel, content) => {
  const path = join(root, rel);
  mkdirSync(join(path, '..'), { recursive: true });
  writeFileSync(path, content.replace(/__COUNT__/g, String(testCount)));
};

write('README.md', `# csvshield

Zero-dependency CSV and TSV security toolkit for Node.js. csvshield stops CWE-1236 spreadsheet formula injection and DDE payloads before a CSV ever reaches Excel, LibreOffice, Google Sheets or Numbers. Pure ECMAScript, no runtime dependencies, ESM plus CommonJS plus TypeScript declarations.

## Why

A cell beginning with \`=\`, \`+\`, \`-\`, \`@\`, a tab, a carriage return, a newline or a pipe can be interpreted as a formula by spreadsheet software. Attackers hide the trigger behind spaces, BOMs, zero-width characters, CR/LF smuggling or quote breaks. csvshield detects those variants and neutralizes them with a configurable policy.

## Install

\`\`\`sh
npm install csvshield
\`\`\`

Requires Node.js 20 or newer. The package has no dependencies and no build step at install time.

## Quick start

\`\`\`js
import { sanitizeCell, stringifySafeCsv, parseSafeCsv, inspectCsv } from 'csvshield';

sanitizeCell('=SUM(A1:A9)');        // "'=SUM(A1:A9)"
sanitizeCell('-42', { mode: 'preserve-numbers' }); // "-42"
stringifySafeCsv([{ name: 'Alice', formula: '@SUM(1)' }]);
// "name,formula\\r\\nAlice,'@SUM(1)\\r\\n"

parseSafeCsv('name,formula\\nAlice,=1\\n', { hasHeader: true });
// [{ name: 'Alice', formula: "'=1" }]  (null-prototype record)

inspectCsv('name,formula\\nAlice,=1\\n');
// { safe: false, findings: [{ row: 2, col: 2, header: 'formula', rule: 'leading-trigger', trigger: '=', preview: '=1' }] }
\`\`\`

CommonJS:

\`\`\`js
const { sanitizeCell } = require('csvshield');
\`\`\`

The \`csvshield/core\` subpath exposes the same API without the package index re-export layer.

## API

| Function | Purpose |
| --- | --- |
| \`sanitizeCell(value, options)\` | Neutralize one cell by the selected policy. |
| \`stringifySafeCsv(rows, options)\` | Sanitize and serialize arrays, arrays of arrays or records to RFC 4180 CSV. |
| \`parseSafeCsv(input, options)\` | Strict RFC 4180 parse with per-cell sanitization and header defense. |
| \`inspectCsv(input, options)\` | Audit without modifying cells; returns \`{ safe, findings }\`. |
| \`findCsvTriggers(value, options)\` | List trigger findings with escaped previews. |
| \`isSafeNegativeNumberValue(value)\` | Check whether a value qualifies for the safe-negative exception. |
| \`CsvShieldError\` | Structured error with \`code\`, \`row\`, \`col\`, \`header\`, \`rule\`, \`trigger\`, \`preview\` and \`toJSON()\`. |

### Options

| Option | Default | Description |
| --- | --- | --- |
| \`mode\` | \`'prefix'\` | \`prefix\`, \`strip\`, \`reject\` or \`preserve-numbers\`. |
| \`prefix\` | \`"'\"\` | Prefix inserted before a dangerous cell. |
| \`preserveNumbers\` | \`false\` | Allow finite negative numbers even in prefix mode. |
| \`delimiter\` | \`','\` | Single-character field delimiter. |
| \`hasHeader\` | \`false\` | Emit null-prototype objects keyed by the first row. |
| \`sanitize\` | \`true\` | Disable only for trusted, pre-sanitized input. |
| \`onDangerousHeader\` | \`'throw'\` | \`throw\`, \`skip\` or \`prefix\` for \`__proto__\`, \`constructor\`, \`prototype\`. |
| \`onDuplicateHeader\` | \`'last'\` | \`last\`, \`first\`, \`skip\` or \`throw\`. |
| \`strictColumns\` | \`false\` | Reject rows whose width differs from the header. |
| \`skipEmptyLines\`, \`relaxed\`, \`stripBom\` | \`false\`, \`false\`, \`true\` | Parser tolerance settings. |
| \`eol\`, \`bom\`, \`trailingEol\`, \`columns\` | \`'\\r\\n'\`, \`false\`, \`true\`, inferred | Stringifier settings. |
| \`maxRows\`, \`maxColumns\`, \`maxCellBytes\`, \`maxTotalBytes\` | 10000, 100, 100000, 5000000 | Deterministic DoS bounds (byte counts use UTF-8). |

## Threat model

csvshield covers the trigger prefixes documented by OWASP for CSV injection: \`=\`, \`+\`, \`-\`, \`@\`, tab, CR, LF and pipe. It also handles leading whitespace, Unicode spaces, BOMs, zero-width and bidirectional controls, repeated triggers, embedded CR/LF smuggling and DDE-shaped payloads such as \`=cmd|'/c calc'!A0\`. \`preserve-numbers\` exempts only strict finite negative numeric literals. Object-mode records use \`Object.create(null)\` and dangerous header names are blocked, skipped or prefixed. All inputs are bounded before parsing to prevent memory exhaustion.

Out of scope: URL safety inside hyperlink formulas that no longer begin with a trigger, spreadsheet settings that auto-execute non-prefixed content, and malicious file content that was never parsed by csvshield.

## CLI

\`\`\`sh
csvshield inspect  [file]   # audit; exit 1 when findings exist (use - for stdin)
csvshield sanitize [file]   # re-emit a neutralized CSV
csvshield parse    [file]   # emit sanitized JSON lines
csvshield --help
csvshield --version
\`\`\`

Flags: \`--delimiter <char>\`, \`--mode <mode>\`, \`--has-header\`, \`--json\`, \`--no-bom\`. Exit codes: 0 success, 1 findings or security error, 2 usage/input error.

## Development

\`\`\`sh
npm run build   # regenerate cjs/ from src/ without dependencies
npm test        # pretest rebuilds CJS, then runs __COUNT__ deterministic node:test cases
\`\`\`

The ESM source in \`src/\` is canonical. \`scripts/build-cjs.mjs\` generates \`cjs/\`; never hand-edit generated files. Types live in \`types/index.d.ts\`. See [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md) and [GOOD_FIRST_ISSUES.md](GOOD_FIRST_ISSUES.md) for contribution and reporting details.

## License

MIT. See [LICENSE](LICENSE).
`);

write('SECURITY.md', `# Security policy

## Supported versions

Only the latest published 1.x release receives security fixes.

## Reporting a vulnerability

Report security issues privately through the GitHub repository security advisory form ("Report a vulnerability") for this project. Do not open a public issue for an exploitable finding. Include the csvshield version, Node.js version, a minimal CSV or cell payload, the expected behavior and the observed behavior. You should receive an acknowledgment within seven days; fixes and advisories are coordinated before public disclosure.

Please do not include real customer data or credentials in a report.

## Scope

In scope: bypasses of formula-injection neutralization (including new trigger prefixes or obfuscation), prototype-pollution header handling, RFC 4180 parser confusion that smuggles dangerous cells, and denial-of-service bypasses of the documented limits.

Out of scope: spreadsheet applications that execute content without a leading trigger, malicious content never passed through csvshield, and social engineering.

## Hardening notes

- Input is decoded as strict UTF-8 with an explicit byte budget.
- Every cell is scanned line by line; CR, LF and CRLF separators are handled individually.
- Obfuscation characters (controls, Unicode spaces, BOM, zero-width and bidi marks) are skipped before trigger detection and reported in escaped previews.
- Object-mode output uses null-prototype records; \`__proto__\`, \`constructor\` and \`prototype\` headers are rejected by default.
- Test vectors include DDE and CSV-injection shapes from OWASP, MITRE CWE-1236 and common spreadsheet exploit reports.
`);

write('CONTRIBUTING.md', `# Contributing

Thanks for helping make CSV exports safer. Keep changes small, dependency-free and deterministic.

## Setup

\`\`\`sh
git clone <your fork url>
cd csvshield
npm test
\`\`\`

There is nothing to install: the project has no runtime or development dependencies.

## Ground rules

1. \`src/*.mjs\` is canonical. After editing it, run \`npm run build\` to regenerate \`cjs/*.cjs\` and commit both. Never hand-edit generated CommonJS files.
2. Keep \`types/index.d.ts\` in sync with every public API or option change.
3. Add deterministic regression tests under \`tests/\` using \`node:test\`. No network, timers, randomness or fixtures outside the repo.
4. Keep \`package.json\` dependency lists empty.
5. Update the test count in README.md when adding or removing tests. \`npm test\` prints the live count via \`# tests <n>\`.
6. Use LF line endings and avoid non-ASCII punctuation in prose.

## Pull requests

Explain the threat addressed, reference any issue, and show the exact malicious input and neutralized output. New defenses must include a bypass attempt that fails after the fix. All tests must pass on Node.js 20 and newer before review.

## Commit style

Use short imperative subjects, for example \`harden: detect bidi-formatted formula triggers\`.

## Code of conduct

Be respectful and assume good intent. Security findings must follow SECURITY.md for private disclosure.
`);

const issues = [
  ['Harden repeated-trigger stripping', 'strip mode currently loops over triggers on one line. Add a test for a cell like `@@=@1` and confirm the documented strip contract remains predictable.', 'tests/sanitize.test.mjs'],
  ['Document spreadsheet-specific behaviors', 'Add a short section comparing how Excel, LibreOffice and Google Sheets interpret neutralized cells, with citations.', 'README.md'],
  ['Add a TSV fixture corpus', 'Build a deterministic fixture file of malicious TSV rows and drive both parseSafeCsv and the CLI against it.', 'tests/'],
  ['Test quoted-field CR/LF smuggling', 'Add cases where CRLF appears inside a quoted field followed by a formula trigger; assert rule and column reporting.', 'tests/parse.test.mjs'],
  ['Expand duplicate-header matrix', 'Cover duplicate headers combined with onDangerousHeader skip and prefix policies.', 'tests/parse.test.mjs'],
  ['Audit preview escaping', 'Review previewOf for unhandled Unicode control ranges and add cases for any missing range with escaped expected output.', 'src/core.mjs'],
  ['CLI stdin error paths', 'Add integration tests for unreadable files, invalid UTF-8 on stdin and unknown commands.', 'tests/stringify-cli.test.mjs'],
  ['Type-level tests', 'Add a TypeScript compile check that exercises hasHeader overloads and every options interface.', 'types/'],
  ['Property-style round-trip test', 'Use a deterministic seeded generator to assert stringifySafeCsv then parseSafeCsv never reintroduces a trigger.', 'tests/'],
  ['Improve inspectCsv header mapping', 'When duplicate headers are skipped, verify finding.header matches the column actually consumed.', 'src/core.mjs'],
  ['Benchmark large inputs', 'Add an opt-in deterministic benchmark script for a 100k-row CSV under the default byte bound and document results.', 'scripts/'],
  ['Clarify preserve-numbers grammar', 'Write a formal grammar for accepted negative literals and add boundary tests around exponents and leading zeros.', 'README.md'],
  ['CJS build coverage', 'Extend parity tests to compare error messages and toJSON output for every CsvShieldError code.', 'tests/parity.test.mjs'],
  ['DoD: verify CI matrix', 'Ensure the GitHub Actions workflow runs the suite on all supported Node majors and that the count remains stable.', '.github/workflows/ci.yml'],
  ['Add a security changelog', 'Create a short changelog documenting when each defense landed and link it from SECURITY.md.', 'SECURITY.md'],
];

write('GOOD_FIRST_ISSUES.md', `# Good first issues

Fifteen small, well-scoped tasks for new contributors. Each has a clear target file and an acceptance check. Comment on the issue before starting so work is not duplicated.

${issues.map(([title, body, area], i) => `## Issue ${i + 1}: ${title}

- **Area:** \`${area}\`
- **Task:** ${body}
- **Acceptance:** A focused pull request with deterministic tests and, where behavior changes, an update to the README test count.`).join('\n\n')}
`);

write('LICENSE', `MIT License

Copyright (c) 2026 csvshield contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
`);

write('.github/workflows/ci.yml', `name: ci

on:
  push:
    branches: [main]
  pull_request:

jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      fail-fast: false
      matrix:
        node: [20, 22, 24]
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: \${{ matrix.node }}
      - name: Verify zero dependencies
        run: node -e "const p=require('./package.json'); if(Object.keys(p.dependencies).length||Object.keys(p.devDependencies).length) process.exit(1)"
      - name: Build CommonJS
        run: npm run build
      - name: Run deterministic tests
        run: node --test tests/
`);
