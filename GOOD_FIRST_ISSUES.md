# Good first issues

Fifteen small, well-scoped tasks for new contributors. Each has a clear target file and an acceptance check. Comment on the issue before starting so work is not duplicated.

## Issue 1: Harden repeated-trigger stripping

- **Area:** `tests/sanitize.test.mjs`
- **Task:** strip mode currently loops over triggers on one line. Add a test for a cell like `@@=@1` and confirm the documented strip contract remains predictable.
- **Acceptance:** A focused pull request with deterministic tests and, where behavior changes, an update to the README test count.

## Issue 2: Document spreadsheet-specific behaviors

- **Area:** `README.md`
- **Task:** Add a short section comparing how Excel, LibreOffice and Google Sheets interpret neutralized cells, with citations.
- **Acceptance:** A focused pull request with deterministic tests and, where behavior changes, an update to the README test count.

## Issue 3: Add a TSV fixture corpus

- **Area:** `tests/`
- **Task:** Build a deterministic fixture file of malicious TSV rows and drive both parseSafeCsv and the CLI against it.
- **Acceptance:** A focused pull request with deterministic tests and, where behavior changes, an update to the README test count.

## Issue 4: Test quoted-field CR/LF smuggling

- **Area:** `tests/parse.test.mjs`
- **Task:** Add cases where CRLF appears inside a quoted field followed by a formula trigger; assert rule and column reporting.
- **Acceptance:** A focused pull request with deterministic tests and, where behavior changes, an update to the README test count.

## Issue 5: Expand duplicate-header matrix

- **Area:** `tests/parse.test.mjs`
- **Task:** Cover duplicate headers combined with onDangerousHeader skip and prefix policies.
- **Acceptance:** A focused pull request with deterministic tests and, where behavior changes, an update to the README test count.

## Issue 6: Audit preview escaping

- **Area:** `src/core.mjs`
- **Task:** Review previewOf for unhandled Unicode control ranges and add cases for any missing range with escaped expected output.
- **Acceptance:** A focused pull request with deterministic tests and, where behavior changes, an update to the README test count.

## Issue 7: CLI stdin error paths

- **Area:** `tests/stringify-cli.test.mjs`
- **Task:** Add integration tests for unreadable files, invalid UTF-8 on stdin and unknown commands.
- **Acceptance:** A focused pull request with deterministic tests and, where behavior changes, an update to the README test count.

## Issue 8: Type-level tests

- **Area:** `types/`
- **Task:** Add a TypeScript compile check that exercises hasHeader overloads and every options interface.
- **Acceptance:** A focused pull request with deterministic tests and, where behavior changes, an update to the README test count.

## Issue 9: Property-style round-trip test

- **Area:** `tests/`
- **Task:** Use a deterministic seeded generator to assert stringifySafeCsv then parseSafeCsv never reintroduces a trigger.
- **Acceptance:** A focused pull request with deterministic tests and, where behavior changes, an update to the README test count.

## Issue 10: Improve inspectCsv header mapping

- **Area:** `src/core.mjs`
- **Task:** When duplicate headers are skipped, verify finding.header matches the column actually consumed.
- **Acceptance:** A focused pull request with deterministic tests and, where behavior changes, an update to the README test count.

## Issue 11: Benchmark large inputs

- **Area:** `scripts/`
- **Task:** Add an opt-in deterministic benchmark script for a 100k-row CSV under the default byte bound and document results.
- **Acceptance:** A focused pull request with deterministic tests and, where behavior changes, an update to the README test count.

## Issue 12: Clarify preserve-numbers grammar

- **Area:** `README.md`
- **Task:** Write a formal grammar for accepted negative literals and add boundary tests around exponents and leading zeros.
- **Acceptance:** A focused pull request with deterministic tests and, where behavior changes, an update to the README test count.

## Issue 13: CJS build coverage

- **Area:** `tests/parity.test.mjs`
- **Task:** Extend parity tests to compare error messages and toJSON output for every CsvShieldError code.
- **Acceptance:** A focused pull request with deterministic tests and, where behavior changes, an update to the README test count.

## Issue 14: DoD: verify CI matrix

- **Area:** `.github/workflows/ci.yml`
- **Task:** Ensure the GitHub Actions workflow runs the suite on all supported Node majors and that the count remains stable.
- **Acceptance:** A focused pull request with deterministic tests and, where behavior changes, an update to the README test count.

## Issue 15: Add a security changelog

- **Area:** `SECURITY.md`
- **Task:** Create a short changelog documenting when each defense landed and link it from SECURITY.md.
- **Acceptance:** A focused pull request with deterministic tests and, where behavior changes, an update to the README test count.
