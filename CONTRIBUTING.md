# Contributing

Thanks for helping make CSV exports safer. Keep changes small, dependency-free and deterministic.

## Setup

```sh
git clone <your fork url>
cd csvshield
npm test
```

There is nothing to install: the project has no runtime or development dependencies.

## Ground rules

1. `src/*.mjs` is canonical. After editing it, run `npm run build` to regenerate `cjs/*.cjs` and commit both. Never hand-edit generated CommonJS files.
2. Keep `types/index.d.ts` in sync with every public API or option change.
3. Add deterministic regression tests under `tests/` using `node:test`. No network, timers, randomness or fixtures outside the repo.
4. Keep `package.json` dependency lists empty.
5. Update the test count in README.md when adding or removing tests. `npm test` prints the live count via `# tests <n>`.
6. Use LF line endings and avoid non-ASCII punctuation in prose.

## Pull requests

Explain the threat addressed, reference any issue, and show the exact malicious input and neutralized output. New defenses must include a bypass attempt that fails after the fix. All tests must pass on Node.js 18 and newer before review.

## Commit style

Use short imperative subjects, for example `harden: detect bidi-formatted formula triggers`.

## Code of conduct

Be respectful and assume good intent. Security findings must follow SECURITY.md for private disclosure.
