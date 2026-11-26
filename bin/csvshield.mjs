#!/usr/bin/env node
import { readFileSync } from 'node:fs';
import {
  VERSION,
  inspectCsv,
  parseSafeCsv,
  stringifySafeCsv,
  CsvShieldError,
} from '../src/index.mjs';

const HELP = `csvshield ${VERSION}
Zero-dependency CSV formula-injection and RFC 4180 security toolkit.

Usage:
  csvshield inspect [file]          Audit a CSV file (use - for stdin)
  csvshield sanitize [file]         Re-emit a CSV with all cells neutralized
  csvshield parse [file]            Parse a CSV to JSON lines
  csvshield --version
  csvshield --help

Options:
  --delimiter <char>   Field delimiter (default: comma)
  --mode <mode>        prefix | strip | reject | preserve-numbers
  --has-header         Treat the first row as object keys
  --json               Emit JSON output (inspect)
  --bom                Prepend a UTF-8 BOM when sanitizing
  --no-bom             Do not prepend a UTF-8 BOM when sanitizing (default)
  -h, --help           Show this help

Exit codes:
  0  No findings (inspect) / success
  1  Findings present (inspect) or a security error occurred
  2  Usage or input error`;

function die(message, code = 2) {
  process.stderr.write(`csvshield: ${message}\n`);
  process.exit(code);
}

function takeValue(args, index, flag) {
  const value = args[index + 1];
  if (value === undefined || value.startsWith('--')) die(`Missing value for ${flag}`);
  return value;
}

function parseArgs(argv) {
  const args = argv.slice(2);
  let command = null;
  let file = null;
  const options = { delimiter: ',', mode: 'prefix', json: false, bom: false, hasHeader: false };
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === '-h' || arg === '--help') {
      process.stdout.write(`${HELP}\n`);
      process.exit(0);
    }
    if (arg === '--version') {
      process.stdout.write(`${VERSION}\n`);
      process.exit(0);
    }
    if (arg === '--delimiter') {
      const value = takeValue(args, i, '--delimiter');
      i++;
      if (Array.from(value).length !== 1) die('--delimiter must be one character');
      options.delimiter = value;
      continue;
    }
    if (arg === '--mode') {
      options.mode = takeValue(args, i, '--mode');
      i++;
      continue;
    }
    if (arg === '--has-header') { options.hasHeader = true; continue; }
    if (arg === '--json') { options.json = true; continue; }
    if (arg === '--bom') { options.bom = true; continue; }
    if (arg === '--no-bom') { options.bom = false; continue; }
    if (arg.startsWith('-') && arg !== '-') die(`Unknown option ${arg}`);
    if (command === null) command = arg;
    else if (file === null) file = arg;
    else die('Too many arguments');
  }
  return { command, file, options };
}

function readInput(file) {
  if (file === null || file === '-') return readFileSync(0, 'utf8');
  try {
    return readFileSync(file, 'utf8');
  } catch {
    die(`Cannot read file: ${file}`);
  }
}

const { command, file, options } = parseArgs(process.argv);
if (command === null) {
  process.stderr.write(`${HELP}\n`);
  process.exit(2);
}

const input = ['inspect', 'sanitize', 'parse'].includes(command) ? readInput(file) : null;
const opts = {
  delimiter: options.delimiter,
  mode: options.mode,
  hasHeader: options.hasHeader,
};

try {
  if (command === 'inspect') {
    const report = inspectCsv(input, opts);
    if (options.json) {
      process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
    } else {
      for (const finding of report.findings) {
        process.stdout.write(
          `row ${finding.row}, col ${finding.col}: ${finding.rule} ${JSON.stringify(finding.trigger)} (${finding.preview})\n`,
        );
      }
      if (report.safe) process.stdout.write('No findings.\n');
    }
    process.exit(report.safe ? 0 : 1);
  }
  if (command === 'sanitize') {
    const parsed = parseSafeCsv(input, { ...opts, sanitize: false });
    const output = stringifySafeCsv(parsed, {
      delimiter: options.delimiter,
      eol: '\n',
      bom: options.bom,
      mode: options.mode,
      columns: options.hasHeader && parsed.length > 0 ? Object.keys(parsed[0]) : undefined,
    });
    process.stdout.write(output);
    process.exit(0);
  }
  if (command === 'parse') {
    const records = parseSafeCsv(input, opts);
    for (const record of records) process.stdout.write(`${JSON.stringify(record)}\n`);
    process.exit(0);
  }
  die(`Unknown command: ${command}`);
} catch (error) {
  if (error instanceof CsvShieldError) {
    process.stderr.write(`${error.code}: ${error.message}\n`);
    process.exit(1);
  }
  throw error;
}
