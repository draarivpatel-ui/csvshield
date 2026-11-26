export type PolicyMode = 'prefix' | 'strip' | 'reject' | 'preserve-numbers';
export type OnDangerousHeader = 'throw' | 'skip' | 'prefix';
export type OnDuplicateHeader = 'last' | 'first' | 'skip' | 'throw';

export interface SanitizeOptions {
  mode?: PolicyMode;
  prefix?: string;
  preserveNumbers?: boolean;
}

export interface CsvParseOptions extends SanitizeOptions {
  delimiter?: string;
  hasHeader?: boolean;
  sanitize?: boolean;
  stripBom?: boolean;
  relaxed?: boolean;
  skipEmptyLines?: boolean;
  strictColumns?: boolean;
  onDangerousHeader?: OnDangerousHeader;
  onDuplicateHeader?: OnDuplicateHeader;
  maxRows?: number;
  maxColumns?: number;
  maxCellBytes?: number;
  maxTotalBytes?: number;
}

export interface CsvStringifyOptions extends SanitizeOptions {
  delimiter?: string;
  eol?: '\n' | '\r\n';
  bom?: boolean;
  trailingEol?: boolean;
  sanitize?: boolean;
  columns?: string[];
  maxRows?: number;
  maxColumns?: number;
  maxCellBytes?: number;
  maxTotalBytes?: number;
  onDangerousHeader?: OnDangerousHeader;
}

export type Cell = string | number | boolean | null | undefined;
export type CsvRecord = Record<string, Cell>;
export type CsvMatrix = Cell[][];

export type FindingRule =
  | 'leading-trigger'
  | 'obfuscated-trigger'
  | 'embedded-formula'
  | 'prototype-pollution';

export interface Finding {
  row: number;
  col: number;
  header: string | null;
  rule: FindingRule | string;
  trigger: string;
  preview: string;
}

export interface InspectionReport {
  safe: boolean;
  findings: Finding[];
}

export type CsvShieldErrorCode =
  | 'ERR_CSV_GENERIC'
  | 'ERR_CSV_OPTION'
  | 'ERR_CSV_FORMULA'
  | 'ERR_CSV_LIMIT'
  | 'ERR_CSV_PARSE'
  | 'ERR_CSV_ENCODING'
  | 'ERR_CSV_PROTOTYPE'
  | 'ERR_CSV_HEADER'
  | 'ERR_CSV_COLUMNS';

export interface CsvShieldErrorJSON {
  name: string;
  code: string;
  message: string;
  row?: number;
  col?: number;
  header?: string | null;
  rule?: string;
  trigger?: string;
  preview?: string;
  limit?: string;
  value?: number;
}

export declare class CsvShieldError extends Error {
  readonly name: 'CsvShieldError';
  code: CsvShieldErrorCode | string;
  row?: number;
  col?: number;
  header?: string | null;
  rule?: string;
  trigger?: string;
  preview?: string;
  limit?: string;
  value?: number;
  constructor(message: string, details?: Record<string, unknown>);
  toJSON(): CsvShieldErrorJSON;
}

export declare const VERSION: string;

export declare function sanitizeCell(value: Cell, options?: SanitizeOptions): string;

export declare function stringifySafeCsv(rows: CsvMatrix | CsvRecord[], options?: CsvStringifyOptions): string;

export declare function parseSafeCsv(
  input: string | Uint8Array,
  options?: CsvParseOptions & { hasHeader: true },
): CsvRecord[];
export declare function parseSafeCsv(
  input: string | Uint8Array,
  options?: CsvParseOptions,
): CsvMatrix;

export declare function inspectCsv(input: string | Uint8Array, options?: CsvParseOptions): InspectionReport;

export declare function isSafeNegativeNumberValue(value: Cell): boolean;

export declare function findCsvTriggers(
  value: Cell,
  options?: SanitizeOptions,
): Array<{ rule: string; trigger: string; preview: string }>;
