# Security policy

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
- Object-mode output uses null-prototype records; `__proto__`, `constructor` and `prototype` headers are rejected by default.
- Test vectors include DDE and CSV-injection shapes from OWASP, MITRE CWE-1236 and common spreadsheet exploit reports.
