# Security policy

## Supported versions

| Version | Supported |
| --- | --- |
| Latest published 1.x release | Yes |
| Older releases | No |

Only the latest published 1.x release receives security fixes. Users should upgrade to the fixed release as soon as it is available.

## Reporting a vulnerability

Report suspected vulnerabilities privately through [GitHub private vulnerability reporting](https://github.com/draarivpatel-ui/csvshield/security/advisories/new). Do not open a public issue for an exploitable finding.

Include:

- The csvshield version and Node.js version.
- A minimal CSV or cell payload.
- The expected behavior and the observed behavior.
- Your assessment of impact and a suggested fix if you have one.

Please do not include real customer data, credentials or secrets in a report.

## Acknowledgment and coordinated disclosure timeline

- We aim to acknowledge a vulnerability report within 3 business days.
- We aim to complete initial triage and severity assessment within 14 days.
- We aim to release a fix within 90 days of confirming a vulnerability, sooner for high severity issues when practical.
- We coordinate public disclosure with the reporter. A public advisory is normally published after a fixed release is available or on a mutually agreed date.
- Credit is given in release notes and the advisory unless the reporter prefers otherwise.
- If a report is not accepted as a vulnerability, we will explain the reasoning before closing the advisory.

## Vulnerability handling process

1. Receive the private report through the GitHub security advisory.
2. Reproduce the issue, determine affected versions and assess severity.
3. Develop a fix with regression tests.
4. Publish the fixed release and prepare the advisory.
5. Publish coordinated disclosure notes with affected and fixed versions.

## Scope

In scope: bypasses of formula-injection neutralization (including new trigger prefixes or obfuscation), prototype-pollution header handling, RFC 4180 parser confusion that smuggles dangerous cells, and denial-of-service bypasses of the documented limits.

Out of scope: spreadsheet applications that execute content without a leading trigger, malicious content never passed through csvshield, and social engineering.

## Hardening notes

- Input is decoded as strict UTF-8 with an explicit byte budget.
- Every cell is scanned line by line; CR, LF and CRLF separators are handled individually.
- Obfuscation characters (controls, Unicode spaces, BOM, zero-width and bidi marks) are skipped before trigger detection and reported in escaped previews.
- Object-mode output uses null-prototype records; `__proto__`, `constructor` and `prototype` headers are rejected by default.
- Test vectors include DDE and CSV-injection shapes from OWASP, MITRE CWE-1236 and common spreadsheet exploit reports.
