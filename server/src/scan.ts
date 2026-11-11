/**
 * Prototype Apex scanner: small, deterministic, line-based rules.
 *
 * This is intentionally simple so the demo focuses on the payment flow. Every
 * finding comes from a pattern match on the submitted source; nothing is
 * invented. Production would swap this for Salesforce Code Analyzer + PMD.
 */

export type Severity = 'high' | 'moderate' | 'info';

export interface Finding {
  rule: string;
  severity: Severity;
  line: number;
  code: string;
  message: string;
  fix: string;
}

interface Rule {
  id: string;
  severity: Severity;
  test: (line: string) => boolean;
  message: string;
  fix: string;
}

const RULES: Rule[] = [
  {
    id: 'SOQL_INJECTION',
    severity: 'high',
    // A SOQL string literal being concatenated with something else.
    test: (l) =>
      /['"]\s*select\b[^;]*['"]\s*\+/i.test(l) && !/escapeSingleQuotes/i.test(l),
    message: 'SOQL built by string concatenation. User input could alter the query.',
    fix: 'Use static SOQL with bind variables (:var) or Database.queryWithBinds().',
  },
  {
    id: 'WITHOUT_SHARING',
    severity: 'high',
    test: (l) => /\bwithout\s+sharing\b/i.test(l),
    message: 'Class runs in system context and ignores record sharing.',
    fix: 'Use "with sharing" (or "inherited sharing") unless a reviewed exception applies.',
  },
  {
    id: 'MISSING_SHARING_DECLARATION',
    severity: 'moderate',
    test: (l) =>
      /^\s*(public|global)\s+(virtual\s+|abstract\s+)?class\b/i.test(l) && !/\bsharing\b/i.test(l),
    message: 'Class has no explicit sharing declaration.',
    fix: 'Declare "with sharing" or "inherited sharing" explicitly.',
  },
  {
    id: 'INSECURE_ENDPOINT',
    severity: 'high',
    test: (l) => /setEndpoint\s*\(\s*['"]http:\/\//i.test(l),
    message: 'Callout over plain HTTP.',
    fix: 'Use HTTPS, ideally through a Named Credential.',
  },
  {
    id: 'HARDCODED_CREDENTIAL',
    severity: 'high',
    test: (l) =>
      /(password|passwd|secret|token|api_?key)\w*\s*=\s*['"][^'"]{6,}['"]/i.test(l),
    message: 'Possible hard-coded credential.',
    fix: 'Move secrets to Named/External Credentials and rotate the exposed value.',
  },
  {
    id: 'MISSING_FLS_ON_SOQL',
    severity: 'moderate',
    test: (l) =>
      /\[\s*select\b/i.test(l) && !/with\s+(user_mode|security_enforced)/i.test(l),
    message: 'Inline SOQL without CRUD/FLS enforcement.',
    fix: 'Add WITH USER_MODE (or WITH SECURITY_ENFORCED), or use Security.stripInaccessible().',
  },
  {
    id: 'UNCHECKED_DML',
    severity: 'moderate',
    test: (l) => /^\s*(insert|update|delete|upsert)\s+[\w.()]+\s*;/i.test(l),
    message: 'DML statement without object permission enforcement.',
    fix: 'Use Database.insert(records, AccessLevel.USER_MODE) or check isCreateable()/isUpdateable().',
  },
  {
    id: 'SYSTEM_MODE_ACCESS',
    severity: 'moderate',
    test: (l) => /\bSYSTEM_MODE\b/.test(l),
    message: 'Explicit system-mode access bypasses CRUD/FLS.',
    fix: 'Prefer USER_MODE for user-driven operations.',
  },
  {
    id: 'EXTERNAL_ENTRY_POINT',
    severity: 'info',
    test: (l) => /@RestResource\s*\(|@RemoteAction\b/i.test(l),
    message: 'Externally reachable endpoint. Review Guest user access and sharing.',
    fix: 'Run "with sharing", enforce CRUD/FLS, and confirm the Guest profile has no unneeded access.',
  },
];

export const RULE_COUNT = RULES.length;

export function scanApex(source: string) {
  const lines = source.split(/\r?\n/);
  const findings: Finding[] = [];
  lines.forEach((text, i) => {
    // Skip pure comment lines so commented-out code is not flagged.
    if (/^\s*(\/\/|\*|\/\*)/.test(text)) return;
    for (const rule of RULES) {
      if (rule.test(text)) {
        findings.push({
          rule: rule.id,
          severity: rule.severity,
          line: i + 1,
          code: text.trim().slice(0, 200),
          message: rule.message,
          fix: rule.fix,
        });
      }
    }
  });

  const summary = {
    total: findings.length,
    high: findings.filter((f) => f.severity === 'high').length,
    moderate: findings.filter((f) => f.severity === 'moderate').length,
    info: findings.filter((f) => f.severity === 'info').length,
  };
  return { linesScanned: lines.length, rulesEvaluated: RULE_COUNT, summary, findings };
}
