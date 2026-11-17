/**
 * SIFT-AIR Browser-First Privacy Gatekeeper (shared/redactor.ts)
 *
 * Scrubs regulated payment/identity tokens and cloud credentials in browser memory
 * BEFORE any payload crosses the network or reaches an LLM broker.
 */

export interface RedactionResult {
  sanitizedText: string;
  totalRedactions: number;
  countsByType: Record<string, number>;
  /** Transient RAM-only vault; never serialized into API requests or exported Case JSON. */
  secretVault: Record<string, string>;
}

export interface SanitizedCaseExport {
  caseId: string;
  exportedAtUtc: string;
  zeroRetentionVerified: true;
  sanitizedEvidence: string;
  redactionSummary: Record<string, number>;
  findings?: Record<string, unknown>;
}

function passesLuhn(digits: string): boolean {
  if (digits.length < 13 || digits.length > 19) return false;
  let sum = 0;
  let doubleDigit = false;
  for (let i = digits.length - 1; i >= 0; i -= 1) {
    let d = Number(digits[i]);
    if (Number.isNaN(d)) return false;
    if (doubleDigit) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    doubleDigit = !doubleDigit;
  }
  return sum % 10 === 0;
}

const SECRET_PATTERNS: Array<{
  type: string;
  regex: RegExp;
  validator?: (raw: string) => boolean;
}> = [
  {
    type: "PRIVATE_KEY",
    regex: /-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----/g,
  },
  {
    type: "JWT",
    regex: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g,
  },
  {
    type: "GIT_PAT",
    regex: /\b(?:glpat-[A-Za-z0-9_-]{20,}|gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})\b/g,
  },
  {
    type: "AWS_KEY",
    regex: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g,
  },
  {
    type: "BEARER_TOKEN",
    regex: /\bBearer\s+[A-Za-z0-9._~+/=-]{24,}\b/gi,
  },
  {
    type: "PAN",
    regex: /\b(?:\d[ -]*?){13,19}\b/g,
    validator: (raw: string) => passesLuhn(raw.replace(/\D/g, "")),
  },
  {
    type: "NATIONAL_ID_SSN",
    regex: /\b\d{3}-\d{2}-\d{4}\b/g,
  },
];

export function redactSensitiveTelemetry(rawText: string): RedactionResult {
  let working = rawText;
  const countsByType: Record<string, number> = {};
  const secretVault: Record<string, string> = {};
  const reverseLookup = new Map<string, string>();
  let totalRedactions = 0;

  for (const spec of SECRET_PATTERNS) {
    working = working.replace(spec.regex, (matched) => {
      if (spec.validator && !spec.validator(matched)) {
        return matched;
      }
      const existingToken = reverseLookup.get(matched);
      if (existingToken) {
        return existingToken;
      }
      const nextIndex = (countsByType[spec.type] ?? 0) + 1;
      countsByType[spec.type] = nextIndex;
      totalRedactions += 1;
      const placeholder = `[REDACTED_${spec.type}_${String(nextIndex).padStart(2, "0")}]`;
      secretVault[placeholder] = matched;
      reverseLookup.set(matched, placeholder);
      return placeholder;
    });
  }

  return {
    sanitizedText: working,
    totalRedactions,
    countsByType,
    secretVault,
  };
}

/**
 * Exports a peer-handoff Case JSON bundle while deterministically stripping the
 * transient ``secretVault`` and any unredacted raw input.
 */
export function exportSanitizedCaseBundle(
  caseId: string,
  redaction: RedactionResult,
  findings?: Record<string, unknown>,
): SanitizedCaseExport {
  return {
    caseId,
    exportedAtUtc: new Date().toISOString(),
    zeroRetentionVerified: true,
    sanitizedEvidence: redaction.sanitizedText,
    redactionSummary: { ...redaction.countsByType },
    findings,
  };
}
