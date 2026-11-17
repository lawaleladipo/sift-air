import assert from "node:assert/strict";
import test from "node:test";
import zlib from "node:zlib";

import { runDacPreFlightLinter } from "../shared/dacPreFlightLinter.ts";
import { ACME_CLOUD_INTRUSION_PRESET, SAMPLE_RULES_BY_SURFACE } from "../shared/demoPresets.ts";
import { exportSanitizedCaseBundle, redactSensitiveTelemetry } from "../shared/redactor.ts";
import { correlateSanitizedTextWithContext } from "../server/contextDirectory.ts";
import {
  buildZeroRetentionPayload,
  runDeterministicInvestigationPipeline,
} from "../server/geminiBroker.ts";
import { extractDocxLocally, extractPdfTwoPass } from "../src/utils/documentExtractor.ts";

/** Build a minimal valid PKZIP (.docx) buffer in memory containing word/document.xml */
function createMinimalDocxZip(xmlString: string): Uint8Array {
  const nameBytes = new TextEncoder().encode("word/document.xml");
  const rawXmlBytes = new TextEncoder().encode(xmlString);
  const compressed = new Uint8Array(zlib.deflateRawSync(rawXmlBytes));

  const localHeader = new Uint8Array(30 + nameBytes.length);
  const lv = new DataView(localHeader.buffer);
  lv.setUint32(0, 0x04034b50, true);
  lv.setUint16(4, 20, true);
  lv.setUint16(8, 8, true); // deflate
  lv.setUint32(18, compressed.length, true);
  lv.setUint32(22, rawXmlBytes.length, true);
  lv.setUint16(26, nameBytes.length, true);
  localHeader.set(nameBytes, 30);

  const cdOffset = localHeader.length + compressed.length;
  const cdHeader = new Uint8Array(46 + nameBytes.length);
  const cv = new DataView(cdHeader.buffer);
  cv.setUint32(0, 0x02014b50, true);
  cv.setUint16(4, 20, true);
  cv.setUint16(6, 20, true);
  cv.setUint16(10, 8, true);
  cv.setUint32(20, compressed.length, true);
  cv.setUint32(24, rawXmlBytes.length, true);
  cv.setUint16(28, nameBytes.length, true);
  cv.setUint32(42, 0, true);
  cdHeader.set(nameBytes, 46);

  const eocd = new Uint8Array(22);
  const ev = new DataView(eocd.buffer);
  ev.setUint32(0, 0x06054b50, true);
  ev.setUint16(8, 1, true);
  ev.setUint16(10, 1, true);
  ev.setUint32(12, cdHeader.length, true);
  ev.setUint32(16, cdOffset, true);

  const out = new Uint8Array(localHeader.length + compressed.length + cdHeader.length + eocd.length);
  out.set(localHeader, 0);
  out.set(compressed, localHeader.length);
  out.set(cdHeader, cdOffset);
  out.set(eocd, cdOffset + cdHeader.length);
  return out;
}

test("Gatekeeper scrubs PAN, JWT, Git PAT, and strips secretVault on Case JSON export", () => {
  const res = redactSensitiveTelemetry(ACME_CLOUD_INTRUSION_PRESET.rawTelemetry);
  assert.ok(res.totalRedactions >= 3);
  assert.ok(!res.sanitizedText.includes("4532015112830366"));
  assert.ok(!res.sanitizedText.includes("glpat-AbCdEfGhIjKlMnOpQrSt12"));
  assert.ok(!res.sanitizedText.includes("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"));
  assert.ok(res.sanitizedText.includes("[REDACTED_PAN_01]"));
  assert.ok(res.sanitizedText.includes("[REDACTED_GIT_PAT_01]"));

  const exported = exportSanitizedCaseBundle("CASE-101", res);
  const serialized = JSON.stringify(exported);
  assert.equal(exported.zeroRetentionVerified, true);
  assert.ok(!serialized.includes("4532015112830366"));
  assert.ok(!serialized.includes("secretVault"));
});

test("Local .docx PKZIP extractor reconstructs headings and IOC Markdown tables with zero LLM calls", async () => {
  const sampleXml = `<?xml version="1.0" encoding="UTF-8"?>
    <w:document>
      <w:body>
        <w:p><w:pPr><w:pStyle w:val="Heading1"/></w:pPr><w:r><w:t>Threat Advisory: Cloud Key Theft</w:t></w:r></w:p>
        <w:tbl>
          <w:tr><w:tc><w:t>Indicator</w:t></w:tc><w:tc><w:t>Type</w:t></w:tc></w:tr>
          <w:tr><w:tc><w:t>198.51.100.77</w:t></w:tc><w:tc><w:t>IPv4 C2</w:t></w:tc></w:tr>
        </w:tbl>
      </w:body>
    </w:document>`;
  const zipBytes = createMinimalDocxZip(sampleXml);
  const doc = await extractDocxLocally("advisory.docx", zipBytes);
  assert.equal(doc.extractedLocally, true);
  assert.equal(doc.needsZeroRetentionOcrFallback, false);
  assert.ok(doc.markdownText.includes("# Threat Advisory: Cloud Key Theft"));
  assert.ok(doc.markdownText.includes("| 198.51.100.77 | IPv4 C2 |"));
});

test("Two-pass .pdf extractor inflates /FlateDecode streams and flags scanned PDFs for OCR fallback", async () => {
  const deflated = zlib.deflateSync(
    Buffer.from("BT /F1 12 Tf 72 712 Td (APT Cloud Intrusion Report IOC 198.51.100.77) Tj ET", "latin1"),
  );
  const pdfHeader = Buffer.from("%PDF-1.4\n1 0 obj\n<< /Filter /FlateDecode >>\nstream\n", "latin1");
  const pdfFooter = Buffer.from("\nendstream\nendobj\n%%EOF", "latin1");
  const validPdf = new Uint8Array(Buffer.concat([pdfHeader, deflated, pdfFooter]));

  const parsed = await extractPdfTwoPass("report.pdf", validPdf);
  assert.equal(parsed.extractedLocally, true);
  assert.equal(parsed.needsZeroRetentionOcrFallback, false);
  assert.ok(parsed.markdownText.includes("198.51.100.77"));

  const scannedStub = new TextEncoder().encode("%PDF-1.4\n1 0 obj << /Subtype /Image >> endobj\n%%EOF");
  const scannedRes = await extractPdfTwoPass("scanned.pdf", scannedStub);
  assert.equal(scannedRes.needsZeroRetentionOcrFallback, true);
});

test("Pre-Flight Linter catches Wiz Cloud Event vs Cloud Config Rego traps and 4096-byte cap", () => {
  const brokenWizEvent = `package wiz\nmatch {\n  input.ErrorCode == ""\n}\n` + "#".repeat(4100);
  const badReport = runDacPreFlightLinter("wiz_cloud_event_rego", brokenWizEvent);
  assert.equal(badReport.passed, false);
  const codes = new Set(badReport.issues.map((i) => i.code));
  assert.ok(codes.has("WIZ_EVENT_REGO_4096_BYTE_LIMIT"));
  assert.ok(codes.has("WIZ_EVENT_REGO_FORBIDDEN_PACKAGE"));
  assert.ok(codes.has("WIZ_EVENT_EMPTY_FIELD_TRAP"));

  const cleanEvent = runDacPreFlightLinter(
    "wiz_cloud_event_rego",
    SAMPLE_RULES_BY_SURFACE.wiz_cloud_event_rego,
  );
  assert.equal(cleanEvent.passed, true);

  const cleanConfig = runDacPreFlightLinter(
    "wiz_cloud_config_rego",
    SAMPLE_RULES_BY_SURFACE.wiz_cloud_config_rego,
  );
  assert.equal(cleanConfig.passed, true);
});

test("Pre-Flight Linter enforces Falcon IOC action matrix, RFC1918 block, RE2 lookarounds, and YARA-L $count", () => {
  const badIocs = JSON.stringify([
    { type: "domain", value: "evil-login.org", action: "prevent" },
    { type: "ipv4", value: "10.24.1.5", action: "detect" },
    { type: "domain", value: "sso.example-corp.com", action: "detect" },
  ]);
  const iocReport = runDacPreFlightLinter("falcon_ioc", badIocs);
  assert.equal(iocReport.passed, false);
  const iocCodes = new Set(iocReport.issues.map((i) => i.code));
  assert.ok(iocCodes.has("FALCON_IOC_INVALID_NETWORK_ACTION"));
  assert.ok(iocCodes.has("FALCON_IOC_RFC1918_PRIVATE_IP"));
  assert.ok(iocCodes.has("FALCON_IOC_PROTECTED_CORP_DOMAIN"));

  const badIoa = JSON.stringify({
    ruletype_id: "12",
    disposition_id: 30,
    pattern_severity: "high",
    pattern: "(?i)^(?!.*legit_agent).*curl",
  });
  const ioaReport = runDacPreFlightLinter("falcon_ioa", badIoa);
  assert.equal(ioaReport.passed, false);
  assert.ok(ioaReport.issues.some((i) => i.code === "FALCON_IOA_RE2_LOOKAROUND"));
  assert.ok(ioaReport.issues.some((i) => i.code === "FALCON_IOA_LINUX_KILL_SEMANTICS"));

  const badYaral = `rule test_rule {\n  meta:\n    author = "secops"\n  events:\n    $e.target.hostname = /web/i\n  outcome:\n    $count = count($e.metadata.id)\n  condition:\n    $e\n}`;
  const yaralReport = runDacPreFlightLinter("secops_yaral", badYaral, {
    lifecycleMode: "update_existing_rule",
  });
  assert.equal(yaralReport.passed, false);
  const yaralCodes = new Set(yaralReport.issues.map((i) => i.code));
  assert.ok(yaralCodes.has("YARAL_RESERVED_COUNT_VAR"));
  assert.ok(yaralCodes.has("YARAL_INVALID_REGEX_MODIFIER"));
  assert.ok(yaralCodes.has("DAC_UPDATE_MISSING_ID"));
});

test("Zero-Retention pipeline correlates CSV context and splits safe vs rollback-gated containment", () => {
  assert.throws(() =>
    buildZeroRetentionPayload("gemini-2.5-pro", "leaked glpat-AbCdEfGhIjKlMnOpQrSt12"),
  );

  const redacted = redactSensitiveTelemetry(ACME_CLOUD_INTRUSION_PRESET.rawTelemetry);
  const result = runDeterministicInvestigationPipeline(redacted.sanitizedText);
  assert.equal(result.zeroRetentionEnforced, true);
  assert.equal(result.triageJudge.classification, "CONFIRMED_THREAT");
  assert.ok(result.triageJudge.confirmingEvidence.length >= 2);
  assert.ok(result.triageJudge.disconfirmingEvidence.length >= 1);
  assert.ok(result.scribeResponsePlan.immediateSafeActions.length >= 1);
  assert.ok(
    result.scribeResponsePlan.productionSensitiveActions.every(
      (a) => Boolean(a.rollbackPlan) && a.requiresHumanApproval,
    ),
  );

  const exitedCheck = correlateSanitizedTextWithContext(
    "Alert on jordan.chen@example-corp.com uploading to Mega.nz from CORP-LAPTOP-099",
  );
  assert.ok(exitedCheck.riskFlags.some((f) => f.includes("Post-termination")));
  assert.ok(exitedCheck.riskFlags.some((f) => f.includes("Unsanctioned")));
});
