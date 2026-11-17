import React, { useMemo, useState } from "react";
import {
  runDacPreFlightLinter,
  type RuleSurface,
} from "../shared/dacPreFlightLinter.ts";
import {
  ACME_CLOUD_INTRUSION_PRESET,
  SAMPLE_RULES_BY_SURFACE,
} from "../shared/demoPresets.ts";
import {
  exportSanitizedCaseBundle,
  redactSensitiveTelemetry,
} from "../shared/redactor.ts";
import {
  extractDocxLocally,
  extractPdfTwoPass,
} from "./utils/documentExtractor.ts";

export function App(): React.ReactElement {
  const [rawInput, setRawInput] = useState<string>(ACME_CLOUD_INTRUSION_PRESET.rawTelemetry);
  const [surface, setSurface] = useState<RuleSurface>("wiz_cloud_event_rego");
  const [ruleCode, setRuleCode] = useState<string>(SAMPLE_RULES_BY_SURFACE.wiz_cloud_event_rego);
  const [intakeNote, setIntakeNote] = useState<string>("Ready — secrets stay in browser RAM only.");

  const redaction = useMemo(() => redactSensitiveTelemetry(rawInput), [rawInput]);
  const lintReport = useMemo(() => runDacPreFlightLinter(surface, ruleCode), [surface, ruleCode]);

  async function handleFileDrop(ev: React.ChangeEvent<HTMLInputElement>): Promise<void> {
    const file = ev.target.files?.[0];
    if (!file) return;
    const bytes = new Uint8Array(await file.arrayBuffer());
    if (file.name.toLowerCase().endsWith(".docx")) {
      const doc = await extractDocxLocally(file.name, bytes);
      setRawInput(doc.markdownText);
      setIntakeNote(`Extracted ${file.name} locally via PKZIP/Deflate (0 LLM calls).`);
    } else if (file.name.toLowerCase().endsWith(".pdf")) {
      const doc = await extractPdfTwoPass(file.name, bytes);
      setRawInput(doc.markdownText);
      setIntakeNote(
        doc.needsZeroRetentionOcrFallback
          ? `Scanned/CID PDF detected (${file.name}) — queued for zero-retention OCR fallback.`
          : `Extracted ${file.name} locally via /FlateDecode stream parser.`,
      );
    } else {
      setRawInput(new TextDecoder().decode(bytes));
      setIntakeNote(`Loaded text artifact: ${file.name}`);
    }
  }

  function handleExportCaseJson(): void {
    const bundle = exportSanitizedCaseBundle("CASE-ACME-001", redaction, {
      activeRuleSurface: surface,
      preFlightPassed: lintReport.passed,
    });
    const blob = new Blob([JSON.stringify(bundle, null, 2)], { type: "application/json" });
    const href = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = href;
    a.download = "sift-air-sanitized-case.json";
    a.click();
    URL.revokeObjectURL(href);
  }

  return (
    <main style={{ maxWidth: 1180, margin: "0 auto", padding: 24 }}>
      <header style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <div>
          <h1 style={{ margin: 0 }}>SIFT-AIR Workbench</h1>
          <p style={{ margin: "6px 0 0", color: "#94a3b8" }}>
            Zero-Retention DFIR, Threat Hunting & Multi-Platform Detection-as-Code Studio
          </p>
        </div>
        <button onClick={handleExportCaseJson} style={{ padding: "8px 14px", cursor: "pointer" }}>
          Export Sanitized Case JSON
        </button>
      </header>

      <section style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16, marginTop: 20 }}>
        <div>
          <h3>1. Raw Telemetry / .PDF / .DOCX Dropzone (Browser RAM Only)</h3>
          <input type="file" accept=".pdf,.docx,.txt,.log,.json,.eml,.yaral" onChange={handleFileDrop} />
          <p style={{ fontSize: 13, color: "#38bdf8" }}>{intakeNote}</p>
          <textarea
            value={rawInput}
            onChange={(e) => setRawInput(e.target.value)}
            rows={10}
            style={{ width: "100%", background: "#111827", color: "#f8fafc", padding: 10 }}
          />
        </div>

        <div>
          <h3>
            2. Gatekeeper Sanitized Payload ({redaction.totalRedactions} secrets scrubbed)
          </h3>
          <pre
            style={{
              background: "#0f172a",
              border: "1px solid #1e293b",
              padding: 12,
              whiteSpace: "pre-wrap",
              minHeight: 210,
            }}
          >
            {redaction.sanitizedText}
          </pre>
        </div>
      </section>

      <section style={{ marginTop: 24 }}>
        <h3>3. Multi-Platform Detection-as-Code Studio & 0-ms Pre-Flight Linter</h3>
        <select
          value={surface}
          onChange={(e) => {
            const next = e.target.value as RuleSurface;
            setSurface(next);
            if (SAMPLE_RULES_BY_SURFACE[next]) {
              setRuleCode(SAMPLE_RULES_BY_SURFACE[next]);
            }
          }}
          style={{ padding: 8, marginBottom: 10 }}
        >
          <option value="secops_yaral">Google SecOps — YARA-L 2.0</option>
          <option value="falcon_cql">CrowdStrike NG-SIEM — CQL</option>
          <option value="falcon_ioa">CrowdStrike Custom IOA — RE2 Behavioral</option>
          <option value="falcon_ioc">CrowdStrike IOC Management — Action Matrix</option>
          <option value="wiz_cloud_event_rego">Wiz Threat Detection — Cloud Event Rego</option>
          <option value="wiz_cloud_config_rego">Wiz Posture / IaC — Cloud Config Rego</option>
          <option value="wiz_kql">Wiz Threat Detection — Advanced KQL</option>
          <option value="wiz_automation">Wiz Automation — Scoped Playbook</option>
        </select>

        <textarea
          value={ruleCode}
          onChange={(e) => setRuleCode(e.target.value)}
          rows={10}
          style={{ width: "100%", fontFamily: "monospace", background: "#111827", color: "#f8fafc", padding: 10 }}
        />

        <div style={{ marginTop: 10 }}>
          <strong>
            Pre-Flight Status: {lintReport.passed ? "PASS (Ready for Human MR)" : "BLOCKED"} ·{" "}
            {lintReport.utf8ByteLength} UTF-8 bytes
          </strong>
          <ul>
            {lintReport.issues.map((iss, idx) => (
              <li key={idx}>
                [{iss.severity}] <code>{iss.code}</code>: {iss.message} — <em>{iss.remediation}</em>
              </li>
            ))}
          </ul>
        </div>
      </section>
    </main>
  );
}
