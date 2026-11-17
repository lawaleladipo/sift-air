/**
 * Self-contained CSV Asset, Identity, Endpoint & Cloud Context Correlator
 * Allows any security team to enrich investigations out of the box using local CSVs.
 */

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const DEFAULT_CONTEXT_DIR = path.resolve(__dirname, "..", "sample-context");

function parseCsvFile(filePath: string): Array<Record<string, string>> {
  if (!fs.existsSync(filePath)) return [];
  const lines = fs.readFileSync(filePath, "utf-8").trim().split(/\r?\n/);
  if (lines.length < 2) return [];
  const headers = lines[0].split(",").map((h) => h.trim());
  return lines.slice(1).map((line) => {
    const cols = line.split(",").map((c) => c.trim());
    const row: Record<string, string> = {};
    headers.forEach((h, idx) => {
      row[h] = cols[idx] ?? "";
    });
    return row;
  });
}

export interface ContextCorrelation {
  matchedIdentities: Array<Record<string, string>>;
  matchedEndpoints: Array<Record<string, string>>;
  matchedCloudProjects: Array<Record<string, string>>;
  matchedApps: Array<Record<string, string>>;
  riskFlags: string[];
}

export function correlateSanitizedTextWithContext(
  sanitizedText: string,
  contextDir: string = DEFAULT_CONTEXT_DIR,
): ContextCorrelation {
  const lower = sanitizedText.toLowerCase();
  const identities = parseCsvFile(path.join(contextDir, "identities.csv"));
  const endpoints = parseCsvFile(path.join(contextDir, "endpoints.csv"));
  const projects = parseCsvFile(path.join(contextDir, "cloud_projects.csv"));
  const apps = parseCsvFile(path.join(contextDir, "sanctioned_apps.csv"));

  const matchedIdentities = identities.filter(
    (r) =>
      (r.email && lower.includes(r.email.toLowerCase())) ||
      (r.employee_id && lower.includes(r.employee_id.toLowerCase())),
  );
  const matchedEndpoints = endpoints.filter(
    (r) =>
      (r.hostname && lower.includes(r.hostname.toLowerCase())) ||
      (r.serial_number && lower.includes(r.serial_number.toLowerCase())),
  );
  const matchedCloudProjects = projects.filter(
    (r) => r.project_id && lower.includes(r.project_id.toLowerCase()),
  );
  const matchedApps = apps.filter(
    (r) => r.app_name && lower.includes(r.app_name.toLowerCase()),
  );

  const riskFlags: string[] = [];
  for (const id of matchedIdentities) {
    if (id.status === "EXITED") {
      riskFlags.push(
        `CRITICAL: Post-termination activity detected for ${id.email} (exited ${id.termination_date})`,
      );
    }
    if (id.on_leave === "true") {
      riskFlags.push(`HIGH: Activity observed while employee ${id.email} is marked on leave`);
    }
  }
  for (const ep of matchedEndpoints) {
    if (ep.sase_status === "UNMANAGED" || ep.edr_status !== "ACTIVE") {
      riskFlags.push(
        `HIGH: Endpoint ${ep.hostname} has posture gap (EDR=${ep.edr_status}, SASE=${ep.sase_status})`,
      );
    }
  }
  for (const proj of matchedCloudProjects) {
    if (proj.tier === "tier-0") {
      riskFlags.push(`CRITICAL: Tier-0 cloud project affected (${proj.project_id} — ${proj.product_name})`);
    }
  }
  for (const app of matchedApps) {
    if (app.sanction_status === "UNSANCTIONED") {
      riskFlags.push(`MEDIUM: Unsanctioned SaaS/Cloud tool referenced (${app.app_name})`);
    }
  }

  return {
    matchedIdentities,
    matchedEndpoints,
    matchedCloudProjects,
    matchedApps,
    riskFlags,
  };
}
