# SIFT-AIR — Zero-Retention DFIR, Threat Hunting & Multi-Platform Detection-as-Code Workbench

[![CI](https://github.com/lawaleladipo/sift-air/actions/workflows/ci.yml/badge.svg)](https://github.com/lawaleladipo/sift-air/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Node 22+](https://img.shields.io/badge/node-22%2B-339933.svg)](package.json)

**SIFT-AIR** (*Security Intelligence, Forensic Triage & Autonomous Incident Response*) is a privacy-first **DFIR, Threat Hunting, and Multi-Platform Detection-as-Code (DaC) Workbench** built for Detection & Response Engineers.

It compresses multi-cloud incident triage and threat-advisory-to-rule engineering into one workbench—while **scrubbing secrets inside browser RAM before any network request**, parsing `.docx` and `.pdf` threat advisories locally, enforcing `store: false` zero-retention inference, and policing LLM-generated rules with **deterministic 0-ms pre-flight linters** across **Google SecOps**, **CrowdStrike Falcon**, and **Wiz CNAPP**.

---

## Architectural Guardrails

```text
+-------------------------------------------------------------------------+
|                     Analyst Browser (Trust Boundary)                    |
|                                                                         |
|  [.PDF / .DOCX / Raw Multi-Cloud Logs]                                  |
|           |                                                             |
|           v                                                             |
|  [Local PKZIP (.docx) & /FlateDecode (.pdf) Stream Extractor]           |
|           |                                                             |
|           v                                                             |
|  [Deterministic Regex & Luhn Scrubber] ---> [RAM-Only Secret Vault]     |
+-----------+-------------------------------------------------------------+
            |  Sanitized Bundle Only ([REDACTED_JWT_01], [REDACTED_PAN_01])
            v
+-------------------------------------------------------------------------+
|  Zero-Retention Reasoning Broker (store: false + Offline Fallback)      |
|   • Context Weaver (Self-contained CSV Identity/Endpoint/Cloud Context) |
|   • Triage Judge (Confirming vs. Disconfirming Evidence Rubric)         |
|   • Chronos & Atlas (Dual UTC/Local Timeline + Multi-Plane Graph)       |
|   • Hunter's Compass (Hypotheses + SIEM / EDR / CNAPP Pivot Queries)    |
|   • Forge Compiler (7 Detection & Prevention Rule Surfaces)             |
+-----------+-------------------------------------------------------------+
            |
            v
+-------------------------------------------------------------------------+
|  Deterministic Pre-Flight Linter + Blast-Radius Containment Split       |
|   • Blocks broken syntax, RE2 lookarounds & 4,096B caps BEFORE Git MR   |
+-------------------------------------------------------------------------+
```

### 1. Browser-Side Privacy Gatekeeper + Native `.docx` / `.pdf` Intake
- **Client-side secret scrubbing (`shared/redactor.ts`):** Masks Luhn-validated payment cards (PANs), national IDs, `Bearer` / JWT tokens, GitLab/GitHub PATs (`glpat-`, `ghp_`), AWS keys (`AKIA`/`ASIA`), and PEM private keys *before* any payload leaves browser memory. Even exported peer-handoff Case JSON bundles deterministically strip raw values and the transient `secretVault`.
- **Local binary document parsing (`src/utils/documentExtractor.ts`):** Inflates `.docx` `word/document.xml` via PKZIP Central Directory + `DecompressionStream("deflate-raw")` (preserving IOC Markdown tables in milliseconds with zero LLM calls) and runs local `/FlateDecode` stream extraction on `.pdf` advisories before falling back to zero-retention OCR only on scanned/CID pages.

### 2. Deterministic Pre-Flight Linters Across 7 Rule Surfaces (`shared/dacPreFlightLinter.ts`)
LLMs routinely blend dialects across SIEM, EDR, and CNAPP tools. SIFT-AIR validates rules deterministically in `0 ms`:
- **Google SecOps (YARA-L 2.0):** Catches reserved `$count` outcome identifiers, unsupported `/pattern/i` flags (enforces `/pattern/ nocase`), missing `meta:`/`events:`/`condition:` blocks, and GitOps new-vs-update `rule_id` traps.
- **CrowdStrike Falcon (NG-SIEM CQL, Custom IOAs, IOC API):**
  - Blocks RE2-incompatible Perl lookarounds (`(?!...)`, `(?=...)`) in Custom IOAs and warns on `disposition_id: 30` Linux `Kill Process` (`ruletype_id: 12`) vs. Windows/macOS `Block Execution`.
  - Enforces Falcon's IOC action matrix (`prevent`/`allow` restricted strictly to `sha256`/`md5` hashes—never `domain`/`ipv4`) and blocks RFC1918 private IPs or protected corporate domains that cause fleet-wide alert storms.
- **Wiz CNAPP (Cloud Event Rego, Cloud Config/IaC Rego, KQL, Automation):**
  - Enforces the critical split between **Wiz Cloud Event Rego** (forbids `package` headers, requires `match`, enforces Wiz's **4,096-byte UTF-8 save ceiling**, and catches the `input.ErrorCode == ""` empty-field omission trap) and **Wiz Cloud Configuration Rego** (requires `package wiz` and `result = "pass" | "fail"`).
  - Blocks destructive Wiz Automation rules scoped to `ALL_PROJECTS`.

### 3. Calibrated Triage & Blast-Radius-Split Containment (`server/geminiBroker.ts`)
- **Triage Judge** forces side-by-side **Confirming** and **Disconfirming** evidence to counter LLM sycophancy.
- **Scribe & War-Room** separates **Immediate Safe Actions (Green)** from **Production-Sensitive Actions Requiring Approval (Amber/Red)**—requiring an explicit rollback plan on every shared IAM, Kubernetes, or WAF action, mapped to **PCI-DSS v4.0**, **ISO/IEC 27001:2022**, and **NIST CSF 2.0**.

---

## Quick Start

```bash
git clone https://github.com/lawaleladipo/sift-air.git
cd sift-air
cp .env.example .env

# Run the full zero-dependency deterministic guardrail & linter test suite (Node 22+)
node --experimental-strip-types --test tests/siftAirGuardrails.test.ts

# Optional: install web UI packages and launch both API broker (:8080) and React workbench (:5173)
npm install
npm run dev:server
npm run dev:web
```

### Customizing Asset & Identity Context
Drop your team's sanitized CSVs into [`sample-context/`](sample-context/) (`identities.csv`, `endpoints.csv`, `cloud_projects.csv`, `sanctioned_apps.csv`) to enrich investigations automatically with exited-employee, leave, unmanaged-endpoint, and tier-0 project risk flags.

---

## Author & License

Built by **Olawale Oladipo** ([GitHub](https://github.com/lawaleladipo) · [Medium](https://medium.com/@lawaleladipo) · [LinkedIn](https://www.linkedin.com/in/olawale-oladipo-cybersecurity/)).  
Released under the [MIT License](LICENSE).
