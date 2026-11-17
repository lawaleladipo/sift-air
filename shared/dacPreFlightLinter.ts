/**
 * SIFT-AIR Deterministic Multi-Platform Detection-as-Code Pre-Flight Linter
 *
 * Catches platform-breaking rule syntax, byte ceilings, RE2 incompatibilities,
 * IOC action-matrix violations, and cloud empty-field traps in 0 ms before CI or save.
 */

export type RuleSurface =
  | "secops_yaral"
  | "falcon_cql"
  | "falcon_ioa"
  | "falcon_ioc"
  | "wiz_cloud_event_rego"
  | "wiz_kql"
  | "wiz_cloud_config_rego"
  | "wiz_automation";

export type LifecycleMode = "new_rule" | "update_existing_rule";

export interface LintIssue {
  severity: "BLOC_ERROR" | "WARNING";
  code: string;
  message: string;
  remediation: string;
}

export interface LintReport {
  surface: RuleSurface;
  passed: boolean;
  utf8ByteLength: number;
  issues: LintIssue[];
}

export interface FalconIocRecord {
  type: "sha256" | "md5" | "domain" | "ipv4" | "ipv6";
  value: string;
  action: "prevent" | "detect" | "no_action" | "allow";
}

const WIZ_CLOUD_EVENT_MAX_BYTES = 4096;
const RE2_LOOKAROUND_RE = /\(\?(?:!|=|<=|<!)/;
const PRIVATE_IPV4_RE =
  /^(?:10\.|127\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|169\.254\.)/;

export function runDacPreFlightLinter(
  surface: RuleSurface,
  content: string,
  options: {
    lifecycleMode?: LifecycleMode;
    ruleId?: string;
    protectedDomains?: string[];
  } = {},
): LintReport {
  const issues: LintIssue[] = [];
  const utf8ByteLength = new TextEncoder().encode(content).byteLength;
  const lifecycle = options.lifecycleMode ?? "new_rule";
  const protectedDomains = (options.protectedDomains ?? ["example-corp.com", "acme-fintech.example"]).map(
    (d) => d.toLowerCase(),
  );

  if (!content.trim()) {
    issues.push({
      severity: "BLOC_ERROR",
      code: "EMPTY_ARTIFACT",
      message: "Rule content is empty.",
      remediation: "Provide a rule body before exporting or opening a Merge Request.",
    });
    return { surface, passed: false, utf8ByteLength, issues };
  }

  // GitOps Rule-ID Lifecycle Check (SecOps & Falcon NG-SIEM DaC)
  if (surface === "secops_yaral" || surface === "falcon_cql") {
    const hasRuleId = Boolean(options.ruleId?.trim()) || /\brule_id\s*[:=]\s*["']ru_/i.test(content);
    if (lifecycle === "new_rule" && hasRuleId) {
      issues.push({
        severity: "BLOC_ERROR",
        code: "DAC_NEW_RULE_HAS_ID",
        message: "Brand-new GitOps rule pre-fills an existing rule_id.",
        remediation: "Leave rule_id unset on initial creation so the CI pipeline assigns a canonical ID.",
      });
    } else if (lifecycle === "update_existing_rule" && !hasRuleId) {
      issues.push({
        severity: "BLOC_ERROR",
        code: "DAC_UPDATE_MISSING_ID",
        message: "Updating an existing rule without rule_id will create a duplicate rule in production.",
        remediation: "Populate the canonical upstream rule_id in metadata before opening an update MR.",
      });
    }
  }

  switch (surface) {
    case "secops_yaral": {
      for (const section of ["meta:", "events:", "condition:"]) {
        if (!content.includes(section)) {
          issues.push({
            severity: "BLOC_ERROR",
            code: "YARAL_MISSING_SECTION",
            message: `Missing required YARA-L 2.0 '${section}' block.`,
            remediation: `Add a valid '${section}' section to the rule.`,
          });
        }
      }
      if (/\$count\s*=/.test(content)) {
        issues.push({
          severity: "BLOC_ERROR",
          code: "YARAL_RESERVED_COUNT_VAR",
          message: "'$count' is a reserved identifier in Google SecOps YARA-L 2.0.",
          remediation: "Rename outcome variable to '$event_count' or '$hit_count'.",
        });
      }
      if (/\/[^/\n]+\/i\b/.test(content)) {
        issues.push({
          severity: "BLOC_ERROR",
          code: "YARAL_INVALID_REGEX_MODIFIER",
          message: "Inline '/pattern/i' regex flag fails Chronicle YARA-L compilation.",
          remediation: "Use '/pattern/ nocase' syntax instead.",
        });
      }
      if (!/\b(?:mitre|tactic|technique|T\d{4})/i.test(content)) {
        issues.push({
          severity: "WARNING",
          code: "YARAL_MISSING_MITRE",
          message: "No MITRE ATT&CK tactic or technique tag found in meta: block.",
          remediation: "Add mitre_attack_tactic and mitre_attack_technique metadata.",
        });
      }
      break;
    }

    case "falcon_cql": {
      if (!/#event_simpleName|event_simpleName/i.test(content)) {
        issues.push({
          severity: "WARNING",
          code: "CQL_UNSCOPED_EVENT",
          message: "CQL query does not filter on #event_simpleName.",
          remediation: "Constrain #event_simpleName early to prevent expensive full-repo scans.",
        });
      }
      if (RE2_LOOKAROUND_RE.test(content)) {
        issues.push({
          severity: "BLOC_ERROR",
          code: "CQL_UNSUPPORTED_LOOKAROUND",
          message: "Perl lookaround assertion detected in CQL regex.",
          remediation: "Replace negative lookaheads with '!= /pattern/' or CQL exclusion clauses.",
        });
      }
      break;
    }

    case "falcon_ioa": {
      if (RE2_LOOKAROUND_RE.test(content)) {
        issues.push({
          severity: "BLOC_ERROR",
          code: "FALCON_IOA_RE2_LOOKAROUND",
          message: "CrowdStrike Custom IOAs compile with RE2 and reject Perl lookarounds ((?!...), (?=...)).",
          remediation: "Move benign exclusions into the structured field-level 'exclude' pattern array.",
        });
      }
      const sevMatch = content.match(/"pattern_severity"\s*:\s*"?(\w+)"?/i);
      if (sevMatch && !["informational", "low", "medium", "high", "critical", "10", "30", "50", "70", "90"].includes(sevMatch[1].toLowerCase())) {
        issues.push({
          severity: "BLOC_ERROR",
          code: "FALCON_IOA_INVALID_SEVERITY",
          message: `Invalid Falcon IOA severity '${sevMatch[1]}'.`,
          remediation: "Use informational (10), low (30), medium (50), high (70), or critical (90).",
        });
      }
      if (/"ruletype_id"\s*:\s*"12"/.test(content) && /"disposition_id"\s*:\s*30/.test(content)) {
        issues.push({
          severity: "WARNING",
          code: "FALCON_IOA_LINUX_KILL_SEMANTICS",
          message: "Linux Process Creation (ruletype_id 12) with disposition_id 30 executes 'Kill Process' rather than Windows/macOS pre-exec 'Block Execution'.",
          remediation: "Verify production process tree impact on Linux workloads before enabling prevention.",
        });
      }
      break;
    }

    case "falcon_ioc": {
      let parsed: FalconIocRecord[] = [];
      try {
        const json = JSON.parse(content);
        parsed = Array.isArray(json) ? json : json.indicators ?? [json];
      } catch {
        // Parse CSV fallback: type,value,action
        const lines = content.trim().split(/\r?\n/).filter((l) => !l.startsWith("type,"));
        parsed = lines.map((line) => {
          const [type, value, action] = line.split(",").map((s) => s.trim());
          return {
            type: (type as FalconIocRecord["type"]) ?? "domain",
            value: value ?? "",
            action: (action as FalconIocRecord["action"]) ?? "detect",
          };
        });
      }
      for (const ioc of parsed) {
        const t = (ioc.type ?? "").toLowerCase();
        const act = (ioc.action ?? "").toLowerCase();
        const val = (ioc.value ?? "").trim().toLowerCase();

        if (["domain", "ipv4", "ipv6"].includes(t) && (act === "prevent" || act === "allow")) {
          issues.push({
            severity: "BLOC_ERROR",
            code: "FALCON_IOC_INVALID_NETWORK_ACTION",
            message: `Falcon IOC API forbids action '${act}' on indicator type '${t}' (${val}).`,
            remediation:
              "Restrict 'prevent'/'allow' to sha256/md5 hashes; use 'detect' for network IOCs or author a Custom IOA (disposition_id: 30) to block processes on network/DNS.",
          });
        }
        if (t === "ipv4" && PRIVATE_IPV4_RE.test(val)) {
          issues.push({
            severity: "BLOC_ERROR",
            code: "FALCON_IOC_RFC1918_PRIVATE_IP",
            message: `Private/loopback IPv4 '${val}' would trigger a fleet-wide alert storm.`,
            remediation: "Remove internal RFC1918/loopback addresses from external IOC uploads.",
          });
        }
        if (t === "domain" && protectedDomains.some((d) => val === d || val.endsWith(`.${d}`))) {
          issues.push({
            severity: "BLOC_ERROR",
            code: "FALCON_IOC_PROTECTED_CORP_DOMAIN",
            message: `Protected organizational domain '${val}' detected in IOC batch.`,
            remediation: "Strip internal corporate domains before importing IOCs.",
          });
        }
      }
      break;
    }

    case "wiz_cloud_event_rego": {
      if (utf8ByteLength > WIZ_CLOUD_EVENT_MAX_BYTES) {
        issues.push({
          severity: "BLOC_ERROR",
          code: "WIZ_EVENT_REGO_4096_BYTE_LIMIT",
          message: `Wiz Cloud Event Rego is ${utf8ByteLength} bytes, exceeding Wiz's hard ${WIZ_CLOUD_EVENT_MAX_BYTES}-byte save limit.`,
          remediation: "Compact helper sets/comments so UTF-8 byte length stays <= 4,096 bytes.",
        });
      }
      if (/^\s*package\s+\w+/m.test(content)) {
        issues.push({
          severity: "BLOC_ERROR",
          code: "WIZ_EVENT_REGO_FORBIDDEN_PACKAGE",
          message: "Wiz Cloud Event Rules forbid 'package' declarations (unlike Cloud Configuration Rules).",
          remediation: "Remove 'package wiz' and define a top-level 'match { ... }' rule head.",
        });
      }
      if (!/\bmatch\b/.test(content)) {
        issues.push({
          severity: "BLOC_ERROR",
          code: "WIZ_EVENT_REGO_MISSING_MATCH_HEAD",
          message: "Wiz Cloud Event Rego must define a 'match' rule head.",
          remediation: "Add 'match { ... }' (or 'match if { ... }') as the primary rule entrypoint.",
        });
      }
      if (/input\.ErrorCode\s*==\s*""/.test(content)) {
        issues.push({
          severity: "BLOC_ERROR",
          code: "WIZ_EVENT_EMPTY_FIELD_TRAP",
          message: "'input.ErrorCode == \"\"' passes UI test payloads but fails in production because Wiz omits empty keys on live cloud events.",
          remediation: "Check 'input.Result == 0' or 'not input.ErrorCode' instead.",
        });
      }
      break;
    }

    case "wiz_cloud_config_rego": {
      if (!/^\s*package\s+wiz\b/m.test(content)) {
        issues.push({
          severity: "BLOC_ERROR",
          code: "WIZ_CONFIG_MISSING_PACKAGE_WIZ",
          message: "Wiz Cloud Configuration / IaC Rego policies require 'package wiz'.",
          remediation: "Add 'package wiz' at the top of the policy and return result = \"pass\" | \"fail\".",
        });
      }
      if (!/\bresult\s*:=|\bdefault\s+result\s*=/.test(content)) {
        issues.push({
          severity: "BLOC_ERROR",
          code: "WIZ_CONFIG_MISSING_RESULT_HEAD",
          message: "Wiz Cloud Configuration Rego requires a 'result' variable ('pass' / 'fail' / 'skip').",
          remediation: "Declare 'default result = \"pass\"' and set 'result = \"fail\" { ... }'.",
        });
      }
      break;
    }

    case "wiz_kql": {
      if (!/\|\s*where\b/i.test(content)) {
        issues.push({
          severity: "WARNING",
          code: "WIZ_KQL_UNFILTERED",
          message: "Wiz Advanced Query (KQL) has no '| where' predicate.",
          remediation: "Add '| where' predicates and threshold aggregation (e.g. '| summarize count() by ...').",
        });
      }
      break;
    }

    case "wiz_automation": {
      if (/delete|quarantine|revoke|isolate/i.test(content) && /"scope"\s*:\s*"ALL_PROJECTS"/i.test(content)) {
        issues.push({
          severity: "BLOC_ERROR",
          code: "WIZ_AUTOMATION_UNSCOPED_DESTRUCTIVE",
          message: "Destructive Wiz Automation action is scoped to ALL_PROJECTS.",
          remediation: "Scope auto-remediation rules to non-prod or explicit project IDs with human approval.",
        });
      }
      break;
    }
  }

  return {
    surface,
    passed: issues.every((i) => i.severity !== "BLOC_ERROR"),
    utf8ByteLength,
    issues,
  };
}
