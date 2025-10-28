package report.verify

import rego.v1

# --- config -----------------------------------------------------
default required := {
  "linting":                 true,
  "formatting":              true,
  "vulnerability_check":     false,
  "commit_verification":     false,
  "env_variables_check":     false,
  "slsa_check":              true,
}

default min_test_coverage := 20.0

default warn_as_fail := {
  "linting": false,
}

allowed_ports := {80, 443, 8080, 9090}
allowed_env_vars := {"APP_ENV", "LOG_LEVEL", "DB_HOST", "DB_USER"}

# ---------------------------------------------------------------

flat_report := inspect.print_report_strings(input)

default stored_hash := ""
stored_hash := s if {
  input.metadata
  s := input.metadata.report_sha256
  s != null
  s != ""
}

missing_stored if stored_hash == ""

calculated_hash := crypto.sha256(flat_report)

hash_match if {
  not missing_stored
  stored_hash == calculated_hash
}

# helpers
is_required(name) := b if {
  b := required[name]
} else := false

status_bad(name, s) if s == "FAILED"
status_bad(name, s) if {
  warn_as_fail[name]
  s == "WARNING"
}

section_failures := {
  k: sect |
  some k
  sect := input.report[k]
  is_required(k)
  status_bad(k, sect.status)
}

custom_failures := {
  sprintf("custom:%s", [item.name]): item |
  some i
  item := input.report.custom_checks[i]
  n := sprintf("custom:%s", [item.name])
  is_required(n)
  status_bad(n, item.status)
}

failures := object.union(section_failures, custom_failures)

# denies
deny contains msg if {
  missing_stored
  msg := "metadata.report_sha256 is missing"
}

deny contains msg if {
  not missing_stored
  calculated_hash != stored_hash
  msg := sprintf("hash mismatch: stored=%s calculated=%s", [stored_hash, calculated_hash])
}
deny contains msg if {
    manifest := input.report.manifest_scan.kubernetes_manifests[_]
    port_info := manifest.exposed_ports[_]
    print("port info", port_info)
    not port_info.port in allowed_ports
    msg := sprintf("Port %v in %v is not allowed", [port_info.port, manifest.name])
}

deny contains msg if {
  some k
  failures[k]
  msg := sprintf("required check failed: %s", [k])
}

deny contains msg if {
  coverage := input.report.test_coverage.coverage_percent
  coverage < min_test_coverage
  msg := sprintf("test coverage %.1f%% is below minimum required %.1f%%", [coverage, min_test_coverage])
}
# deny contains msg if {
#     manifest := input.report.manifest_scan.kubernetes_manifests[_]
#     port_info := manifest.exposed_ports[_]
#     not port_info.port in allowed_ports
#     msg := sprintf("Port %v in %v is not allowed", [port_info.port, manifest.name])
# }

summary := {
  "hash": {
    "stored":     stored_hash,
    # "calculated": calculated_hash,
    # "match":      hash_match,
  },
  "required":     required,
  "warn_as_fail": warn_as_fail,
  "deny":         deny,
  "ok":           count(deny) == 0,
}

result := {
  "summary":  summary,
  "failures": failures,
}
