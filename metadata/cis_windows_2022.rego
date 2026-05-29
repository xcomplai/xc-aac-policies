# Metadata for CIS Microsoft Windows Server 2022 Benchmark — the first WINDOWS
# host-plane framework (Tier 3.K windows track). Routed to opa-security like the
# Linux frameworks, but its gather collection is the (future) xcomplai.aac_windows,
# which collects host state over WinRM/PowerShell — not the Linux host gatherer
# (xcomplai.aac_common) and not the per-account cloud gatherer.
#
# Like Linux (and unlike cloud), Windows is assessed PER HOST, so it dispatches
# through the per-host generic_framework_assessment.yml: its gather role is named
# `gather` so the generic `{{ collection }}.gather` include resolves unchanged.
#
# Transitional overlay: injected into the bundle at CI build.

package cis_windows_2022.metadata

import rego.v1

default schema := "fact_contract/v1"

default display_name := "CIS Microsoft Windows Server 2022 Benchmark v3.0.0"

default framework_key := "cis_windows_2022"

default framework_version := "v3.0.0"

default domain := "security"

# Windows host data plane: a WinRM/PowerShell gatherer, NOT xcomplai.aac_common
# (Linux) or xcomplai.aac_cloud (per-account).
default collection := "xcomplai.aac_windows"

default collection_version_min := "0.1.0"

default opa_endpoint_path := "/v1/data/cis_windows_2022/main/compliance_report"

default pg_table := "compliance_results"

default dashboard_uid := "aac-framework-report"

# Windows host nouns (gathered over WinRM), not Linux host nouns or cloud nouns.
default facts_schema := {
	"framework_facts": {
		"account_policy": [
			"password_history",
			"max_password_age",
			"min_password_length",
			"password_complexity",
			"lockout_threshold",
			"lockout_duration",
		],
		"audit_policy": ["logon_success", "logon_failure"],
		"firewall": ["domain_enabled", "private_enabled", "public_enabled"],
		"registry": ["smb1_enabled", "guest_account_enabled"],
		"services": ["enabled"],
	},
	"assessment_target": "windows_host",
}
