# Metadata for DISA STIG RHEL 9 — consumed by xcomplai/xc-aac's
# generic_framework_assessment.yml at data.stig_rhel9.metadata and aggregated
# into data.aac.catalog by metadata/aac_catalog.rego.
#
# STIG reuses the SAME framework_facts nouns as CIS RHEL 9 (it evaluates the
# same host state, with stricter thresholds + DISA control IDs) — so the
# collection (xcomplai.aac_common) gathers once and both frameworks evaluate it.
#
# Transitional overlay: injected into the bundle at CI build (Tier 3.K).

package stig_rhel9.metadata

import rego.v1

default schema := "fact_contract/v1"

default display_name := "DISA STIG for Red Hat Enterprise Linux 9"

default framework_key := "stig_rhel9"

default framework_version := "V2R3"

default domain := "security"

default collection := "xcomplai.aac_common"

default collection_version_min := "1.0.0"

default opa_endpoint_path := "/v1/data/stig_rhel9/main/compliance_report"

default pg_table := "compliance_results"

default dashboard_uid := "aac-framework-report"

# Same nouns as CIS RHEL 9 — STIG evaluates the same host state.
default facts_schema := {
	"framework_facts": {
		"filesystem": ["gpg_keys_present"],
		"ssh": ["sshd_config_present", "permit_root_login", "permit_empty_passwords"],
		"selinux": ["status", "mode"],
		"services": ["enabled"],
		"filesystem_permissions": ["paths"],
	},
	"required_ansible_facts": [
		"ansible_distribution",
		"ansible_distribution_major_version",
	],
}
