# Metadata for NIST SP 800-53 Rev 5 (technical subset) — consumed by
# xcomplai/xc-aac's generic_framework_assessment.yml at data.nist_800_53.metadata
# and aggregated into data.aac.catalog.
#
# NIST is a control CATALOG, not a host checklist: this covers the TECHNICAL
# control families derivable from the host facts the gatherer already produces
# (AC / IA / CM / SC / SI), reusing the same nouns as CIS/STIG. Organisational/
# process controls (PM, PL, PS, …) are out of host-gather scope and are NOT
# evaluated here (report them via a separate evidence process). FIPS / crypto
# (SC-13) is deferred until xcomplai.aac_common gathers a `crypto` noun.
#
# Transitional overlay: injected into the bundle at CI build (Tier 3.K).

package nist_800_53.metadata

import rego.v1

default schema := "fact_contract/v1"

default display_name := "NIST SP 800-53 Rev 5 (technical subset)"

default framework_key := "nist_800_53"

default framework_version := "Rev5"

default domain := "security"

default collection := "xcomplai.aac_common"

default collection_version_min := "1.0.0"

default opa_endpoint_path := "/v1/data/nist_800_53/main/compliance_report"

default pg_table := "compliance_results"

default dashboard_uid := "aac-framework-report"

default facts_schema := {
	"framework_facts": {
		"filesystem": ["gpg_keys_present", "auto_updates_enabled"],
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
