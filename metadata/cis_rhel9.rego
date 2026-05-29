# Metadata for CIS RHEL 9 — consumed by xcomplai/xc-aac's
# generic_framework_assessment.yml at data.cis_rhel9.metadata and aggregated
# into data.aac.catalog by metadata/aac_catalog.rego.
#
# Per docs/architecture/FACT_CONTRACT.md (Tier 3.G) in xcomplai/xc-aac.
#
# Transitional overlay: this file is injected into the bundle at CI build time
# (release-bundle.yml copies ./metadata/* into ./rego_src before `opa build`).
# Upstream goal is for the rego library (ynotbhatc/rego_policy_libraries) to
# carry this declaration in cis_rhel9/cis_rhel9_metadata.rego directly; the
# overlay goes away then.

package cis_rhel9.metadata

import rego.v1

default schema := "fact_contract/v1"
default display_name := "CIS Red Hat Enterprise Linux 9 v2.0.0"
default framework_key := "cis_rhel9"
default framework_version := "2.0.0"
default domain := "security"
default collection := "xcomplai.aac_common"
default collection_version_min := "1.0.0"
default opa_endpoint_path := "/v1/data/cis_rhel9/main/compliance_report"
default pg_table := "compliance_results"
default dashboard_uid := "cis-rhel9"

default facts_schema := {
	"framework_facts": {
		"filesystem": [
			"auto_updates_enabled",
			"yum_repos",
			"gpg_keys_present",
		],
		"ssh": [
			"sshd_config_present",
			"sshd_config_raw",
			"permit_root_login",
			"permit_empty_passwords",
			"protocol",
		],
		"selinux": [
			"status",
			"mode",
			"type",
			"policy_version",
		],
		"services": [
			"service_mgr",
			"running",
			"enabled",
		],
		"filesystem_permissions": ["paths"],
		"crypto": ["fips_enabled", "crypto_policy"],
	},
	"required_ansible_facts": [
		"ansible_distribution",
		"ansible_distribution_major_version",
		"ansible_kernel",
		"ansible_service_mgr",
		"ansible_mounts",
	],
}
