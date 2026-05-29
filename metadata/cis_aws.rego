# Metadata for CIS AWS Foundations Benchmark — the first CLOUD-plane framework
# (Tier 3.K cloud track). Routed to opa-security like the Linux frameworks, but
# its gather collection is the (future) xcomplai.aac_cloud, which queries AWS
# APIs PER ACCOUNT — not the Linux host gatherer.
#
# Transitional overlay: injected into the bundle at CI build.

package cis_aws.metadata

import rego.v1

default schema := "fact_contract/v1"

default display_name := "CIS AWS Foundations Benchmark v3.0.0"

default framework_key := "cis_aws"

default framework_version := "v3.0.0"

default domain := "security"

# Cloud data plane: a per-account API gatherer, NOT xcomplai.aac_common (Linux).
default collection := "xcomplai.aac_cloud"

default collection_version_min := "0.1.0"

default opa_endpoint_path := "/v1/data/cis_aws/main/compliance_report"

default pg_table := "compliance_results"

default dashboard_uid := "aac-framework-report"

# Cloud nouns (gathered from AWS APIs per account), not host nouns.
default facts_schema := {
	"framework_facts": {
		"iam": ["root_mfa_enabled", "root_access_keys_present", "password_policy"],
		"s3": ["buckets"],
		"cloudtrail": ["enabled", "multi_region", "log_file_validation"],
		"security_groups": ["groups"],
		"vpc": ["flow_logs_enabled"],
	},
	"assessment_target": "aws_account",
}
