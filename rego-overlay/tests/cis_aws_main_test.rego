# Unit tests for data.cis_aws.main (cloud plane). Run: `opa test rego-overlay/`.

package cis_aws.main_test

import rego.v1

import data.cis_aws.main

_clean := {"framework_facts": {
	"iam": {"root_mfa_enabled": true, "root_access_keys_present": false, "password_policy": {"minimum_length": 14}},
	"s3": {"buckets": [
		{"name": "logs", "encryption_enabled": true, "public_access_blocked": true},
		{"name": "data", "encryption_enabled": true, "public_access_blocked": true},
	]},
	"cloudtrail": {"enabled": true, "multi_region": true, "log_file_validation": true},
	"security_groups": {"groups": [{"id": "sg-1", "ingress": [{"cidr": "10.0.0.0/8", "from_port": 22, "to_port": 22}]}]},
	"vpc": {"flow_logs_enabled": true},
}}

_dirty := {"framework_facts": {
	"iam": {"root_mfa_enabled": false, "root_access_keys_present": true, "password_policy": {"minimum_length": 8}},
	"s3": {"buckets": [
		{"name": "logs", "encryption_enabled": false, "public_access_blocked": true},
		{"name": "public", "encryption_enabled": true, "public_access_blocked": false},
	]},
	"cloudtrail": {"enabled": true, "multi_region": false, "log_file_validation": false},
	"security_groups": {"groups": [{"id": "sg-open", "ingress": [{"cidr": "0.0.0.0/0", "from_port": 0, "to_port": 65535}]}]},
	"vpc": {"flow_logs_enabled": false},
}}

test_clean_account_is_compliant if {
	report := main.compliance_report with input as _clean
	report.compliant == true
	report.violation_count == 0
	report.compliance_percentage == 100
	report.framework == "cis_aws"
}

test_dirty_account_flags_all if {
	report := main.compliance_report with input as _dirty
	report.compliant == false
	controls := {v.control | some v in report.violations}
	# every implemented control fires on the fully-bad account
	controls == {"1.4", "1.5", "1.8", "2.1.1", "2.1.4", "3.1", "3.2", "3.9", "5.2"}
}

# 0.0.0.0/0 over a wide port range (0-65535) must be caught for 22 and 3389.
test_world_open_admin_port_caught if {
	report := main.compliance_report with input as _dirty
	some v in report.violations
	v.control == "5.2"
}

test_total_controls_and_safe_empty if {
	report := main.compliance_report with input as {}
	report.total_controls == 9
	is_boolean(report.compliant)
}
