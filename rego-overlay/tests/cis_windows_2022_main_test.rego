# Unit tests for data.cis_windows_2022.main (windows host plane).
# Run: `opa test rego-overlay/`.

package cis_windows_2022.main_test

import rego.v1

import data.cis_windows_2022.main

_clean := {"framework_facts": {
	"account_policy": {
		"password_history": 24,
		"max_password_age": 60,
		"min_password_length": 14,
		"password_complexity": true,
		"lockout_threshold": 5,
		"lockout_duration": 15,
	},
	"audit_policy": {"logon_success": true, "logon_failure": true},
	"firewall": {"domain_enabled": true, "private_enabled": true, "public_enabled": true},
	"registry": {"smb1_enabled": false, "guest_account_enabled": false},
	"services": {"enabled": ["W32Time", "EventLog"]},
}}

_dirty := {"framework_facts": {
	"account_policy": {
		"password_history": 0,
		"max_password_age": 0,
		"min_password_length": 8,
		"password_complexity": false,
		"lockout_threshold": 0,
		"lockout_duration": 0,
	},
	"audit_policy": {"logon_success": false, "logon_failure": false},
	"firewall": {"domain_enabled": false, "private_enabled": false, "public_enabled": false},
	"registry": {"smb1_enabled": true, "guest_account_enabled": true},
	"services": {"enabled": ["TlntSvr", "SNMP", "EventLog"]},
}}

test_clean_host_is_compliant if {
	report := main.compliance_report with input as _clean
	report.compliant == true
	report.violation_count == 0
	report.compliance_percentage == 100
	report.framework == "cis_windows_2022"
}

test_dirty_host_flags_all if {
	report := main.compliance_report with input as _dirty
	report.compliant == false
	controls := {v.control | some v in report.violations}
	# every implemented control fires on the fully-bad host
	controls == {
		"1.1.1", "1.1.2", "1.1.4", "1.1.5",
		"1.2.1", "1.2.2",
		"2.3.1.2",
		"9.1.1", "9.2.1", "9.3.1",
		"17.5.1",
		"18.3.1",
		"5.1",
	}
}

# max_password_age=0 ("never expires") and lockout_threshold=0 ("never lock
# out") are both non-compliant despite being "0" — guard the inverted logic.
test_zero_means_non_compliant if {
	report := main.compliance_report with input as _dirty
	controls := {v.control | some v in report.violations}
	"1.1.2" in controls # max_password_age=0
	"1.2.2" in controls # lockout_threshold=0
}

# Only the insecure enabled services should drive 5.1 (EventLog is benign).
test_insecure_services_caught if {
	report := main.compliance_report with input as _dirty
	some v in report.violations
	v.control == "5.1"
}

test_total_controls_and_safe_empty if {
	report := main.compliance_report with input as {}
	report.total_controls == 13
	is_boolean(report.compliant)
}
