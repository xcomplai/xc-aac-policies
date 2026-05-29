# Unit tests for data.cis_rhel9.main (Tier 3.J overlay). Run: `opa test rego-overlay/`.
# Lives under tests/ so the bundle CI's `cp rego-overlay/*.rego` does NOT ship it.

package cis_rhel9.main_test

import rego.v1

import data.cis_rhel9.main

_clean := {"framework_facts": {
	"filesystem": {"gpg_keys_present": true, "auto_updates_enabled": true},
	"ssh": {"sshd_config_present": true, "permit_root_login": "no", "permit_empty_passwords": ""},
	"selinux": {"status": "enabled", "mode": "enforcing"},
	"services": {"enabled": ["sshd.service"]},
	"filesystem_permissions": {"paths": [
		{"path": "/etc/passwd", "mode": "0644", "owner": "root", "exists": true},
		{"path": "/etc/shadow", "mode": "0000", "owner": "root", "exists": true},
	]},
	"crypto": {"fips_enabled": true, "crypto_policy": "DEFAULT"},
}}

_dirty := {"framework_facts": {
	"filesystem": {"gpg_keys_present": false, "auto_updates_enabled": false},
	"ssh": {"sshd_config_present": true, "permit_root_login": "yes", "permit_empty_passwords": "yes"},
	"selinux": {"status": "enabled", "mode": "permissive"},
	"services": {"enabled": ["telnet.socket", "sshd.service"]},
	"filesystem_permissions": {"paths": [
		{"path": "/etc/passwd", "mode": "0666", "owner": "root", "exists": true},
		{"path": "/etc/shadow", "mode": "0644", "owner": "root", "exists": true},
	]},
	"crypto": {"fips_enabled": false, "crypto_policy": "LEGACY"},
}}

test_clean_host_is_compliant if {
	report := main.compliance_report with input as _clean
	report.compliant == true
	report.violation_count == 0
	report.compliance_percentage == 100
	report.passed_controls == report.total_controls
}

test_dirty_host_is_not_compliant if {
	report := main.compliance_report with input as _dirty
	report.compliant == false
	report.violation_count == 9
}

test_dirty_host_flags_permit_root_login if {
	report := main.compliance_report with input as _dirty
	some v in report.violations
	v.control == "5.1.22"
}

# SELinux is enabled but permissive → "not disabled" (1.6.1.2) passes,
# "enforcing" (1.6.1.3) fails. Guards that distinction.
test_selinux_enabled_but_permissive if {
	report := main.compliance_report with input as _dirty
	controls := {v.control | some v in report.violations}
	"1.6.1.3" in controls
	not "1.6.1.2" in controls
}

# Unset PermitEmptyPasswords (defaults to "no") must NOT be flagged.
test_unset_empty_passwords_not_flagged if {
	report := main.compliance_report with input as _clean
	controls := {v.control | some v in report.violations}
	not "5.1.23" in controls
}

# Missing framework_facts must not crash — returns a well-formed report.
test_empty_input_is_safe if {
	report := main.compliance_report with input as {}
	report.total_controls == 10
	is_boolean(report.compliant)
}
