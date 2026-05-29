# Unit tests for data.nist_800_53.main. Run: `opa test rego-overlay/`.

package nist_800_53.main_test

import rego.v1

import data.nist_800_53.main

_clean := {"framework_facts": {
	"filesystem": {"gpg_keys_present": true, "auto_updates_enabled": true},
	"ssh": {"sshd_config_present": true, "permit_root_login": "no", "permit_empty_passwords": "no"},
	"selinux": {"status": "enabled", "mode": "enforcing"},
	"services": {"enabled": ["sshd.service"]},
	"filesystem_permissions": {"paths": [
		{"path": "/etc/passwd", "mode": "0644", "owner": "root", "exists": true},
		{"path": "/etc/shadow", "mode": "0000", "owner": "root", "exists": true},
	]},
	"crypto": {"fips_enabled": true, "crypto_policy": "FIPS"},
}}

_dirty := {"framework_facts": {
	"filesystem": {"gpg_keys_present": false, "auto_updates_enabled": false},
	"ssh": {"sshd_config_present": true, "permit_root_login": "yes", "permit_empty_passwords": "yes"},
	"selinux": {"status": "disabled"},
	"services": {"enabled": ["telnet.socket"]},
	"filesystem_permissions": {"paths": [
		{"path": "/etc/passwd", "mode": "0666", "owner": "root", "exists": true},
		{"path": "/etc/shadow", "mode": "0644", "owner": "root", "exists": true},
	]},
	"crypto": {"fips_enabled": false},
}}

test_clean_host_is_compliant if {
	report := main.compliance_report with input as _clean
	report.compliant == true
	report.violation_count == 0
	report.compliance_percentage == 100
	report.framework == "nist_800_53"
}

test_dirty_host_flags_nist_families if {
	report := main.compliance_report with input as _dirty
	report.compliant == false
	controls := {v.control | some v in report.violations}
	# every implemented family fires on the fully-bad host
	controls == {"AC-3(4)", "AC-6", "IA-5", "CM-6", "SC-28", "SC-13", "SI-2", "SI-7", "CM-7"}
}

test_total_controls_and_safe_empty if {
	report := main.compliance_report with input as {}
	report.total_controls == 9
	is_boolean(report.compliant)
}
