# Unit tests for data.stig_rhel9.main. Run: `opa test rego-overlay/`.
# Includes the cases where STIG is STRICTER than CIS (same facts → STIG fails).

package stig_rhel9.main_test

import rego.v1

import data.stig_rhel9.main

_clean := {"framework_facts": {
	"filesystem": {"gpg_keys_present": true},
	"ssh": {"sshd_config_present": true, "permit_root_login": "no", "permit_empty_passwords": "no"},
	"selinux": {"status": "enabled", "mode": "enforcing"},
	"services": {"enabled": ["sshd.service"]},
	"filesystem_permissions": {"paths": [
		{"path": "/etc/passwd", "mode": "0644", "owner": "root", "exists": true},
		{"path": "/etc/shadow", "mode": "0000", "owner": "root", "exists": true},
	]},
	"crypto": {"fips_enabled": true, "crypto_policy": "FIPS"},
}}

# A host that PASSES CIS but FAILS STIG: SELinux permissive (CIS 1.6.1.2 ok),
# /etc/shadow 0640 (CIS allows, STIG requires 0000).
_cis_ok_stig_strict := {"framework_facts": {
	"filesystem": {"gpg_keys_present": true},
	"ssh": {"sshd_config_present": true, "permit_root_login": "no", "permit_empty_passwords": "no"},
	"selinux": {"status": "enabled", "mode": "permissive"},
	"services": {"enabled": ["sshd.service"]},
	"filesystem_permissions": {"paths": [
		{"path": "/etc/passwd", "mode": "0644", "owner": "root", "exists": true},
		{"path": "/etc/shadow", "mode": "0640", "owner": "root", "exists": true},
	]},
}}

test_clean_host_is_compliant if {
	report := main.compliance_report with input as _clean
	report.compliant == true
	report.violation_count == 0
	report.compliance_percentage == 100
	report.framework == "stig_rhel9"
}

test_stig_stricter_than_cis if {
	report := main.compliance_report with input as _cis_ok_stig_strict
	report.compliant == false
	controls := {v.control | some v in report.violations}
	# SELinux permissive → STIG enforcing control fires
	"RHEL-09-431015" in controls
	# /etc/shadow 0640 → STIG 0000-only control fires (CIS would pass this)
	"RHEL-09-232035" in controls
}

test_total_controls_and_safe_empty if {
	report := main.compliance_report with input as {}
	report.total_controls == 8
	is_boolean(report.compliant)
}
