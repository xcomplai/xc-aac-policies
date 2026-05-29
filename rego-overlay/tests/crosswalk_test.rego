# Unit tests for data.aac.crosswalk. Run: `opa test rego-overlay/`.

package aac.crosswalk_test

import rego.v1

import data.aac.crosswalk

# 8 checks: 3+3+3+3+3+3+2+3 = 23 (framework,control) mappings.
test_mappings_count if {
	count(crosswalk.mappings) == 26
}

test_control_for if {
	crosswalk.control_for("ssh_root_login_disabled", "nist_800_53") == "AC-6"
	crosswalk.control_for("etc_shadow_perms", "stig_rhel9") == "RHEL-09-232035"
	# auto_updates has no STIG control → undefined
	not crosswalk.control_for("auto_updates", "stig_rhel9")
}

test_frameworks_for if {
	crosswalk.frameworks_for("selinux_enforcing") == {"cis_rhel9", "stig_rhel9", "nist_800_53"}
	crosswalk.frameworks_for("auto_updates") == {"cis_rhel9", "nist_800_53"}
}

test_coverage if {
	crosswalk.coverage["ssh_root_login_disabled"] == 3
	crosswalk.coverage["auto_updates"] == 2
}

test_reverse_lookup if {
	# STIG RHEL-09-255045 maps back to the canonical ssh_root_login_disabled check
	crosswalk.check_for_control["stig_rhel9"]["RHEL-09-255045"] == "ssh_root_login_disabled"
	crosswalk.check_for_control["cis_rhel9"]["6.1.1"] == "etc_passwd_perms"
}
