# data.aac.crosswalk — control crosswalk across frameworks (Tier 3.K Phase 5).
#
# The same underlying host check satisfies controls in MULTIPLE frameworks
# (CIS / STIG / NIST share most technical checks). This maps each canonical
# check (named for its data.aac.lib.linux predicate) to the control ID it
# satisfies per framework. It's the data behind "assess once, report against
# many": one gather → N framework reports, and one finding → the N controls it
# affects.
#
# Control IDs here MUST match those emitted by the …main.compliance_report rules
# (cis_rhel9 / stig_rhel9 / nist_800_53). Transitional overlay.

package aac.crosswalk

import rego.v1

# Canonical check → human title + per-framework control IDs.
checks := {
	"ssh_root_login_disabled": {
		"title": "SSH direct root login disabled",
		"frameworks": {"cis_rhel9": "5.1.22", "stig_rhel9": "RHEL-09-255045", "nist_800_53": "AC-6"},
	},
	"ssh_empty_passwords_disabled": {
		"title": "SSH empty passwords disabled",
		"frameworks": {"cis_rhel9": "5.1.23", "stig_rhel9": "RHEL-09-255095", "nist_800_53": "IA-5"},
	},
	"selinux_enforcing": {
		"title": "SELinux enabled and enforcing",
		"frameworks": {"cis_rhel9": "1.6.1.3", "stig_rhel9": "RHEL-09-431015", "nist_800_53": "AC-3(4)"},
	},
	"etc_shadow_perms": {
		"title": "/etc/shadow permissions",
		"frameworks": {"cis_rhel9": "6.1.2", "stig_rhel9": "RHEL-09-232035", "nist_800_53": "SC-28"},
	},
	"etc_passwd_perms": {
		"title": "/etc/passwd permissions",
		"frameworks": {"cis_rhel9": "6.1.1", "stig_rhel9": "RHEL-09-232010", "nist_800_53": "CM-6"},
	},
	"gpg_keys_present": {
		"title": "RPM GPG keys present (package signature verification)",
		"frameworks": {"cis_rhel9": "1.2.1", "stig_rhel9": "RHEL-09-215010", "nist_800_53": "SI-7"},
	},
	"auto_updates": {
		"title": "Automatic update tooling configured",
		"frameworks": {"cis_rhel9": "1.2.2", "nist_800_53": "SI-2"},
	},
	"no_insecure_services": {
		"title": "No legacy insecure services enabled",
		"frameworks": {"cis_rhel9": "2.2.1", "stig_rhel9": "RHEL-09-215075", "nist_800_53": "CM-7"},
	},
	"fips_enabled": {
		"title": "FIPS mode enabled",
		"frameworks": {"nist_800_53": "SC-13", "stig_rhel9": "RHEL-09-671010"},
	},
	"crypto_policy_not_legacy": {
		"title": "System-wide crypto policy is not legacy",
		"frameworks": {"cis_rhel9": "1.10"},
	},
}

# Flat triples — easy to query / join against stored results.
mappings contains {"check": k, "framework": fw, "control": cid} if {
	some k, m in checks
	some fw, cid in m.frameworks
}

# Frameworks a given check satisfies (set of framework keys).
frameworks_for(check) := object.keys(checks[check].frameworks)

# The control id for (check, framework), or undefined if that framework doesn't
# carry the check.
control_for(check, fw) := checks[check].frameworks[fw]

# Per-check coverage: how many frameworks share it.
coverage[check] := n if {
	some check, m in checks
	n := count(m.frameworks)
}

# Reverse lookup: framework control id → canonical check key.
check_for_control[fw][cid] := k if {
	some k, m in checks
	some fw, cid in m.frameworks
}
