# data.stig_rhel9.main.compliance_report — evaluate DISA STIG RHEL 9 against the
# fact_contract/v1 framework_facts the xcomplai.aac_common gatherer produces.
#
# Tier 3.K. STIG reuses the SAME shared predicates as CIS (data.aac.lib.linux)
# over the SAME nouns — it differs in DISA control IDs and STRICTER thresholds.
# Two thresholds here are deliberately stricter than CIS to demonstrate the
# shared-lib + per-framework-threshold model:
#   - SELinux MUST be enforcing (one control), vs CIS's "not disabled" + "enforcing".
#   - /etc/shadow MUST be 0000 exactly, vs CIS allowing 0000/0600/0640.
#
# Starter coverage keyed to the gatherer's current nouns; grows as aac_common
# gathers more (audit/pam/crypto for the deeper STIG controls). Transitional
# overlay (see rego-overlay/README.md).

package stig_rhel9.main

import rego.v1

import data.aac.lib.linux as lib

_ff := object.get(input, "framework_facts", {})

# STIG /etc/shadow is STRICTER than CIS: must be exactly 0000 (root).
_shadow_modes := {"0000"}

_passwd_modes := {"0644", "0640", "0600", "0400"}

controls := {
	"RHEL-09-255045", "RHEL-09-255095",
	"RHEL-09-431015",
	"RHEL-09-232035", "RHEL-09-232010",
	"RHEL-09-215010", "RHEL-09-215075",
	"RHEL-09-671010",
}

# RHEL-09-671010 — RHEL 9 must implement a FIPS-validated crypto policy
violation contains {
	"control": "RHEL-09-671010",
	"title": "RHEL 9 must enable FIPS mode",
	"detail": sprintf("FIPS mode not enabled (crypto_policy=%v) — STIG requires FIPS", [lib.crypto_policy(_ff)]),
} if {
	not lib.fips_enabled(_ff)
}

# ── SSH ───────────────────────────────────────────────────────────────────────
violation contains {
	"control": "RHEL-09-255045",
	"title": "RHEL 9 must not permit direct logons to the root account using SSH",
	"detail": sprintf("PermitRootLogin=%v (STIG requires no)", [lib.permit_root_login(_ff)]),
} if {
	lib.sshd_present(_ff)
	not lib.sshd_root_login_disabled(_ff)
}

violation contains {
	"control": "RHEL-09-255095",
	"title": "RHEL 9 SSH server must not permit empty passwords",
	"detail": sprintf("PermitEmptyPasswords=%v (STIG requires no)", [lib.permit_empty_passwords(_ff)]),
} if {
	lib.sshd_present(_ff)
	not lib.sshd_empty_passwords_disabled(_ff)
}

# ── SELinux — STIG requires enforcing (stricter: one control, no "permissive") ─
violation contains {
	"control": "RHEL-09-431015",
	"title": "RHEL 9 must have SELinux enabled and enforcing",
	"detail": sprintf("SELinux status=%v mode=%v (STIG requires enforcing)", [lib.selinux_status(_ff), lib.selinux_mode(_ff)]),
} if {
	not lib.selinux_enforcing(_ff)
}

# ── File permissions — /etc/shadow STRICTER (0000 only) ───────────────────────
violation contains {
	"control": "RHEL-09-232035",
	"title": "RHEL 9 /etc/shadow file must have mode 0000",
	"detail": sprintf("/etc/shadow mode=%v owner=%v (STIG requires 0000 root)", [e.mode, e.owner]),
} if {
	e := lib.file_entry(_ff, "/etc/shadow")
	object.get(e, "exists", false) == true
	not lib.file_ok(_ff, "/etc/shadow", "root", _shadow_modes)
}

violation contains {
	"control": "RHEL-09-232010",
	"title": "RHEL 9 /etc/passwd file must have mode 0644 or less permissive",
	"detail": sprintf("/etc/passwd mode=%v owner=%v (STIG requires <=0644 root)", [e.mode, e.owner]),
} if {
	e := lib.file_entry(_ff, "/etc/passwd")
	object.get(e, "exists", false) == true
	not lib.file_ok(_ff, "/etc/passwd", "root", _passwd_modes)
}

# ── Package integrity / services ──────────────────────────────────────────────
violation contains {
	"control": "RHEL-09-215010",
	"title": "RHEL 9 must check the GPG signature of packages (GPG keys present)",
	"detail": "no RPM GPG keys present under /etc/pki/rpm-gpg",
} if {
	not lib.gpg_keys_present(_ff)
}

violation contains {
	"control": "RHEL-09-215075",
	"title": "RHEL 9 must not have legacy insecure services enabled",
	"detail": sprintf("enabled insecure service: %v", [s]),
} if {
	some s in lib.insecure_services_enabled(_ff)
}

# ── Aggregate report (same shape as cis_rhel9.main) ───────────────────────────
violations_list := [v | some v in violation]

_failed_controls := {v.control | some v in violation}

default compliant := false

compliant if count(violation) == 0

compliance_report := {
	"framework": "stig_rhel9",
	"version": "DISA STIG for RHEL 9 V2R3",
	"schema": "fact_contract/v1",
	"coverage": "starter — controls keyed to the aac_common facts_schema (ssh/selinux/services/filesystem/filesystem_permissions), reusing data.aac.lib.linux with STIG-stricter thresholds. compliance_percentage is over evaluated_controls, not the full STIG.",
	"total_controls": count(controls),
	"evaluated_controls": sort([c | some c in controls]),
	"violations": violations_list,
	"violation_count": count(violations_list),
	"failed_controls": count(_failed_controls),
	"passed_controls": count(controls) - count(_failed_controls),
	"compliant": compliant,
	"compliance_percentage": round((count(controls) - count(_failed_controls)) / count(controls) * 100),
}
