# data.nist_800_53.main.compliance_report — evaluate the TECHNICAL subset of
# NIST SP 800-53 Rev 5 against the fact_contract/v1 framework_facts the
# xcomplai.aac_common gatherer produces.
#
# Tier 3.K. Same shared predicates (data.aac.lib.linux) and same nouns as
# CIS/STIG — NIST differs only in the control IDs (mapped to 800-53 families)
# the host facts satisfy. This is the "assess once, report against many
# frameworks" payoff: one gather, three rego evaluations.
#
# Scope: technical, host-derivable controls only (AC/IA/CM/SC/SI). Org/process
# families (PM/PL/PS/…) are out of scope. FIPS/crypto (SC-13) is deferred until
# aac_common gathers a `crypto` noun. Transitional overlay.

package nist_800_53.main

import rego.v1

import data.aac.lib.linux as lib

_ff := object.get(input, "framework_facts", {})

_passwd_modes := {"0644", "0640", "0600", "0400"}

_shadow_modes := {"0000", "0600", "0640"}

# Technical control families evaluated here (the denominator).
controls := {
	"AC-3(4)", "AC-6", "IA-5",
	"CM-6", "SC-28", "SC-13",
	"SI-2", "SI-7", "CM-7",
}

# SC-13 — cryptographic protection (FIPS mode enabled)
violation contains {
	"control": "SC-13",
	"title": "Cryptographic protection — FIPS mode must be enabled",
	"detail": sprintf("FIPS mode not enabled (crypto_policy=%v)", [lib.crypto_policy(_ff)]),
} if {
	not lib.fips_enabled(_ff)
}

# AC-3(4) — mandatory access control (SELinux enforcing)
violation contains {
	"control": "AC-3(4)",
	"title": "Mandatory access control (SELinux) must be enabled and enforcing",
	"detail": sprintf("SELinux status=%v mode=%v", [lib.selinux_status(_ff), lib.selinux_mode(_ff)]),
} if {
	not lib.selinux_enforcing(_ff)
}

# AC-6 — least privilege (no direct SSH root login)
violation contains {
	"control": "AC-6",
	"title": "Least privilege — direct SSH root login must be disabled",
	"detail": sprintf("PermitRootLogin=%v", [lib.permit_root_login(_ff)]),
} if {
	lib.sshd_present(_ff)
	not lib.sshd_root_login_disabled(_ff)
}

# IA-5 — authenticator management (no empty passwords)
violation contains {
	"control": "IA-5",
	"title": "Authenticator management — SSH must not permit empty passwords",
	"detail": sprintf("PermitEmptyPasswords=%v", [lib.permit_empty_passwords(_ff)]),
} if {
	lib.sshd_present(_ff)
	not lib.sshd_empty_passwords_disabled(_ff)
}

# CM-6 — configuration settings (/etc/passwd permissions)
violation contains {
	"control": "CM-6",
	"title": "Configuration settings — /etc/passwd permissions",
	"detail": sprintf("/etc/passwd mode=%v owner=%v", [e.mode, e.owner]),
} if {
	e := lib.file_entry(_ff, "/etc/passwd")
	object.get(e, "exists", false) == true
	not lib.file_ok(_ff, "/etc/passwd", "root", _passwd_modes)
}

# SC-28 — protection of information at rest (/etc/shadow permissions)
violation contains {
	"control": "SC-28",
	"title": "Protection at rest — /etc/shadow permissions",
	"detail": sprintf("/etc/shadow mode=%v owner=%v", [e.mode, e.owner]),
} if {
	e := lib.file_entry(_ff, "/etc/shadow")
	object.get(e, "exists", false) == true
	not lib.file_ok(_ff, "/etc/shadow", "root", _shadow_modes)
}

# SI-2 — flaw remediation (automatic updates configured)
violation contains {
	"control": "SI-2",
	"title": "Flaw remediation — automatic update tooling must be configured",
	"detail": "dnf-automatic is not installed/enabled",
} if {
	not lib.auto_updates_enabled(_ff)
}

# SI-7 — software/firmware integrity (package GPG verification)
violation contains {
	"control": "SI-7",
	"title": "Software integrity — RPM GPG keys must be present",
	"detail": "no RPM GPG keys present under /etc/pki/rpm-gpg",
} if {
	not lib.gpg_keys_present(_ff)
}

# CM-7 — least functionality (no legacy insecure services)
violation contains {
	"control": "CM-7",
	"title": "Least functionality — legacy insecure services must not be enabled",
	"detail": sprintf("enabled insecure service: %v", [s]),
} if {
	some s in lib.insecure_services_enabled(_ff)
}

# ── Aggregate report (same shape as cis_rhel9.main / stig_rhel9.main) ─────────
violations_list := [v | some v in violation]

_failed_controls := {v.control | some v in violation}

default compliant := false

compliant if count(violation) == 0

compliance_report := {
	"framework": "nist_800_53",
	"version": "NIST SP 800-53 Rev 5 (technical subset)",
	"schema": "fact_contract/v1",
	"coverage": "technical subset (AC/IA/CM/SC/SI) derivable from aac_common's current nouns; org/process families out of scope; FIPS/crypto (SC-13) deferred. compliance_percentage is over evaluated_controls.",
	"total_controls": count(controls),
	"evaluated_controls": sort([c | some c in controls]),
	"violations": violations_list,
	"violation_count": count(violations_list),
	"failed_controls": count(_failed_controls),
	"passed_controls": count(controls) - count(_failed_controls),
	"compliant": compliant,
	"compliance_percentage": round((count(controls) - count(_failed_controls)) / count(controls) * 100),
}
