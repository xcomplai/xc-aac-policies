# data.cis_rhel9.main.compliance_report — evaluate CIS RHEL 9 against the
# fact_contract/v1 framework_facts the xcomplai.cis_os collection produces.
#
# Tier 3.J. The legacy data.cis_rhel9.* modules (cis_rhel9_complete.rego in the
# rego library) consume raw input.ansible_facts; this `main` sub-package consumes
# the projected input.framework_facts — the nouns declared in
# data.cis_rhel9.metadata.facts_schema — and returns the contract report shape
# the orchestrator (generic_framework_assessment.yml) POSTs to
# /v1/data/cis_rhel9/main/compliance_report and stores to PostgreSQL.
#
# Control predicates live in data.aac.lib.linux (shared with stig_rhel9 /
# nist_800_53 / … — Tier 3.K). This rule supplies the CIS control IDs, titles,
# thresholds, and the report aggregation.
#
# Coverage is the STARTER set keyed to xcomplai.cis_os v1.2.0's facts_schema
# (filesystem / ssh / selinux / services / filesystem_permissions); it grows as
# the collection gathers more nouns. compliance_percentage is reported against
# the controls EVALUATED here, not the full 338-control benchmark.
#
# Transitional overlay (see rego-overlay/README.md): injected into the bundle at
# CI build until it lands upstream in ynotbhatc/rego_policy_libraries.

package cis_rhel9.main

import rego.v1

import data.aac.lib.linux as lib

_ff := object.get(input, "framework_facts", {})

# Allowed modes per CIS RHEL 9 v2.0.0 for the critical identity files.
_passwd_modes := {"0644", "0640", "0600", "0400"}

_shadow_modes := {"0000", "0600", "0640"}

# Controls this overlay evaluates (the denominator for compliance_percentage).
controls := {
	"1.2.1", "1.2.2",
	"1.6.1.2", "1.6.1.3",
	"5.1.22", "5.1.23",
	"6.1.1", "6.1.2",
	"2.2.1",
}

# ── Section 1.2 — software updates / package integrity ────────────────────────
violation contains {
	"control": "1.2.1",
	"title": "Ensure GPG keys are configured",
	"detail": "no RPM GPG keys present under /etc/pki/rpm-gpg",
} if {
	not lib.gpg_keys_present(_ff)
}

violation contains {
	"control": "1.2.2",
	"title": "Ensure software update tooling is configured",
	"detail": "dnf-automatic is not installed/enabled",
} if {
	not lib.auto_updates_enabled(_ff)
}

# ── Section 1.6 — SELinux ─────────────────────────────────────────────────────
violation contains {
	"control": "1.6.1.2",
	"title": "Ensure SELinux is not disabled",
	"detail": sprintf("SELinux status=%v (want enabled)", [lib.selinux_status(_ff)]),
} if {
	not lib.selinux_enabled(_ff)
}

violation contains {
	"control": "1.6.1.3",
	"title": "Ensure the SELinux mode is enforcing",
	"detail": sprintf("SELinux mode=%v (want enforcing)", [lib.selinux_mode(_ff)]),
} if {
	lib.selinux_enabled(_ff)
	not lib.selinux_enforcing(_ff)
}

# ── Section 5.1 — SSH server ──────────────────────────────────────────────────
violation contains {
	"control": "5.1.22",
	"title": "Ensure SSH PermitRootLogin is disabled",
	"detail": sprintf("PermitRootLogin=%v (want no)", [lib.permit_root_login(_ff)]),
} if {
	lib.sshd_present(_ff)
	not lib.sshd_root_login_disabled(_ff)
}

violation contains {
	"control": "5.1.23",
	"title": "Ensure SSH PermitEmptyPasswords is disabled",
	"detail": sprintf("PermitEmptyPasswords=%v (want no)", [lib.permit_empty_passwords(_ff)]),
} if {
	lib.sshd_present(_ff)
	not lib.sshd_empty_passwords_disabled(_ff)
}

# ── Section 6.1 — critical file permissions ───────────────────────────────────
violation contains {
	"control": "6.1.1",
	"title": "Ensure permissions on /etc/passwd are configured",
	"detail": sprintf("/etc/passwd mode=%v owner=%v (want <=0644 root)", [e.mode, e.owner]),
} if {
	e := lib.file_entry(_ff, "/etc/passwd")
	object.get(e, "exists", false) == true
	not lib.file_ok(_ff, "/etc/passwd", "root", _passwd_modes)
}

violation contains {
	"control": "6.1.2",
	"title": "Ensure permissions on /etc/shadow are configured",
	"detail": sprintf("/etc/shadow mode=%v owner=%v (want 0000/0600/0640 root)", [e.mode, e.owner]),
} if {
	e := lib.file_entry(_ff, "/etc/shadow")
	object.get(e, "exists", false) == true
	not lib.file_ok(_ff, "/etc/shadow", "root", _shadow_modes)
}

# ── Section 2.2 — legacy insecure services ────────────────────────────────────
violation contains {
	"control": "2.2.1",
	"title": "Ensure legacy insecure services are not enabled",
	"detail": sprintf("enabled insecure service: %v", [s]),
} if {
	some s in lib.insecure_services_enabled(_ff)
}

# ── Aggregate report (the contract output) ────────────────────────────────────
violations_list := [v | some v in violation]

# Distinct controls that produced at least one violation.
_failed_controls := {v.control | some v in violation}

default compliant := false

compliant if count(violation) == 0

compliance_report := {
	"framework": "cis_rhel9",
	"version": "CIS Red Hat Enterprise Linux 9 Benchmark v2.0.0",
	"schema": "fact_contract/v1",
	"coverage": "starter — controls keyed to xcomplai.cis_os facts_schema (filesystem/ssh/selinux/services/filesystem_permissions); extends as the collection gathers more nouns. compliance_percentage is over evaluated_controls, not the full 338.",
	"total_controls": count(controls),
	"evaluated_controls": sort([c | some c in controls]),
	"violations": violations_list,
	"violation_count": count(violations_list),
	"failed_controls": count(_failed_controls),
	"passed_controls": count(controls) - count(_failed_controls),
	"compliant": compliant,
	"compliance_percentage": round((count(controls) - count(_failed_controls)) / count(controls) * 100),
}
