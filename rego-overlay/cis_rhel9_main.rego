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
# Coverage is the STARTER set keyed to xcomplai.cis_os v1.2.0's facts_schema
# (filesystem / ssh / selinux / services / filesystem_permissions); it grows as
# the collection gathers more nouns. compliance_percentage is reported against
# the controls EVALUATED here, not the full 338-control benchmark — see
# `coverage` in the report.
#
# Transitional overlay (see rego-overlay/README.md): injected into the bundle at
# CI build until it lands upstream in ynotbhatc/rego_policy_libraries.

package cis_rhel9.main

import rego.v1

# ── Safe accessors into the contract input ────────────────────────────────────
_ff := object.get(input, "framework_facts", {})

_fs := object.get(_ff, "filesystem", {})

_ssh := object.get(_ff, "ssh", {})

_selinux := object.get(_ff, "selinux", {})

_svc := object.get(_ff, "services", {})

_perms := object.get(object.get(_ff, "filesystem_permissions", {}), "paths", [])

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
	object.get(_fs, "gpg_keys_present", false) == false
}

violation contains {
	"control": "1.2.2",
	"title": "Ensure software update tooling is configured",
	"detail": "dnf-automatic is not installed/enabled",
} if {
	object.get(_fs, "auto_updates_enabled", false) == false
}

# ── Section 1.6 — SELinux ─────────────────────────────────────────────────────
violation contains {
	"control": "1.6.1.2",
	"title": "Ensure SELinux is not disabled",
	"detail": sprintf("SELinux status=%v (want enabled)", [object.get(_selinux, "status", "unknown")]),
} if {
	object.get(_selinux, "status", "disabled") != "enabled"
}

violation contains {
	"control": "1.6.1.3",
	"title": "Ensure the SELinux mode is enforcing",
	"detail": sprintf("SELinux mode=%v (want enforcing)", [object.get(_selinux, "mode", "")]),
} if {
	object.get(_selinux, "status", "disabled") == "enabled"
	object.get(_selinux, "mode", "") != "enforcing"
}

# ── Section 5.1 — SSH server ──────────────────────────────────────────────────
# Unset PermitRootLogin defaults to prohibit-password, not "no" → CIS wants an
# explicit "no", so unset ("") is a finding.
violation contains {
	"control": "5.1.22",
	"title": "Ensure SSH PermitRootLogin is disabled",
	"detail": sprintf("PermitRootLogin=%v (want no)", [object.get(_ssh, "permit_root_login", "<unset>")]),
} if {
	object.get(_ssh, "sshd_config_present", false) == true
	lower(object.get(_ssh, "permit_root_login", "")) != "no"
}

# Unset PermitEmptyPasswords defaults to "no" → only a finding if explicitly set
# to something other than "no".
violation contains {
	"control": "5.1.23",
	"title": "Ensure SSH PermitEmptyPasswords is disabled",
	"detail": sprintf("PermitEmptyPasswords=%v (want no)", [object.get(_ssh, "permit_empty_passwords", "")]),
} if {
	object.get(_ssh, "sshd_config_present", false) == true
	_pep := lower(object.get(_ssh, "permit_empty_passwords", ""))
	_pep != "no"
	_pep != ""
}

# ── Section 6.1 — critical file permissions ───────────────────────────────────
violation contains {
	"control": "6.1.1",
	"title": "Ensure permissions on /etc/passwd are configured",
	"detail": sprintf("/etc/passwd mode=%v owner=%v (want <=0644 root)", [e.mode, e.owner]),
} if {
	some e in _perms
	e.path == "/etc/passwd"
	object.get(e, "exists", false) == true
	not _passwd_ok(e)
}

_passwd_ok(e) if {
	e.owner == "root"
	e.mode in {"0644", "0640", "0600", "0400"}
}

violation contains {
	"control": "6.1.2",
	"title": "Ensure permissions on /etc/shadow are configured",
	"detail": sprintf("/etc/shadow mode=%v owner=%v (want 0000/0600/0640 root)", [e.mode, e.owner]),
} if {
	some e in _perms
	e.path == "/etc/shadow"
	object.get(e, "exists", false) == true
	not _shadow_ok(e)
}

_shadow_ok(e) if {
	e.owner == "root"
	e.mode in {"0000", "0600", "0640"}
}

# ── Section 2.2 — legacy insecure services ────────────────────────────────────
_insecure_services := {
	"telnet.socket", "telnet.service",
	"rsh.socket", "rlogin.socket", "rexec.socket",
	"tftp.socket", "tftp.service",
	"vsftpd.service",
}

violation contains {
	"control": "2.2.1",
	"title": "Ensure legacy insecure services are not enabled",
	"detail": sprintf("enabled insecure service: %v", [s]),
} if {
	some s in object.get(_svc, "enabled", [])
	s in _insecure_services
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
