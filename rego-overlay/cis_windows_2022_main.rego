# data.cis_windows_2022.main.compliance_report — evaluate the CIS Microsoft
# Windows Server 2022 Benchmark against fact_contract/v1 WINDOWS framework_facts
# (Tier 3.K windows track).
#
# Same decoupled pattern as the Linux + cloud frameworks, on the Windows host
# data plane: the (future) xcomplai.aac_windows gatherer collects host state once
# per host over WinRM/PowerShell and produces the windows framework_facts; this
# rule evaluates them via data.aac.lib.windows. Windows frameworks are rego-only
# too — only the gatherer + lib are plane-specific. Routed to opa-security like
# the other security-domain frameworks.
#
# Starter coverage (CIS Windows Server 2022 v3.0.0) keyed to the windows noun set
# the gatherer will produce (account_policy / audit_policy / firewall / registry
# / services). compliance_percentage is over evaluated_controls, NOT the full
# benchmark. Transitional overlay (see rego-overlay/README.md).

package cis_windows_2022.main

import rego.v1

import data.aac.lib.windows as win

_ff := object.get(input, "framework_facts", {})

controls := {
	"1.1.1", "1.1.2", "1.1.4", "1.1.5",
	"1.2.1", "1.2.2",
	"2.3.1.2",
	"9.1.1", "9.2.1", "9.3.1",
	"17.5.1",
	"18.3.1",
	"5.1",
}

# ── Section 1.1 — Password Policy ─────────────────────────────────────────────
violation contains {
	"control": "1.1.1",
	"title": "Ensure 'Enforce password history' is set to '24 or more password(s)'",
	"detail": sprintf("password_history=%v (want >=24)", [object.get(win._acct(_ff), "password_history", 0)]),
} if {
	not win.password_history_ok(_ff, 24)
}

violation contains {
	"control": "1.1.2",
	"title": "Ensure 'Maximum password age' is set to '365 or fewer days, but not 0'",
	"detail": sprintf("max_password_age=%v (want 1..365)", [object.get(win._acct(_ff), "max_password_age", 0)]),
} if {
	not win.max_password_age_ok(_ff, 365)
}

violation contains {
	"control": "1.1.4",
	"title": "Ensure 'Minimum password length' is set to '14 or more character(s)'",
	"detail": sprintf("min_password_length=%v (want >=14)", [object.get(win._acct(_ff), "min_password_length", 0)]),
} if {
	not win.min_password_length_ok(_ff, 14)
}

violation contains {
	"control": "1.1.5",
	"title": "Ensure 'Password must meet complexity requirements' is set to 'Enabled'",
	"detail": "password complexity is not enabled",
} if {
	not win.password_complexity_enabled(_ff)
}

# ── Section 1.2 — Account Lockout Policy ──────────────────────────────────────
violation contains {
	"control": "1.2.1",
	"title": "Ensure 'Account lockout duration' is set to '15 or more minute(s)'",
	"detail": sprintf("lockout_duration=%v (want >=15)", [object.get(win._acct(_ff), "lockout_duration", 0)]),
} if {
	not win.lockout_duration_ok(_ff, 15)
}

violation contains {
	"control": "1.2.2",
	"title": "Ensure 'Account lockout threshold' is set to '5 or fewer invalid logon attempt(s), but not 0'",
	"detail": sprintf("lockout_threshold=%v (want 1..5)", [object.get(win._acct(_ff), "lockout_threshold", 0)]),
} if {
	not win.lockout_threshold_ok(_ff, 5)
}

# ── Section 2.3.1 — Security Options: Accounts ────────────────────────────────
violation contains {
	"control": "2.3.1.2",
	"title": "Ensure 'Accounts: Guest account status' is set to 'Disabled'",
	"detail": "built-in Guest account is enabled",
} if {
	not win.guest_account_disabled(_ff)
}

# ── Section 9 — Windows Defender Firewall ─────────────────────────────────────
violation contains {
	"control": "9.1.1",
	"title": "Ensure 'Windows Firewall: Domain: Firewall state' is 'On'",
	"detail": "domain-profile firewall is off",
} if {
	not win.firewall_profile_on(_ff, "domain_enabled")
}

violation contains {
	"control": "9.2.1",
	"title": "Ensure 'Windows Firewall: Private: Firewall state' is 'On'",
	"detail": "private-profile firewall is off",
} if {
	not win.firewall_profile_on(_ff, "private_enabled")
}

violation contains {
	"control": "9.3.1",
	"title": "Ensure 'Windows Firewall: Public: Firewall state' is 'On'",
	"detail": "public-profile firewall is off",
} if {
	not win.firewall_profile_on(_ff, "public_enabled")
}

# ── Section 17.5 — Advanced Audit Policy: Logon/Logoff ────────────────────────
violation contains {
	"control": "17.5.1",
	"title": "Ensure 'Audit Logon' is set to 'Success and Failure'",
	"detail": "Logon auditing is not set to Success and Failure",
} if {
	not win.audit_logon_full(_ff)
}

# ── Section 18 — Administrative Templates (SMBv1) ─────────────────────────────
violation contains {
	"control": "18.3.1",
	"title": "Ensure SMBv1 (legacy) is disabled",
	"detail": "SMBv1 is enabled",
} if {
	not win.smb1_disabled(_ff)
}

# ── Section 5 — System Services (legacy/insecure) ─────────────────────────────
violation contains {
	"control": "5.1",
	"title": "Ensure legacy insecure services are not enabled",
	"detail": sprintf("enabled insecure service(s): %v", [sort([s | some s in win.insecure_services_enabled(_ff)])]),
} if {
	not win.no_insecure_services(_ff)
}

# ── Aggregate report (same shape as the Linux + cloud …main rules) ────────────
violations_list := [v | some v in violation]

_failed_controls := {v.control | some v in violation}

default compliant := false

compliant if count(violation) == 0

compliance_report := {
	"framework": "cis_windows_2022",
	"version": "CIS Microsoft Windows Server 2022 Benchmark v3.0.0",
	"schema": "fact_contract/v1",
	"coverage": "starter — CIS Windows Server 2022 controls keyed to the windows noun set (account_policy/audit_policy/firewall/registry/services) the xcomplai.aac_windows gatherer will produce. compliance_percentage is over evaluated_controls, not the full benchmark. Assessed PER HOST over WinRM.",
	"total_controls": count(controls),
	"evaluated_controls": sort([c | some c in controls]),
	"violations": violations_list,
	"violation_count": count(violations_list),
	"failed_controls": count(_failed_controls),
	"passed_controls": count(controls) - count(_failed_controls),
	"compliant": compliant,
	"compliance_percentage": round((count(controls) - count(_failed_controls)) / count(controls) * 100),
}
