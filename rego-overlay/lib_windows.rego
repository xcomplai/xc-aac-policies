# data.aac.lib.windows — shared Windows control predicates over fact_contract/v1
# framework_facts for the WINDOWS host data plane (Tier 3.K windows track). The
# Windows analog of data.aac.lib.linux / data.aac.lib.aws: cis_windows_* (and
# future stig_windows) build on these instead of reimplementing "is the password
# policy strong enough? / are all three firewall profiles on? / is SMBv1 off?".
#
# Input shape (windows framework_facts, produced by the future
# xcomplai.aac_windows gatherer over WinRM/PowerShell — assessed PER HOST, like
# Linux):
#   account_policy: {password_history, max_password_age, min_password_length,
#                    password_complexity, lockout_threshold, lockout_duration}
#   audit_policy:   {logon_success, logon_failure}
#   firewall:       {domain_enabled, private_enabled, public_enabled}
#   registry:       {smb1_enabled, guest_account_enabled}
#   services:       {enabled:[name,…]}
#
# Defaults lean fail-SECURE: a missing fact resolves to the non-compliant value
# (e.g. an absent guest_account_enabled is treated as enabled), so a partial
# gather surfaces gaps as violations rather than silently passing.
#
# Transitional overlay (see rego-overlay/README.md).

package aac.lib.windows

import rego.v1

_acct(ff) := object.get(ff, "account_policy", {})

_fw(ff) := object.get(ff, "firewall", {})

_audit(ff) := object.get(ff, "audit_policy", {})

_reg(ff) := object.get(ff, "registry", {})

_svcs_enabled(ff) := object.get(object.get(ff, "services", {}), "enabled", [])

# ── Account / password policy ─────────────────────────────────────────────────
password_history_ok(ff, n) if object.get(_acct(ff), "password_history", 0) >= n

min_password_length_ok(ff, n) if object.get(_acct(ff), "min_password_length", 0) >= n

password_complexity_enabled(ff) if object.get(_acct(ff), "password_complexity", false) == true

# Max password age must be set (non-zero = "never expires" is non-compliant) and
# no greater than n days.
max_password_age_ok(ff, n) if {
	a := object.get(_acct(ff), "max_password_age", 0)
	a > 0
	a <= n
}

# Lockout threshold must be enabled (>0 = "never lock out" is non-compliant) and
# no greater than n attempts.
lockout_threshold_ok(ff, n) if {
	t := object.get(_acct(ff), "lockout_threshold", 0)
	t > 0
	t <= n
}

lockout_duration_ok(ff, n) if object.get(_acct(ff), "lockout_duration", 0) >= n

# ── Windows Defender Firewall ─────────────────────────────────────────────────
firewall_profile_on(ff, profile) if object.get(_fw(ff), profile, false) == true

firewall_all_profiles_on(ff) if {
	firewall_profile_on(ff, "domain_enabled")
	firewall_profile_on(ff, "private_enabled")
	firewall_profile_on(ff, "public_enabled")
}

# ── Audit policy ──────────────────────────────────────────────────────────────
audit_logon_full(ff) if {
	object.get(_audit(ff), "logon_success", false) == true
	object.get(_audit(ff), "logon_failure", false) == true
}

# ── Registry-derived security options ─────────────────────────────────────────
# Defaults are the INSECURE value so a missing fact reads as a violation.
smb1_disabled(ff) if object.get(_reg(ff), "smb1_enabled", true) == false

guest_account_disabled(ff) if object.get(_reg(ff), "guest_account_enabled", true) == false

# ── System services ───────────────────────────────────────────────────────────
# Legacy / cleartext services that must not be enabled (the Windows analog of
# data.aac.lib.linux.insecure_services_enabled).
_insecure_services := {"TlntSvr", "FTPSVC", "SNMP", "RemoteRegistry", "Browser"}

# Set of enabled service short-names that are on the insecure list.
insecure_services_enabled(ff) := {s |
	some s in _svcs_enabled(ff)
	s in _insecure_services
}

no_insecure_services(ff) if count(insecure_services_enabled(ff)) == 0
