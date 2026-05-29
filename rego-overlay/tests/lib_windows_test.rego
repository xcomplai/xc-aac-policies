# Unit tests for data.aac.lib.windows shared predicates.
# Run: `opa test rego-overlay/`.

package aac.lib.windows_test

import rego.v1

import data.aac.lib.windows as win

# ── Fail-secure defaults: missing facts read as the non-compliant value ───────
test_missing_guest_reads_as_enabled if {
	not win.guest_account_disabled({}) # absent guest_account_enabled defaults true
}

test_missing_smb1_reads_as_enabled if {
	not win.smb1_disabled({}) # absent smb1_enabled defaults true
}

# ── Inverted-zero logic ───────────────────────────────────────────────────────
test_max_password_age_zero_is_bad if {
	not win.max_password_age_ok({"account_policy": {"max_password_age": 0}}, 365)
}

test_max_password_age_in_range_ok if {
	win.max_password_age_ok({"account_policy": {"max_password_age": 60}}, 365)
}

test_lockout_threshold_zero_is_bad if {
	not win.lockout_threshold_ok({"account_policy": {"lockout_threshold": 0}}, 5)
}

test_lockout_threshold_in_range_ok if {
	win.lockout_threshold_ok({"account_policy": {"lockout_threshold": 5}}, 5)
}

test_lockout_threshold_over_limit_is_bad if {
	not win.lockout_threshold_ok({"account_policy": {"lockout_threshold": 10}}, 5)
}

# ── Firewall: all three profiles required ─────────────────────────────────────
test_firewall_all_on if {
	win.firewall_all_profiles_on({"firewall": {"domain_enabled": true, "private_enabled": true, "public_enabled": true}})
}

test_firewall_one_off_fails if {
	not win.firewall_all_profiles_on({"firewall": {"domain_enabled": true, "private_enabled": false, "public_enabled": true}})
}

# ── Services: only insecure enabled services are flagged ──────────────────────
test_insecure_services_selected if {
	win.insecure_services_enabled({"services": {"enabled": ["EventLog", "TlntSvr", "SNMP"]}}) == {"TlntSvr", "SNMP"}
}

test_no_insecure_services_when_clean if {
	win.no_insecure_services({"services": {"enabled": ["EventLog", "W32Time"]}})
}
