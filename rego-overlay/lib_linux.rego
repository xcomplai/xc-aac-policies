# data.aac.lib.linux — shared Linux control predicates over fact_contract/v1
# framework_facts. Imported by every framework's …main rule (cis_rhel9,
# stig_rhel9, nist_800_53, …) so "is PermitRootLogin no? / SELinux enforcing? /
# shadow 0000?" is written ONCE. Functions take the framework_facts object (ff)
# so they're input-agnostic and composable. Part of Tier 3.K
# (docs/architecture/TIER_3K_DECOUPLED_GATHER_REORG.md).
#
# Transitional overlay (see rego-overlay/README.md): bundled at CI build until it
# lands upstream in ynotbhatc/rego_policy_libraries.

package aac.lib.linux

import rego.v1

# ── SELinux ───────────────────────────────────────────────────────────────────
selinux_status(ff) := object.get(object.get(ff, "selinux", {}), "status", "disabled")

selinux_mode(ff) := object.get(object.get(ff, "selinux", {}), "mode", "")

selinux_enabled(ff) if selinux_status(ff) == "enabled"

selinux_enforcing(ff) if {
	selinux_status(ff) == "enabled"
	selinux_mode(ff) == "enforcing"
}

# ── SSH ───────────────────────────────────────────────────────────────────────
sshd_present(ff) if object.get(object.get(ff, "ssh", {}), "sshd_config_present", false) == true

permit_root_login(ff) := lower(object.get(object.get(ff, "ssh", {}), "permit_root_login", ""))

permit_empty_passwords(ff) := lower(object.get(object.get(ff, "ssh", {}), "permit_empty_passwords", ""))

# CIS wants an explicit "no"; unset ("") defaults to prohibit-password → not ok.
sshd_root_login_disabled(ff) if permit_root_login(ff) == "no"

# Unset ("") defaults to "no" on RHEL 9 → ok.
sshd_empty_passwords_disabled(ff) if permit_empty_passwords(ff) in {"no", ""}

# ── Filesystem / package integrity ────────────────────────────────────────────
gpg_keys_present(ff) if object.get(object.get(ff, "filesystem", {}), "gpg_keys_present", false) == true

auto_updates_enabled(ff) if object.get(object.get(ff, "filesystem", {}), "auto_updates_enabled", false) == true

# ── File permissions ──────────────────────────────────────────────────────────
# The stat-projected entry for a path, or undefined if not gathered.
file_entry(ff, path) := e if {
	some e in object.get(object.get(ff, "filesystem_permissions", {}), "paths", [])
	e.path == path
}

file_present(ff, path) if object.get(file_entry(ff, path), "exists", false) == true

# True when path exists, is owned by `owner`, and its mode is in `allowed_modes`.
file_ok(ff, path, owner, allowed_modes) if {
	e := file_entry(ff, path)
	object.get(e, "exists", false) == true
	e.owner == owner
	e.mode in allowed_modes
}

# ── Services ──────────────────────────────────────────────────────────────────
enabled_services(ff) := object.get(object.get(ff, "services", {}), "enabled", [])

insecure_service_set := {
	"telnet.socket", "telnet.service",
	"rsh.socket", "rlogin.socket", "rexec.socket",
	"tftp.socket", "tftp.service",
	"vsftpd.service",
}

# The set of enabled services that are on the legacy-insecure list.
insecure_services_enabled(ff) := {s |
	some s in enabled_services(ff)
	s in insecure_service_set
}

# ── Crypto (FIPS + system-wide crypto policy) ─────────────────────────────────
fips_enabled(ff) if object.get(object.get(ff, "crypto", {}), "fips_enabled", false) == true

crypto_policy(ff) := object.get(object.get(ff, "crypto", {}), "crypto_policy", "")

# CIS: the system-wide crypto policy must not be LEGACY (an unset/empty policy is
# also not ok — couldn't confirm a hardened policy).
crypto_policy_not_legacy(ff) if {
	p := upper(crypto_policy(ff))
	p != ""
	p != "LEGACY"
}
