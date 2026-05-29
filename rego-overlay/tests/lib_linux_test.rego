# Direct unit tests for data.aac.lib.linux (the shared predicate API that
# cis_rhel9 / stig_rhel9 / nist_800_53 rules build on). Run: `opa test rego-overlay/`.

package aac.lib.linux_test

import rego.v1

import data.aac.lib.linux as lib

_enforcing := {"selinux": {"status": "enabled", "mode": "enforcing"}}

_permissive := {"selinux": {"status": "enabled", "mode": "permissive"}}

_disabled := {"selinux": {"status": "disabled"}}

test_selinux_enforcing if {
	lib.selinux_enforcing(_enforcing)
	not lib.selinux_enforcing(_permissive)
	not lib.selinux_enforcing(_disabled)
}

test_selinux_enabled if {
	lib.selinux_enabled(_permissive) # enabled-but-permissive is still "enabled"
	not lib.selinux_enabled(_disabled)
}

test_sshd_root_login_disabled if {
	lib.sshd_root_login_disabled({"ssh": {"permit_root_login": "no"}})
	not lib.sshd_root_login_disabled({"ssh": {"permit_root_login": "yes"}})
	not lib.sshd_root_login_disabled({"ssh": {}}) # unset → not "no" → not ok
}

test_sshd_empty_passwords_disabled if {
	lib.sshd_empty_passwords_disabled({"ssh": {"permit_empty_passwords": "no"}})
	lib.sshd_empty_passwords_disabled({"ssh": {}}) # unset defaults to no → ok
	not lib.sshd_empty_passwords_disabled({"ssh": {"permit_empty_passwords": "yes"}})
}

_perms(mode) := {"filesystem_permissions": {"paths": [{"path": "/etc/shadow", "mode": mode, "owner": "root", "exists": true}]}}

test_file_ok if {
	lib.file_ok(_perms("0000"), "/etc/shadow", "root", {"0000", "0640"})
	not lib.file_ok(_perms("0644"), "/etc/shadow", "root", {"0000", "0640"})
	lib.file_present(_perms("0000"), "/etc/shadow")
	not lib.file_present({}, "/etc/shadow")
}

test_insecure_services_enabled if {
	got := lib.insecure_services_enabled({"services": {"enabled": ["telnet.socket", "sshd.service"]}})
	got == {"telnet.socket"}
	lib.insecure_services_enabled({"services": {"enabled": ["sshd.service"]}}) == set()
}

test_gpg_and_updates if {
	lib.gpg_keys_present({"filesystem": {"gpg_keys_present": true}})
	not lib.gpg_keys_present({"filesystem": {}})
	lib.auto_updates_enabled({"filesystem": {"auto_updates_enabled": true}})
	not lib.auto_updates_enabled({})
}
