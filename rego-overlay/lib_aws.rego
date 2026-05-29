# data.aac.lib.aws — shared AWS control predicates over fact_contract/v1
# framework_facts for the CLOUD data plane (Tier 3.K cloud track). The cloud
# analog of data.aac.lib.linux: cis_aws (and future aws-domain frameworks) build
# on these instead of reimplementing "is the root MFA on? / is every bucket
# encrypted? / does any SG expose 22 to the world?".
#
# Input shape (cloud framework_facts, produced by the future xcomplai.aac_cloud
# gatherer querying AWS APIs — assessed PER ACCOUNT, not per host):
#   iam:             {root_mfa_enabled, root_access_keys_present, password_policy:{minimum_length,…}}
#   s3:              {buckets:[{name, encryption_enabled, public_access_blocked}]}
#   cloudtrail:      {enabled, multi_region, log_file_validation, kms_encrypted}
#   security_groups: {groups:[{id, ingress:[{cidr, from_port, to_port}]}]}
#   vpc:             {flow_logs_enabled}
#
# Transitional overlay (see rego-overlay/README.md).

package aac.lib.aws

import rego.v1

_iam(ff) := object.get(ff, "iam", {})

_s3_buckets(ff) := object.get(object.get(ff, "s3", {}), "buckets", [])

_ct(ff) := object.get(ff, "cloudtrail", {})

_sgs(ff) := object.get(object.get(ff, "security_groups", {}), "groups", [])

# ── IAM ───────────────────────────────────────────────────────────────────────
iam_root_mfa_enabled(ff) if object.get(_iam(ff), "root_mfa_enabled", false) == true

iam_no_root_access_keys(ff) if object.get(_iam(ff), "root_access_keys_present", false) == false

iam_password_min_length_ok(ff, n) if {
	object.get(object.get(_iam(ff), "password_policy", {}), "minimum_length", 0) >= n
}

# ── S3 ────────────────────────────────────────────────────────────────────────
# Vacuously true on an account with no buckets.
s3_all_encrypted(ff) if {
	every b in _s3_buckets(ff) {
		object.get(b, "encryption_enabled", false) == true
	}
}

s3_all_public_access_blocked(ff) if {
	every b in _s3_buckets(ff) {
		object.get(b, "public_access_blocked", false) == true
	}
}

# ── CloudTrail ────────────────────────────────────────────────────────────────
cloudtrail_multiregion(ff) if {
	object.get(_ct(ff), "enabled", false) == true
	object.get(_ct(ff), "multi_region", false) == true
}

cloudtrail_log_file_validation(ff) if object.get(_ct(ff), "log_file_validation", false) == true

# ── Security groups ───────────────────────────────────────────────────────────
_admin_ports := {22, 3389}

# A rule that opens an admin port to the whole internet.
_world_admin_rule(r) if {
	r.cidr == "0.0.0.0/0"
	some p in _admin_ports
	object.get(r, "from_port", 0) <= p
	p <= object.get(r, "to_port", 0)
}

# Set of security-group IDs exposing an admin port to 0.0.0.0/0.
sg_world_admin_open(ff) := {g.id |
	some g in _sgs(ff)
	some r in object.get(g, "ingress", [])
	_world_admin_rule(r)
}

sg_no_world_admin(ff) if count(sg_world_admin_open(ff)) == 0

# ── VPC ───────────────────────────────────────────────────────────────────────
vpc_flow_logs_enabled(ff) if object.get(object.get(ff, "vpc", {}), "flow_logs_enabled", false) == true
