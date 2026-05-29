# data.cis_aws.main.compliance_report — evaluate the CIS AWS Foundations
# Benchmark against fact_contract/v1 CLOUD framework_facts (Tier 3.K cloud track).
#
# Same decoupled pattern as the Linux frameworks, on a different DATA PLANE: the
# (future) xcomplai.aac_cloud gatherer queries AWS APIs once per ACCOUNT and
# produces the cloud framework_facts; this rule evaluates them via
# data.aac.lib.aws. Cloud frameworks are rego-only too — only the gatherer + lib
# are plane-specific.
#
# Starter coverage (CIS AWS Foundations v3.0.0) keyed to the cloud noun set the
# gatherer will produce (iam / s3 / cloudtrail / security_groups / vpc).
# Transitional overlay.

package cis_aws.main

import rego.v1

import data.aac.lib.aws as aws

_ff := object.get(input, "framework_facts", {})

controls := {
	"1.4", "1.5", "1.8",
	"2.1.1", "2.1.4",
	"3.1", "3.2", "3.9",
	"5.2",
}

# ── Section 1 — IAM ───────────────────────────────────────────────────────────
violation contains {
	"control": "1.4",
	"title": "Ensure no root user access keys exist",
	"detail": "root account has access keys",
} if {
	not aws.iam_no_root_access_keys(_ff)
}

violation contains {
	"control": "1.5",
	"title": "Ensure MFA is enabled for the root user",
	"detail": "root account MFA is not enabled",
} if {
	not aws.iam_root_mfa_enabled(_ff)
}

violation contains {
	"control": "1.8",
	"title": "Ensure IAM password policy requires minimum length of 14",
	"detail": sprintf("IAM password policy minimum_length=%v (want >=14)", [object.get(object.get(object.get(_ff, "iam", {}), "password_policy", {}), "minimum_length", 0)]),
} if {
	not aws.iam_password_min_length_ok(_ff, 14)
}

# ── Section 2 — Storage (S3) ──────────────────────────────────────────────────
violation contains {
	"control": "2.1.1",
	"title": "Ensure S3 buckets have server-side encryption enabled",
	"detail": "one or more S3 buckets lack server-side encryption",
} if {
	not aws.s3_all_encrypted(_ff)
}

violation contains {
	"control": "2.1.4",
	"title": "Ensure S3 buckets block public access",
	"detail": "one or more S3 buckets do not block public access",
} if {
	not aws.s3_all_public_access_blocked(_ff)
}

# ── Section 3 — Logging ───────────────────────────────────────────────────────
violation contains {
	"control": "3.1",
	"title": "Ensure CloudTrail is enabled in all regions",
	"detail": "CloudTrail is not enabled multi-region",
} if {
	not aws.cloudtrail_multiregion(_ff)
}

violation contains {
	"control": "3.2",
	"title": "Ensure CloudTrail log file validation is enabled",
	"detail": "CloudTrail log file validation is disabled",
} if {
	not aws.cloudtrail_log_file_validation(_ff)
}

violation contains {
	"control": "3.9",
	"title": "Ensure VPC flow logging is enabled in all VPCs",
	"detail": "VPC flow logs are not enabled",
} if {
	not aws.vpc_flow_logs_enabled(_ff)
}

# ── Section 5 — Networking ────────────────────────────────────────────────────
violation contains {
	"control": "5.2",
	"title": "Ensure no security groups allow 0.0.0.0/0 to admin ports (22/3389)",
	"detail": sprintf("security groups open to the world on 22/3389: %v", [sort([id | some id in aws.sg_world_admin_open(_ff)])]),
} if {
	not aws.sg_no_world_admin(_ff)
}

# ── Aggregate report (same shape as the Linux …main rules) ────────────────────
violations_list := [v | some v in violation]

_failed_controls := {v.control | some v in violation}

default compliant := false

compliant if count(violation) == 0

compliance_report := {
	"framework": "cis_aws",
	"version": "CIS AWS Foundations Benchmark v3.0.0",
	"schema": "fact_contract/v1",
	"coverage": "starter — CIS AWS Foundations controls keyed to the cloud noun set (iam/s3/cloudtrail/security_groups/vpc) the xcomplai.aac_cloud gatherer will produce. compliance_percentage is over evaluated_controls. Cloud is assessed PER ACCOUNT.",
	"total_controls": count(controls),
	"evaluated_controls": sort([c | some c in controls]),
	"violations": violations_list,
	"violation_count": count(violations_list),
	"failed_controls": count(_failed_controls),
	"passed_controls": count(controls) - count(_failed_controls),
	"compliant": compliant,
	"compliance_percentage": round((count(controls) - count(_failed_controls)) / count(controls) * 100),
}
