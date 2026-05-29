# data.aac.catalog — discovery aggregator over every framework's metadata.
#
# Orchestration in xc-aac queries this to discover which frameworks the bundle
# supports + their dispatch metadata (collection, opa_endpoint_path, pg_table,
# dashboard_uid, facts_schema) — see docs/architecture/FACT_CONTRACT.md and
# ansible/playbooks/generic_framework_assessment.yml in xc-aac.
#
# Each new framework adds itself by:
#   1. Adding its own data.<framework>.metadata declaration (per cis_rhel9.rego
#      in this dir).
#   2. Adding an entry to `frameworks` below.
#
# Transitional overlay: this file is injected into the bundle at CI build time
# alongside the per-framework metadata files. Upstream goal is for each
# framework's metadata to live next to its rego in ynotbhatc/rego_policy_libraries
# and for this aggregator to be generated from that set.

package aac.catalog

import rego.v1

# Per-framework metadata that should appear in the catalog. Each entry pulls
# from the corresponding `data.<framework>.metadata` rule and adds its key.
frameworks contains {
	"key": "cis_rhel8",
	"metadata": data.cis_rhel8.metadata,
}

frameworks contains {
	"key": "cis_rhel9",
	"metadata": data.cis_rhel9.metadata,
}

frameworks contains {
	"key": "stig_rhel9",
	"metadata": data.stig_rhel9.metadata,
}

# Lookup by framework key — used by generic_framework_assessment.yml's
# catalog-first dispatch path when it lands. The result is the metadata object
# for the named framework, or undefined if the framework isn't in the catalog
# (in which case the playbook falls back to the local framework_dispatch_map).
metadata[k] := v if {
	some entry in frameworks
	k := entry.key
	v := entry.metadata
}

# Convenience: just the keys, sorted. UIs use this to populate a framework
# picker.
keys := sort([k | some entry in frameworks; k := entry.key])
