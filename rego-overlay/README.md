# Rego policy overlay (Tier 3.J)

Policy **rules** in this directory are **injected into the bundle at CI build
time** (the `release-bundle` workflow copies `rego-overlay/*.rego` into
`rego_src/aac_rego_overlay/` before `opa build`). They consume the
`fact_contract/v1` `framework_facts` that the AAC framework-gather collections
produce, and return the compliance-report shape the orchestration layer stores.

This is distinct from [`../metadata/`](../metadata/README.md): that overlay
carries `data.<framework>.metadata` + `data.aac.catalog` (discovery); **this**
overlay carries the `…main.compliance_report` evaluation rules.

## Files

| File | Serves | Consumes |
|------|--------|----------|
| `cis_rhel9_main.rego` | `data.cis_rhel9.main.compliance_report` | `input.framework_facts` from `xcomplai.cis_os` (filesystem / ssh / selinux / services / filesystem_permissions) |
| `tests/*_test.rego` | — (not bundled) | unit tests, run by `opa test rego-overlay/` and gated in CI |

## Why this lives here (transitional)

The legacy `data.cis_rhel9.*` modules in
[`ynotbhatc/rego_policy_libraries`](https://github.com/ynotbhatc/rego_policy_libraries)
(`cis_rhel9_complete.rego`) evaluate against raw `input.ansible_facts`. The
`fact_contract/v1` path sends a **projected** `input.framework_facts` (the nouns
declared in `data.cis_rhel9.metadata.facts_schema`), so it needs a rule written
against that shape. The canonical home is alongside the framework's rego
upstream; until it lands there, this overlay provides it so the bundle serves
`/v1/data/cis_rhel9/main/compliance_report` today.

## Coverage

`cis_rhel9_main.rego` is the **starter** set keyed to `xcomplai.cis_os` v1.2.0's
`facts_schema` (9 controls across the 5 nouns the collection currently gathers).
`compliance_percentage` is reported over the **evaluated** controls, not the full
338-control benchmark (see `coverage` in the report). It grows as the collection
extends its `facts_schema` (auth/audit/pam/sudo/network/cron/boot/…).

## Adding controls / frameworks

1. Extend `cis_rhel9_main.rego` (add a `violation contains {…} if {…}` rule and
   its id to the `controls` set) as the collection gathers the needed noun.
2. New framework → add `<framework>_main.rego` here (+ its `metadata/<framework>.rego`).
3. Add/extend `tests/` and tag a bundle release.
