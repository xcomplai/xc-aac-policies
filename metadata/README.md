# Metadata overlay (Tier 3.J)

Files in this directory are **injected into the bundle at CI build time** alongside the rego cloned from [ynotbhatc/rego_policy_libraries](https://github.com/ynotbhatc/rego_policy_libraries). The release-bundle workflow copies `./metadata/*.rego` into `./rego_src/` before running `opa build`, so every published bundle (v1.0.4 onward) carries:

- `data.<framework>.metadata` per supported framework (one rego file per framework).
- `data.aac.catalog` — aggregator + lookup helpers across every framework declared above.

Both are consumed by the orchestration layer in [xcomplai/xc-aac](https://github.com/xcomplai/xc-aac):
- `ansible/playbooks/generic_framework_assessment.yml` queries `data.aac.catalog.metadata[<framework>]` to discover the framework's collection, OPA endpoint, PG table, dashboard UID, and facts schema.
- UIs / dashboards iterate `data.aac.catalog.frameworks` to enumerate what's available without xc-aac needing to know in advance.

## Why this lives here (transitional)

The canonical home for each framework's metadata is alongside its rego in [ynotbhatc/rego_policy_libraries](https://github.com/ynotbhatc/rego_policy_libraries) (e.g. `cis_rhel9/cis_rhel9_metadata.rego`). Until those declarations land upstream, `xc-aac-policies` provides them as an **overlay** that gets bundled alongside the source rego.

When upstream accepts the metadata declarations:
1. Drop the framework's file from this directory.
2. Bump `policy-source.yaml`'s `ref` to the upstream commit with the metadata.
3. Cut a new release tag — the build automatically excludes that framework from the overlay.

`aac_catalog.rego` may stay in this repo permanently (as the bundle's curation layer over the rego library), or also migrate upstream — TBD per upstream's appetite.

## Adding a framework

When a new framework collection ships (e.g. `xcomplai.cis_rhel8`):

1. Add `metadata/<framework>.rego` declaring `data.<framework>.metadata` per [the contract](https://github.com/xcomplai/xc-aac/blob/main/docs/architecture/FACT_CONTRACT.md#metadata-declared-in-rego-data%3Cframework%3Emetadata).
2. Append a `frameworks contains { key: "...", metadata: data.<framework>.metadata }` entry to `aac_catalog.rego`.
3. Bump `xc-aac`'s `framework_dispatch_map` in `ansible/vars/site_config.yml` with the same dispatch info for the local-fallback path.
4. Tag a new bundle release.

## Tier 3.K rollout

Each framework collection (Tier 3.K) adds one metadata file here and one `frameworks contains` entry in `aac_catalog.rego`. The CI bundle build picks them up automatically.
