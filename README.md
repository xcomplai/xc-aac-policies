# xc-aac-policies

OPA policy bundle releases for [xc-aac](https://github.com/xcomplai/xc-aac), built from the rego policy source at [ynotbhatc/rego_policy_libraries](https://github.com/ynotbhatc/rego_policy_libraries).

Each tagged release publishes:
- `xc-aac-policies-vX.Y.Z.tar.gz` — the OPA bundle, consumable by OPA's HTTPS bundle service.
- `xc-aac-policies-vX.Y.Z.tar.gz.sha256` — sidecar checksum for integrity verification.

The [`aac-opa` Helm chart](https://github.com/xcomplai/xc-aac/blob/main/deploy/helm/aac-opa/values.yaml) in xcomplai/xc-aac points at these release URLs by default.

## Consume from OPA

```yaml
services:
  aac-bundle-server:
    url: https://github.com/xcomplai/xc-aac-policies/releases/download/v1.0.0
bundles:
  aac:
    service: aac-bundle-server
    resource: xc-aac-policies-v1.0.0.tar.gz
    polling:
      min_delay_seconds: 60
      max_delay_seconds: 120
    persist: true
persistence_directory: /tmp/opa-persist
```

When running under the `aac-opa` chart, this is rendered for you — set `policies.bundle.enabled=true` and override `policies.bundle.https.resource` to pin a specific release.

## Cutting a new release

1. **Bump `policy-source.yaml`** in this repo to the rego commit SHA (or tag) you want to build from:
   ```yaml
   source:
     repo: ynotbhatc/rego_policy_libraries
     ref: <new-sha-or-tag>
   ```
2. Commit and push to `main`.
3. Tag the release and push the tag:
   ```bash
   git tag v1.1.0
   git push origin v1.1.0
   ```
4. The [`release-bundle` workflow](.github/workflows/release-bundle.yml) fires on the tag push: clones the rego source at the pinned ref, runs `opa build`, and creates the GitHub Release with the bundle tarball + SHA256 sidecar.
5. (Downstream) Bump the `aac-opa` chart's default `policies.bundle.https.resource` in xcomplai/xc-aac when consumers should roll forward.

You can also trigger the workflow manually from the Actions tab via `workflow_dispatch`, passing a tag input — useful for re-running a build against an existing tag.

## Build a bundle locally

```
git clone https://github.com/ynotbhatc/rego_policy_libraries.git
cd rego_policy_libraries
opa build -b . -o /tmp/xc-aac-policies-vX.Y.Z.tar.gz
sha256sum /tmp/xc-aac-policies-vX.Y.Z.tar.gz
```
