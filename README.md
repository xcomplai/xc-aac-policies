# xc-aac-policies

OPA policy bundle releases for [xc-aac](https://github.com/xcomplai/xc-aac), built from the rego policy source at [ynotbhatc/rego_policy_libraries](https://github.com/ynotbhatc/rego_policy_libraries).

Each tagged release publishes a tarball asset (`xc-aac-policies-vX.Y.Z.tar.gz`) consumable by OPA's HTTPS bundle service. The `aac-opa` Helm chart in `xcomplai/xc-aac` points at these release URLs by default.

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

## Build a bundle

```
git clone https://github.com/ynotbhatc/rego_policy_libraries.git
cd rego_policy_libraries
opa build -b . -o ../xc-aac-policies-vX.Y.Z.tar.gz
```

Then create a release on this repo with the tarball as an asset.
