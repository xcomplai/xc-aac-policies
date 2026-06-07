#!/usr/bin/env bash
# build-domain-bundles.sh — build ONE OPA bundle per AAC domain (security /
# compliance / ot) from a directory-level partition of the rego source.
#
# Per opa-per-instance-scoping: each OPA instance pulls only its domain bundle.
# Driven by bundle-domains.yaml (domains.<name>.paths). All bundles are built
# from the SAME source tree in one run (lockstep), so a shared package never
# skews between domains.
#
# Usage: build-domain-bundles.sh <rego_src_dir> <out_dir> <tag>
#   rego_src_dir  checked-out xcomplai/xc-rego-policies at the pinned ref
#   out_dir       where the per-domain tarballs + .sha256 sidecars are written
#   tag           release tag (e.g. v2.1.0) — used in the filename + manifest revision
#
# Output per domain: <out>/xc-aac-policies-<domain>-<tag>.tar.gz (+ .sha256)
set -euo pipefail

SRC="${1:?rego_src_dir required}"
OUT="${2:?out_dir required}"
TAG="${3:?tag required}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG="${BUNDLE_DOMAINS_CONFIG:-$HERE/bundle-domains.yaml}"

command -v opa >/dev/null || { echo "::error::opa not found on PATH"; exit 1; }
mkdir -p "$OUT"

domains=$(python3 -c "import yaml,sys; print(' '.join(yaml.safe_load(open('$CONFIG'))['domains'].keys()))")

for D in $domains; do
  asm="$(mktemp -d)"
  # paths for this domain
  mapfile -t paths < <(python3 -c "import yaml; print('\n'.join(yaml.safe_load(open('$CONFIG'))['domains']['$D']['paths']))")
  found=0
  for p in "${paths[@]}"; do
    if [ -e "$SRC/$p" ]; then
      mkdir -p "$asm/$(dirname "$p")"
      cp -r "$SRC/$p" "$asm/$p"
      found=$((found + 1))
    else
      echo "::warning::domain '$D' path '$p' not present in source — skipped"
    fi
  done
  [ "$found" -gt 0 ] || { echo "::error::domain '$D' has no source paths present"; exit 1; }

  # ── Option F: inject the fact_contract layer (aac/) into this bundle ─────────
  # Shared aac (lib_*, crosswalk, catalog aggregator) → EVERY bundle; each
  # framework's main/metadata/registration → the bundle named by its
  # metadata.domain. The shared lib travels with the mains so the bundle compiles
  # standalone (rego function libs can't be split across separately-built
  # bundles). Lib duplication across bundles is intentional (lockstep build → no
  # drift). See bundle-domains.yaml.
  while IFS= read -r rel; do
    [ -n "$rel" ] || continue
    mkdir -p "$asm/$(dirname "$rel")"
    cp "$SRC/$rel" "$asm/$rel"
  done < <(python3 - "$SRC" "$D" <<'PY'
import sys, glob, os, re
src, domain = sys.argv[1], sys.argv[2]
aac = os.path.join(src, "aac")
out = []
# Shared: libs + crosswalk + the catalog aggregator → every bundle.
shared = glob.glob(os.path.join(aac, "rego", "lib_*.rego")) + [
    os.path.join(aac, "rego", "crosswalk.rego"),
    os.path.join(aac, "metadata", "aac_catalog.rego"),
]
for p in shared:
    if os.path.exists(p):
        out.append(os.path.relpath(p, src))
# Per-framework: route main + metadata + registration by metadata.domain.
DOM = re.compile(r'default\s+domain\s*:=\s*"([^"]+)"')
KEY = re.compile(r'default\s+framework_key\s*:=\s*"([^"]+)"')
for meta in sorted(glob.glob(os.path.join(aac, "metadata", "*.rego"))):
    b = os.path.basename(meta)
    if b == "aac_catalog.rego" or b.endswith("_catalog.rego"):
        continue  # aggregator + registrations handled separately
    txt = open(meta, encoding="utf-8", errors="ignore").read()
    md = DOM.search(txt)
    if not md or md.group(1) != domain:
        continue
    fk = KEY.search(txt)
    fw = fk.group(1) if fk else b[:-5]
    for cand in [
        os.path.join(aac, "rego", fw + "_main.rego"),
        meta,
        os.path.join(aac, "metadata", fw + "_catalog.rego"),
    ]:
        if os.path.exists(cand):
            out.append(os.path.relpath(cand, src))
for f in out:
    print(f)
PY
)

  # Write an explicit .manifest with revision + the per-namespace ROOTS this
  # bundle owns (the top-level data namespace of every package it contains, e.g.
  # cis_rhel9 / aac / iso27001). opa build does NOT auto-derive roots — without
  # an explicit list it ships roots:[""] (claim-everything), which works for one
  # bundle per instance but blocks the future common+domain co-load (disjoint
  # roots required) and hides the domain boundary. Computing them here makes the
  # bundle properly scoped + future-ready.
  python3 - "$asm" "${TAG}-${D}" > "$asm/.manifest" <<'PY'
import sys, glob, re, json
asm, rev = sys.argv[1], sys.argv[2]
roots = set()
for f in glob.glob(asm + '/**/*.rego', recursive=True):
    for line in open(f, encoding='utf-8', errors='ignore'):
        m = re.match(r'\s*package\s+([A-Za-z_][A-Za-z0-9_]*)', line)
        if m:
            roots.add(m.group(1)); break
print(json.dumps({"revision": rev, "roots": sorted(roots)}))
PY
  bundle="$OUT/xc-aac-policies-${D}-${TAG}.tar.gz"
  opa build -b "$asm" -o "$bundle"
  sha256sum "$bundle" | awk '{print $1}' > "$bundle.sha256"
  roots=$(tar xzOf "$bundle" /.manifest 2>/dev/null | python3 -c "import sys,json; print(len(json.load(sys.stdin).get('roots',[])))" 2>/dev/null || echo '?')
  rego=$(find "$asm" -name '*.rego' | wc -l)
  echo "  built $D: $(basename "$bundle")  ($rego rego files, $roots roots, $(du -h "$bundle" | cut -f1))"
  rm -rf "$asm"
done

echo "domain bundles written to $OUT"
