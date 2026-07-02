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
  # v3 layout: shared libs (aac/lib/*) + catalog contract (aac/catalog/*) → EVERY
  # bundle; each framework dir aac/frameworks/<fw>/<token>/ (policy + metadata +
  # register) → the bundle named by its metadata.domain. The shared lib travels
  # with the policies so the bundle compiles standalone (rego function libs can't
  # be split across separately-built bundles); lib duplication across bundles is
  # intentional (lockstep build → no drift). Co-located *_test.rego NEVER ship.
  while IFS= read -r rel; do
    [ -n "$rel" ] || continue
    mkdir -p "$asm/$(dirname "$rel")"
    cp "$SRC/$rel" "$asm/$rel"
  done < <(python3 - "$SRC" "$D" "$CONFIG" <<'PY'
import sys, glob, os, re
src, domain = sys.argv[1], sys.argv[2]
aac = os.path.join(src, "aac")
out = []
def add(p):
    if os.path.exists(p) and not p.endswith("_test.rego"):
        out.append(os.path.relpath(p, src))
# Shared → every bundle (domain-agnostic): plane libs + crosswalk (aac/lib/), the
# catalog contract (aac/catalog/), and the report/derivation layer (aac/report/ —
# debt scoring etc., on the assessment-output contract; ADR-016). Exclude tests.
# Recurse (**): a lib noun may be a single file (aac/lib/windows.rego) OR a
# file-per-noun subdir keeping the same package (aac/lib/linux/*.rego, package
# aac.lib.linux — ADR-047 P1). A one-level glob silently drops the split bodies,
# so the bundle fails opa build with undefined-function errors. catalog/report
# recurse too: harmless today (flat) and future-proof if they split likewise.
# The add() _test.rego filter still excludes co-located tests at any depth.
for p in sorted(glob.glob(os.path.join(aac, "lib", "**", "*.rego"), recursive=True)
                + glob.glob(os.path.join(aac, "catalog", "**", "*.rego"), recursive=True)
                + glob.glob(os.path.join(aac, "report", "**", "*.rego"), recursive=True)):
    add(p)
# Per-framework: route the whole framework dir (policy + metadata + register; a
# preview stub has metadata + register only, no policy) by metadata.domain.
DOM = re.compile(r'default\s+domain\s*:=\s*"([^"]+)"')
for meta in sorted(glob.glob(os.path.join(aac, "frameworks", "*", "*", "metadata.rego"))):
    txt = open(meta, encoding="utf-8", errors="ignore").read()
    md = DOM.search(txt)
    if not md or md.group(1) != domain:
        continue
    for f in sorted(glob.glob(os.path.join(os.path.dirname(meta), "*.rego"))):
        add(f)
# Co-load delegation TARGETS (policy-only, NO catalog registration). A framework
# in THIS domain may REFERENCE a framework whose home domain is another (e.g.
# compliance/hipaa §164.312(a)/(b)/(d) delegate to data.nist_800_53.rev5, whose
# home domain is security). That target package is otherwise undefined in this
# bundle → the referencing rules yield degenerate rows. bundle-domains.yaml lists
# such targets under domains.<D>.co_load_frameworks (["<fw>/<token>", ...]); we
# co-load ONLY their policy + metadata namespaces so the reference RESOLVES, and
# EXCLUDE their aac.catalog self-registration (register.rego / any `package
# aac.catalog` file) so the target does NOT leak into THIS domain's catalog (and
# thus its generated coverage). The target's home-domain routing above stays the
# SOLE owner of its catalog entry. Co-located *_test.rego never ship (add() drops
# them). Built lockstep from the same source release, so no drift.
import yaml as _yaml
_cfg = _yaml.safe_load(open(sys.argv[3], encoding="utf-8"))
_CATPKG = re.compile(r'^\s*package\s+aac\.catalog\b', re.M)
for rel in (_cfg["domains"].get(domain, {}).get("co_load_frameworks") or []):
    fdir = os.path.join(aac, "frameworks", rel)
    if not os.path.isdir(fdir):
        sys.stderr.write("::warning::co_load_frameworks: '%s' not found under aac/frameworks — skipped\n" % rel)
        continue
    for f in sorted(glob.glob(os.path.join(fdir, "*.rego"))):
        head = open(f, encoding="utf-8", errors="ignore").read(4096)
        if _CATPKG.search(head):   # skip aac.catalog registration → no catalog leak
            continue
        add(f)                     # add() still drops *_test.rego + missing
for f in out:
    print(f)
PY
)

  # Hygiene gate: tests NEVER ship. The lib injection above already filters
  # *_test.rego, but the domain `paths` copy (cp -r whole dirs) does not, so a
  # co-located test under any path (e.g. benchmarks/.../cis_rhel9_test.rego)
  # would otherwise ride along. Strip them from the assembled tree before build.
  find "$asm" -name '*_test.rego' -delete

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
