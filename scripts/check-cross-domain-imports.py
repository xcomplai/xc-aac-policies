#!/usr/bin/env python3
"""check-cross-domain-imports.py — guard the per-domain bundle partition.

Each AAC OPA instance pulls only its own domain bundle (security / compliance /
ot), built from a directory partition of the rego source (bundle-domains.yaml).
A bundle owns the ROOTS (top-level package tokens) of the packages it contains,
and an OPA instance can only evaluate the packages it actually loads.

So the moment a framework in ONE domain references a rego PACKAGE defined in
ANOTHER domain (e.g. a compliance framework importing `data.aac.lib.linux`,
where the `aac.lib.*` packages live in the security bundle), that reference is
UNRESOLVABLE in the referencing instance's bundle — the assessment silently
returns {} / undefined.

The fix is NOT to duplicate the shared code: it is to factor the shared
package(s) into a `common` bundle that is co-loaded ALONGSIDE every domain
bundle (OPA supports multiple bundles per instance with DISJOINT roots), built
from the same source release so the shared layer never drifts.

This script is that trip-wire: it FAILS the build the first time a cross-domain
PACKAGE reference appears, with the exact remediation, so the common bundle gets
added at precisely the point it becomes necessary — not before (premature 4th
bundle) and not after (a shipped-but-broken bundle).

Precision: it matches references against the set of package paths actually
DEFINED in the source (longest-prefix), so `data.aac.lib.linux` (a real shared
package) is caught while `data.aac.templates` (runtime-injected DATA — no such
package) is not. Roots claimed by two domains (which would block disjoint-root
co-loading) are reported separately.

Usage:  check-cross-domain-imports.py <rego_src_dir> [--config bundle-domains.yaml]
Exit:   0 = clean   1 = violation(s)   2 = bad input
"""
import argparse
import glob
import os
import re
import sys

try:
    import yaml
except ImportError:
    print("::error::PyYAML required (pip install pyyaml)", file=sys.stderr)
    sys.exit(2)

PKG_RE = re.compile(r"^\s*package\s+([A-Za-z_][\w.]*)")
IMPORT_RE = re.compile(r"^\s*import\s+data\.([A-Za-z_][\w.]*)")
DATAREF_RE = re.compile(r"\bdata\.([A-Za-z_][\w.]*)")


def rego_files(root_dir):
    return glob.glob(os.path.join(root_dir, "**", "*.rego"), recursive=True)


def file_package(path):
    """Full dotted package path of a rego file (e.g. aac.lib.linux)."""
    with open(path, encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            m = PKG_RE.match(line)
            if m:
                return m.group(1)
    return None


def referenced_paths(path):
    """Dotted package paths this file references via `import data.X` / inline `data.X`.

    Comment lines and trailing comments are stripped to avoid doc/example noise."""
    refs = set()
    with open(path, encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            if line.lstrip().startswith("#"):
                continue
            m = IMPORT_RE.match(line)
            if m:
                refs.add(m.group(1))
            for dm in DATAREF_RE.finditer(line.split("#", 1)[0]):
                refs.add(dm.group(1))
    return refs


def resolve_owner(ref, pkg_owner):
    """Longest defined package that `ref` falls under → its owning domain, else None.

    A reference owns a package if ref == pkg or ref starts with pkg + '.'."""
    best = None
    for pkg in pkg_owner:
        if ref == pkg or ref.startswith(pkg + "."):
            if best is None or len(pkg) > len(best):
                best = pkg
    return (best, pkg_owner[best]) if best else (None, None)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("rego_src", help="checked-out xc-rego-policies tree")
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    ap.add_argument("--config", default=os.path.join(here, "bundle-domains.yaml"))
    args = ap.parse_args()

    if not os.path.isdir(args.rego_src):
        print(f"::error::rego_src '{args.rego_src}' is not a directory", file=sys.stderr)
        return 2

    with open(args.config, encoding="utf-8") as fh:
        domains = yaml.safe_load(fh)["domains"]

    pkg_owner = {}                  # full package path -> domain
    root_owner = {}                 # top-level root token -> domain
    overlaps = []                   # (root, domainA, domainB)
    files_by_domain = {}            # domain -> [abs file paths]
    for domain, spec in domains.items():
        dfiles = []
        for rel in spec.get("paths", []):
            base = os.path.join(args.rego_src, rel)
            if os.path.exists(base):
                dfiles.extend(rego_files(base))
        files_by_domain[domain] = dfiles
        for f in dfiles:
            pkg = file_package(f)
            if not pkg:
                continue
            pkg_owner[pkg] = domain
            root = pkg.split(".", 1)[0]
            if root in root_owner and root_owner[root] != domain:
                overlaps.append((root, root_owner[root], domain))
            else:
                root_owner[root] = domain

    # Cross-domain PACKAGE references.
    violations = {}  # (ref_domain, pkg, owning_domain) -> set(example files)
    for domain, dfiles in files_by_domain.items():
        for f in dfiles:
            for ref in referenced_paths(f):
                pkg, owning = resolve_owner(ref, pkg_owner)
                if owning and owning != domain:
                    key = (domain, pkg, owning)
                    violations.setdefault(key, set()).add(os.path.relpath(f, args.rego_src))

    ok = True

    if overlaps:
        ok = False
        print("::error::bundle-domain partition OVERLAP — a root is claimed by two domains:")
        for root, a, b in sorted(set(overlaps)):
            print(f"    root '{root}' is in both '{a}' and '{b}' — bundles must have DISJOINT roots")

    if violations:
        ok = False
        print("::error::CROSS-DOMAIN policy reference detected — a common bundle is now required.")
        print("")
        for (domain, pkg, owning), exs in sorted(violations.items()):
            sample = ", ".join(sorted(exs)[:3])
            more = "" if len(exs) <= 3 else f" (+{len(exs) - 3} more)"
            print(f"  • domain '{domain}' references data.{pkg} — defined in the '{owning}' bundle.")
            print(f"      in: {sample}{more}")
        print("")
        print("  WHY THIS FAILS: each OPA instance loads only its domain bundle, so a")
        print("  package from another domain resolves to undefined at runtime.")
        print("")
        print("  FIX — factor the shared package(s) into a `common` bundle:")
        print("    1. In bundle-domains.yaml, add a `common` domain whose paths cover")
        print("       the shared rego (e.g. aac/rego/lib_*.rego + crosswalk), and REMOVE")
        print("       those paths from the domain that currently owns them so roots stay DISJOINT.")
        print("    2. build-domain-bundles.sh already emits one bundle per domain key,")
        print("       so `common` builds automatically once it's in the config.")
        print("    3. In the aac-opa chart, add a SECOND bundle entry (the common bundle)")
        print("       to every OPA instance — OPA co-loads multiple bundles with disjoint roots.")
        print("    See opa-per-instance-scoping for the full procedure.")

    if ok:
        print(f"OK — no cross-domain package references; {len(pkg_owner)} packages / "
              f"{len(root_owner)} roots across {len(domains)} domains, all self-contained.")
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
