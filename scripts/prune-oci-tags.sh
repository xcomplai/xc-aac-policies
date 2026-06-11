#!/usr/bin/env bash
# prune-oci-tags.sh — tag-hygiene for the ghcr.io xc-aac-policies OCI mirror (#29).
#
# Automates the by-hand rc.1-style cleanup: after a promote, remove (1) ORPHANED
# untagged GHCR versions and (2) SUPERSEDED edge versions beyond a keep-window.
#
# ⚠ GHCR deletes by VERSION (digest), and a version can carry MANY tags. Because
# retag-no-rebuild (cosign copy) points stable/rc/digest tags at the SAME digest
# as the edge they were promoted from, a single version may hold e.g.
#   [ v3.0.0-security, v3.0.0-rc.2-security, sha256-…, v3.0.0-edge.15-security ].
# Deleting THAT version to "prune edge.15" would also delete STABLE. So the hard
# rule: a version is prunable ONLY IF *every* tag on it is unprotected — i.e. it
# is purely an old edge version (or fully untagged). Any version carrying a
# stable / rc / *-latest / sha256- / explicitly-protected tag is KEPT, full stop.
#
# Default is DRY-RUN (prints the plan, deletes nothing). Pass --apply to delete.
# --apply needs a token with delete:packages (org container admin): set GH_TOKEN.
#
# Usage:
#   prune-oci-tags.sh [--org ORG] [--package NAME] [--keep-edge N] [--apply]
#                     [--protect 'regex']   # extra keep-pattern (repeatable)
set -euo pipefail

ORG=xcomplai PKG=xc-aac-policies KEEP_EDGE=5 APPLY=0
EXTRA_PROTECT=()
while [ $# -gt 0 ]; do
  case "$1" in
    --org)       ORG="$2"; shift 2 ;;
    --package)   PKG="$2"; shift 2 ;;
    --keep-edge) KEEP_EDGE="$2"; shift 2 ;;
    --apply)     APPLY=1; shift ;;
    --protect)   EXTRA_PROTECT+=("$2"); shift 2 ;;
    -h|--help)   sed -n '2,28p' "$0"; exit 0 ;;
    *) echo "prune: unknown arg $1" >&2; exit 2 ;;
  esac
done
command -v gh >/dev/null || { echo "prune: gh not found" >&2; exit 2; }
command -v jq >/dev/null || { echo "prune: jq not found" >&2; exit 2; }

# A tag is PROTECTED if it is anything other than a pure edge channel tag:
#   bare stable  vX.Y.Z-<domain>     | rc channel  *-rc.*  | moving  *-latest
#   digest pin   sha256-*            | + any --protect regex
is_protected_tag() {
  local t="$1"
  [[ "$t" =~ ^v[0-9]+\.[0-9]+\.[0-9]+-(security|compliance|ot)$ ]] && return 0
  [[ "$t" == *-rc.* ]]      && return 0
  [[ "$t" == *-latest ]]    && return 0
  [[ "$t" == sha256-* ]]    && return 0
  local p; for p in "${EXTRA_PROTECT[@]:-}"; do [ -n "$p" ] && [[ "$t" =~ $p ]] && return 0; done
  return 1
}
# Edge tag → its integer edge number (for the keep-window). Empty if not an edge tag.
edge_num() { [[ "$1" =~ -edge\.([0-9]+)- ]] && echo "${BASH_REMATCH[1]}" || echo ""; }

echo "==> listing ghcr.io/${ORG}/${PKG} versions…"
VERSIONS_JSON="$(gh api --paginate \
  "/orgs/${ORG}/packages/container/${PKG}/versions?per_page=100" \
  | jq -s 'add')"
TOTAL="$(echo "$VERSIONS_JSON" | jq 'length')"

# Newest KEEP_EDGE distinct edge NUMBERS to keep (across domains).
KEEP_NUMS="$(echo "$VERSIONS_JSON" \
  | jq -r '.[].metadata.container.tags // [] | .[]' \
  | sed -nE 's/.*-edge\.([0-9]+)-.*/\1/p' | sort -un | tail -n "$KEEP_EDGE" | tr '\n' ' ')"
echo "    keeping the newest ${KEEP_EDGE} edge numbers: ${KEEP_NUMS:-<none>}"

declare -a PRUNE_IDS PRUNE_DESC
KEPT_PROTECTED=0 KEPT_RECENT=0

while IFS=$'\t' read -r id tagsjoined; do
  # Build the tag array for this version.
  mapfile -t tags < <(echo "$tagsjoined" | tr ',' '\n' | sed '/^$/d')

  if [ "${#tags[@]}" -eq 0 ]; then
    PRUNE_IDS+=("$id"); PRUNE_DESC+=("$id  <UNTAGGED orphan>"); continue
  fi
  # KEEP if ANY tag is protected.
  protected=0; for t in "${tags[@]}"; do is_protected_tag "$t" && { protected=1; break; }; done
  if [ "$protected" = 1 ]; then KEPT_PROTECTED=$((KEPT_PROTECTED+1)); continue; fi
  # Here: all tags are pure edge channel tags. Keep if within the edge window.
  num=""; for t in "${tags[@]}"; do n="$(edge_num "$t")"; [ -n "$n" ] && num="$n" && break; done
  if [ -z "$num" ]; then KEPT_PROTECTED=$((KEPT_PROTECTED+1)); continue; fi   # unparseable → keep (safe)
  keep=0; for k in $KEEP_NUMS; do [ "$k" = "$num" ] && keep=1 && break; done
  if [ "$keep" = 1 ]; then KEPT_RECENT=$((KEPT_RECENT+1)); continue; fi
  PRUNE_IDS+=("$id"); PRUNE_DESC+=("$id  edge.${num}  [${tagsjoined}]")
done < <(echo "$VERSIONS_JSON" | jq -r '.[] | "\(.id)\t\((.metadata.container.tags // []) | join(","))"')

echo "==> plan: ${TOTAL} versions — keep ${KEPT_PROTECTED} protected, ${KEPT_RECENT} recent-edge; PRUNE ${#PRUNE_IDS[@]}"
for d in "${PRUNE_DESC[@]:-}"; do [ -n "$d" ] && echo "    PRUNE  $d"; done

if [ "${#PRUNE_IDS[@]}" -eq 0 ]; then echo "✅ nothing to prune."; exit 0; fi
if [ "$APPLY" = 0 ]; then
  echo "— DRY-RUN (no deletions). Re-run with --apply (needs delete:packages) to execute."
  exit 0
fi

echo "==> applying: deleting ${#PRUNE_IDS[@]} versions…"
fail=0
for id in "${PRUNE_IDS[@]}"; do
  if gh api -X DELETE "/orgs/${ORG}/packages/container/${PKG}/versions/${id}" >/dev/null 2>&1; then
    echo "    deleted $id"
  else
    echo "    ::warning::could not delete $id (need delete:packages?)"; fail=1
  fi
done
[ "$fail" = 0 ] && echo "✅ prune complete." || { echo "⚠ some deletions failed."; exit 1; }
