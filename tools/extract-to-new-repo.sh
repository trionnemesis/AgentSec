#!/usr/bin/env bash
#
# Split this directory out into its own repository, keeping its commit history.
#
# The tree was developed as `agentsec/` inside wazuh_ai_agent so the first
# iteration could be reviewed in one place. `git subtree split` rewrites the
# history so every commit that touched this directory becomes a commit at the
# root of a new branch — no squash, no lost authorship.
#
#   ./tools/extract-to-new-repo.sh                  # dry run: show what happens
#   ./tools/extract-to-new-repo.sh --run            # split into a local branch
#   ./tools/extract-to-new-repo.sh --run --push git@github.com:you/agentsec.git
#
set -euo pipefail

PREFIX="agentsec"
BRANCH="agentsec-split"
DRY_RUN=1
REMOTE=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --run) DRY_RUN=0; shift ;;
    --push) DRY_RUN=0; REMOTE="${2:?--push needs a git remote URL}"; shift 2 ;;
    --branch) BRANCH="${2:?--branch needs a name}"; shift 2 ;;
    -h|--help) sed -n '2,14p' "$0" | sed 's/^# \?//'; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

REPO_ROOT="$(git rev-parse --show-toplevel)"
cd "$REPO_ROOT"

if [[ ! -d "$PREFIX" ]]; then
  echo "error: $PREFIX/ not found at the repository root ($REPO_ROOT)" >&2
  echo "       This script is meant to be run from the repo that still contains" >&2
  echo "       the tree as a subdirectory. If you have already split it out," >&2
  echo "       you do not need it." >&2
  exit 1
fi

if [[ -n "$(git status --porcelain)" ]]; then
  echo "error: working tree is dirty. Commit or stash first — a subtree split" >&2
  echo "       reads committed history, so uncommitted work would be lost." >&2
  exit 1
fi

COMMITS="$(git rev-list --count HEAD -- "$PREFIX")"

cat <<EOF
Extract $PREFIX/ into its own repository
────────────────────────────────────────
  source repo   $REPO_ROOT
  prefix        $PREFIX/
  commits       $COMMITS touching this prefix
  new branch    $BRANCH
  push to       ${REMOTE:-<not pushing>}

Steps:
  1. git subtree split --prefix=$PREFIX -b $BRANCH
  2. git push $BRANCH to the new remote as 'main'      (only with --push)

After extracting, in the NEW repo:
  - move .claude/ to the root and fix the hook path in .claude/settings.json
    (drop the leading 'agentsec/')
  - .github/workflows/ci.yml works unchanged
  - .github/workflows/agentsec-gate.yml default 'workspace' input becomes '.'
  - delete tools/extract-to-new-repo.sh — it has done its job

In the OLD repo, decide deliberately:
  - keep $PREFIX/ as a vendored copy, or
  - 'git rm -r $PREFIX' and reference the new repo from the README
  Do not do both by accident; two diverging copies is the worst outcome.
EOF

if [[ $DRY_RUN -eq 1 ]]; then
  echo
  echo "Dry run. Re-run with --run (optionally --push <url>) to do it."
  exit 0
fi

echo
echo "==> git subtree split --prefix=$PREFIX -b $BRANCH"
git branch -D "$BRANCH" 2>/dev/null || true
git subtree split --prefix="$PREFIX" -b "$BRANCH"

echo
echo "Created branch '$BRANCH' with $PREFIX/ at its root."

if [[ -n "$REMOTE" ]]; then
  echo
  echo "==> pushing $BRANCH -> $REMOTE main"
  # Not --force: if the target already has history, stop and let a human look.
  git push "$REMOTE" "$BRANCH:refs/heads/main"
  echo "Pushed. Clone it fresh to verify:"
  echo "  git clone $REMOTE /tmp/agentsec-verify && cd /tmp/agentsec-verify"
  echo "  pip install -e '.[dev]' && pytest -q && agentsec validate"
else
  echo
  echo "Not pushed. To push manually:"
  echo "  git push git@github.com:<you>/<repo>.git $BRANCH:refs/heads/main"
fi
