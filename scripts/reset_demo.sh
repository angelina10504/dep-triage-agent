#!/usr/bin/env bash
# Reset the demo target after a TC4 run (PR #1 merged -> requests bumped on main).
# Pushes a NEW commit to dep-triage-demo main that pins requests==2.28.0 again.
# No force-push, no history rewrite: works in a throwaway clone, so the local
# ~/dep-triage-demo checkout (and any uncommitted files in it) are never touched.
set -euo pipefail

REPO="${DEMO_REPO:-https://github.com/angelina10504/dep-triage-demo.git}"
PIN="requests==2.28.0"

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
git clone --quiet --depth 1 "$REPO" "$work/demo"
cd "$work/demo"

if ! grep -qiE '^requests[[:space:]]*==' requirements.txt; then
  echo "error: no 'requests==' line in requirements.txt; refusing to guess" >&2
  exit 1
fi
# Replace only the requests pin, keep every other line as is.
sed -E -i.bak "s/^[Rr]equests[[:space:]]*==[^[:space:];#]*/$PIN/" requirements.txt && rm requirements.txt.bak

if git diff --quiet -- requirements.txt; then
  echo "already pinned to $PIN; nothing to push"
  exit 0
fi
git --no-pager diff -- requirements.txt
git add requirements.txt
git commit --quiet -m "Reset demo: pin $PIN for the next TC1 run"
git push --quiet origin HEAD:main            # plain push: rejected if main moved, never forced
echo "pushed $(git rev-parse --short HEAD) to main: $PIN"
