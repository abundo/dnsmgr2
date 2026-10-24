#!/usr/bin/env bash
# Print a release's section of CHANGELOG.md (without its heading), the
# release notes GoReleaser publishes. Fails when the tag has no section.
#
#   dev/release-notes.sh v1.2.2 > notes.md
set -euo pipefail

tag=${1:?usage: release-notes.sh <tag>}
notes=$(awk -v h="## $tag" '
	$0 == h { on = 1; next }
	on && /^## / { exit }
	on { print }
' "$(dirname "$0")/../CHANGELOG.md")

if [ -z "$(echo "$notes" | tr -d '[:space:]')" ]; then
	echo "CHANGELOG.md has no section \"## $tag\"" >&2
	exit 1
fi
# Without the blank lines around the section.
echo "$notes" | sed -e '/./,$!d' | sed -e ':a' -e '/^\n*$/{$d;N;ba' -e '}'
