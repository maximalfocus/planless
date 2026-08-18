#!/bin/sh
# Review every surface a reader of this repository could reach.
#
# Publication is one-way: a pull-request ref outlives any history rewrite, so
# this runs over the whole git history and not only the working tree. It reports
# and changes nothing.
set -eu

cd "$(dirname "$0")/.."

status=0
report() {
	printf '%-46s %s\n' "$1" "$2"
	[ "$2" = "clean" ] || status=1
}

# Patterns that must not appear anywhere: credentials, real account identifiers,
# real cloud or cluster targets, or a link to anything private.
#
# The companion pattern matches the shape of a private companion repository name
# rather than any particular one, because a public artifact must never name a
# private companion — and a guard that spelled the name out in order to forbid it
# would publish it just as permanently as a commit message or a branch name.
# The kubeconfig patterns look for the artifact rather than the word: this
# project's documentation says out loud that no kubeconfig exists anywhere, and
# a promise of absence is not an exposure.
forbidden='AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|-----BEGIN [A-Z ]*PRIVATE KEY-----|xox[baprs]-|ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|[A-Za-z0-9][A-Za-z0-9_-]*-[Pp][Rr][Dd]|KUBECONFIG=|current-context:|\.amazonaws\.com|\.blob\.core\.windows\.net|\.googleapis\.com|eks\.amazonaws|AWS_SECRET_ACCESS_KEY|AZURE_CLIENT_SECRET|GOOGLE_APPLICATION_CREDENTIALS'

# The working tree, including files that are not tracked yet — a new file is
# invisible to a tracked-only search until it is staged, and by then it may
# already be in a commit.
#
# Two paths are excluded, and only these two: this script, and the package whose
# entire job is to hold the same pattern list for the in-container check. An
# exclusion nobody can see is how a review starts lying, so they are named here
# rather than hidden in a config file.
if git grep --untracked -nIE "$forbidden" -- . \
	':!scripts/exposure-review.sh' ':!internal/publication' >/tmp/planless-exposure-tree 2>/dev/null; then
	report "tracked files" "FINDINGS"
	cat /tmp/planless-exposure-tree
else
	report "tracked files" "clean"
fi

# Every commit message in the history.
if git log --format='%H %s%n%b' | grep -nIE "$forbidden" >/tmp/planless-exposure-log 2>/dev/null; then
	report "commit messages" "FINDINGS"
	cat /tmp/planless-exposure-log
else
	report "commit messages" "clean"
fi

# Every blob ever committed, including on branches that no longer exist.
if git rev-list --objects --all |
	git cat-file --batch-check='%(objecttype) %(objectname) %(rest)' |
	awk '$1 == "blob" { print $2, $3 }' |
	while read -r oid path; do
		if git cat-file blob "$oid" 2>/dev/null | grep -qIE "$forbidden"; then
			case "$path" in
			scripts/exposure-review.sh | internal/publication/*) continue ;;
			esac
			echo "$path ($oid)"
		fi
	done | grep . >/tmp/planless-exposure-blobs 2>/dev/null; then
	report "every blob in history" "FINDINGS"
	cat /tmp/planless-exposure-blobs
else
	report "every blob in history" "clean"
fi

# Branch and tag names are permanent provider surfaces too.
if git for-each-ref --format='%(refname)' | grep -nIE "$forbidden" >/dev/null 2>&1; then
	report "branch and tag names" "FINDINGS"
else
	report "branch and tag names" "clean"
fi

# No capability that would help against something real.
#
# Two places dial or resolve deliberately, and both are named here rather than
# excluded quietly:
#
#   internal/api        the platform's own network fabric, carrying a permitted
#                       connect to a workload inside the demonstration network
#   internal/selfcheck  proves that a reserved address does not connect and a
#                       reserved name does not resolve, which needs it to try
#
# Anything else that resolves a name or opens a socket is a capability this
# project should not have.
if git grep -nIE 'net\.LookupHost\(|net\.Dial' -- \
	':!internal/api' ':!internal/selfcheck' ':!*_test.go' >/dev/null 2>&1; then
	report "no discovery or dialling capability" "FINDINGS"
	git grep -nIE 'net\.LookupHost\(|net\.Dial' -- \
		':!internal/api' ':!internal/selfcheck' ':!*_test.go'
else
	report "no discovery or dialling capability" "clean"
fi

rm -f /tmp/planless-exposure-tree /tmp/planless-exposure-log /tmp/planless-exposure-blobs

if [ "$status" -eq 0 ]; then
	printf '\nexposure review: clean\n'
else
	printf '\nexposure review: FINDINGS — see above\n' >&2
fi
exit "$status"
