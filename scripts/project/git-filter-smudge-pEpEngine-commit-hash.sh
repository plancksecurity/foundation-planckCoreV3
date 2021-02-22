#! /bin/sh

echo "HELLO????" >&2

#
# Smudge file for pEpEngine's commit-hash header
#

if [[ "$OSTYPE" == "darwin"* ]]; then
    SED="sed -i ''"
else
    SED="sed -i"
fi

commit_hash="$(git rev-parse HEAD)"
echo "Replacing PEP_CURRENT_COMMIT_HASH value in src/commit_hash.h with current HEAD commit hash, $commit_hash. Will clean on commit or checkout."

$($SED "s/\(PEP_CURRENT_COMMIT_HASH=\).*/\1\"$commit_hash\"/" $1)

