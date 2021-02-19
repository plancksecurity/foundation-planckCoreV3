#! /bin/bash

echo "HELLO" >&2
#
# Clean filter for pEpEngine's commit-hash header.
#

#if [[ "$OSTYPE" == "darwin"* ]]; then
#    SED="sed -i ''"
#else
    SED="sed -i"
#fi

echo "Replacing PEP_CURRENT_COMMIT_HASH value in src/commit_hash.h with DUMMY_COMMIT_HASH_ERROR. See you next checkout or after the commit!"

$($SED "s/\(PEP_CURRENT_COMMIT_HASH=\).*/\1\DUMMY_COMMIT_HASH_ERROR\"/" $1)

