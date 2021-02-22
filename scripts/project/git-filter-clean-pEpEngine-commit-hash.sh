#! /bin/bash

#
# Clean filter for pEpEngine's commit-hash header.
#

if [[ "$OSTYPE" == "darwin"* ]]; then
    SED='sed -i '"'""'"
else
    SED="sed -i"
fi

echo "FILE is $1"
echo "Replacing PEP_CURRENT_COMMIT_HASH value in src/commit_hash.h with DUMMY_COMMIT_HASH_ERROR. See you next checkout or after the commit!"

$($SED "s/\(PEP_CURRENT_COMMIT_HASH=\).*/\1\DUMMY_COMMIT_HASH_ERROR\"/" $1)

# Honestly, I have no idea what git is doing with the stupid empty '' for sed, but I give up. It makes a commit_hash.h'' backup for no reason. So we eat it.
if [[ "$OSTYPE" == "darwin"* ]]; then
    rm $1"'""'"
else
