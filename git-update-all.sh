#!/bin/bash

HERE=$(pwd)

for env in api web; do
    echo -e "\nUpdating $env\n"

    cd $HERE/$env

    CURRENT=$(git rev-parse --abbrev-ref HEAD)

    git fetch --all > /dev/null
#    git remote prune origin > /dev/null

    for branch in $(git branch -r | grep -v '\->' | sed 's/origin\///'); do
        git checkout $branch > /dev/null
        git pull origin $branch > /dev/null

        echo ""
    done

    git checkout $CURRENT > /dev/null
done

echo ""

exit 0

