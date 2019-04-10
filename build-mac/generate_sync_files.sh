#!/bin/bash

export LANG=en_US.UTF-8
mkdir -p "$BUILT_PRODUCTS_DIR/include"

cd "$SRCROOT/.."

bash -l -c "gmake -C sync"
bash -l -c "gmake -C asn.1 Sync.c"

