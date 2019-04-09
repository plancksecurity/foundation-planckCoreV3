#!/bin/bash

cd src; hg status . | sed '/?\ /!d' | sed 's/?\ //' | xargs rm
cd ../asn.1; hg status . | sed '/?\ /!d' | sed 's/?\ //' |  xargs rm
cd ../sync; hg status . | sed '/?\ /!d' | sed 's/?\ //' |  xargs rm
cd ..
branch=`hg branch`
if [ "$branch" = "sync" ]; then
    rm src/KeySync_fsm.c src/KeySync_fsm.h src/Sync_actions.c src/Sync_event.c src/Sync_event.h src/Sync_func.c src/Sync_func.h src/Sync_impl.c src/Sync_impl.h src/sync_codec.c src/sync_codec.h
fi	
