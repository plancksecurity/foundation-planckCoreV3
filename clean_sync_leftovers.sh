#!/bin/bash

cd src; hg status . | sed '/?\ /!d' | sed 's/?\ //' | xargs rm
cd ../asn.1; hg status . | sed '/?\ /!d' | sed 's/?\ //' |  xargs rm
cd ../sync; hg status . | sed '/?\ /!d' | sed 's/?\ //' |  xargs rm
cd ..
