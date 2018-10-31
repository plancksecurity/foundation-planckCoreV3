#!/bin/bash

# Use this to generate test msg.asc and signature.asc

# Keys pair are : 
#
# pEp Test Alice (test key don't use) <pep.test.alice@pep-project.org>
# 6FF00E97
# 
# pEp Test Bob (test key, don't use) <pep.test.bob@pep-project.org> 
# C9C2EE39
# 
# pEp Test John (test key, don't use) <pep.test.john@pep-project.org>
# 70DCF575

# msg.asc from msg.c
# Bob sends a message to Alice and John
gpg -u C9C2EE39 -s -e -r 6FF00E97 -r 70DCF575 --armor msg

# signature.asc from t1.txt
# Bob signs the message
gpg --output signature.asc -u C9C2EE39 -sb --armor t1.txt

