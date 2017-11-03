# Copyright 2017, pEp Foundation
# This file is part of pEpEngine
# This file may be used under the terms of the GNU General Public License version 3
# see LICENSE.txt

include ../default.conf

.PHONY: all
all: .codegen

# Currently not in use, kept for historic reasons
skeleton: .actions

.codegen: .statemachines .actions
	cp -f generated/*.* ../src
	touch $@

.actions: devicegroup.fsm gen_actions.ysl2 fsm.yml2 functions.ysl2
	$(YML2_PROC) $(YML2_OPTS) -y gen_actions.ysl2 $< -o $@

.statemachines: devicegroup.fsm gen_statemachine.ysl2 fsm.yml2 functions.ysl2
	$(YML2_PROC) $(YML2_OPTS) -y gen_statemachine.ysl2 $< -o $@

.PHONY: clean
clean:
	rm -f *.xml *.xsl *.dot *.svg \
	$(patsubst generated/%,../src/%,$(wildcard generated/*.*)) \
	../generated/* ../skeletons/* .statemachines .actions .codegen \
	generated/Makefile.protocols

%.xml: %.fsm
	$(YML2_PATH)/yml2c $< -o $@

%.dot: gen_dot.ysl2 devicegroup.fsm
	$(YML2_PROC) $(YML2_OPTS) -y $^

%.svg: %.dot
	dot -Tsvg -o $@ $<
