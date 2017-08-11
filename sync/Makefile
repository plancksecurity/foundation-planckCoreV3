# This file is under GNU General Public License 3.0
# see LICENSE.txt

include ../Makefile.conf

.PHONY: all
all: .codegen

# Currently not in use, kept for historic reasons
skeleton: .actions

.codegen: .statemachines .actions
	cp -f generated/*.* ../src
	touch $@

.actions: devicegroup.fsm gen_actions.ysl2 fsm.yml2 functions.ysl2
	$(YML2PROC) $(YML_OPTS) -y gen_actions.ysl2 $< -o $@

.statemachines: devicegroup.fsm gen_statemachine.ysl2 fsm.yml2 functions.ysl2
	$(YML2PROC) $(YML_OPTS) -y gen_statemachine.ysl2 $< -o $@

.PHONY: clean
clean:
	rm -f *.xml *.xsl *.dot *.svg \
	$(pathsub generated/%, ../src/% $(wildcard generated/*.*)) \
	../generated/* ../skeletons/* .statemachines .actions .codegen

%.xml: %.fsm
	$(YML_PATH)/yml2c $< -o $@

%.dot: gen_dot.ysl2 devicegroup.fsm
	$(YML2PROC) $(YML_OPTS) -y $^

%.svg: %.dot
	dot -Tsvg -o $@ $<
