
# This file is under GNU General Public License 3.0
# see LICENSE.txt

include ../Makefile.conf

all: .codegen

skeleton: .actions

.codegen: .statemachines .actions
	cp -f generated/*.* ../src
	touch .codegen

.actions: devicegroup.fsm gen_actions.ysl2 fsm.yml2 functions.ysl2
	$(YML2PROC) $(YML_OPTS) -y gen_actions.ysl2 $< -o $@

.statemachines: devicegroup.fsm gen_statemachine.ysl2 fsm.yml2 functions.ysl2
	$(YML2PROC) $(YML_OPTS) -y gen_statemachine.ysl2 $< -o $@

.PHONY: clean

clean:
	rm -f *.xml *.xsl \
    $(pathsub generated/%, ../src/% $(wildcard generated/*.*)) \
    ../generated/* ../skeletons/* .statemachines .actions *.dot *.svg

%.xml: %.fsm
	yml2c $< -o $@

%.dot: devicegroup.fsm gen_dot.ysl2
	$(YML2PROC) $(YML_OPTS) -y gen_dot.ysl2 $<

%.svg: %.dot
	dot -Tsvg -o $@ $<
