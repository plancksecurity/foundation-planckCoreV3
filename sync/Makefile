# This file is under GNU General Public License 3.0
# see LICENSE.txt

include ../default.conf

all: .codegen

.codegen: .statemachines .actions .codecs .messages
	cp -f generated/*.c generated/*.h ../src
	touch .codegen

.actions: sync.fsm gen_actions.ysl2 fsm.yml2 functions.ysl2 cond_act.yml2
	$(YML2_PROC) -y gen_actions.ysl2 $< -o $@

.statemachines: sync.fsm gen_statemachine.ysl2 fsm.yml2 functions.ysl2
	$(YML2_PROC) -y gen_statemachine.ysl2 $< -o $@

.codecs: sync.fsm gen_message_func.ysl2 fsm.yml2 functions.ysl2
	$(YML2_PROC) -y gen_message_func.ysl2 $< -o $@

.messages: sync.fsm gen_messages.ysl2 fsm.yml2 functions.ysl2
	$(YML2_PROC) -y gen_messages.ysl2 $< -o $@

.PHONY: clean

clean:
	rm -f *.xml *.xsl \
    $(pathsub generated/%, ../src/% $(wildcard generated/*.*)) \
    ../generated/* .statemachines .actions .codecs .messages *.dot *.svg

%.xml: %.fsm
	yml2c $< -o $@

%.dot: sync.fsm gen_dot.ysl2
	yml2proc -y gen_dot.ysl2 $<

%.svg: %.dot
	dot -Tsvg -o $@ $<
