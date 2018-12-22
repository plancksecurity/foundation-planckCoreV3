# This file is under GNU General Public License 3.0
# see LICENSE.txt

include ../Makefile.conf

all: .codegen

.codegen: .statemachines .actions .codecs .messages
	-mkdir -p generated
	touch .codegen
	$(MAKE) copy

.actions: sync.fsm gen_actions.ysl2 fsm.yml2 functions.ysl2 $(wildcard cond_act_*.yml2)
	$(YML2_PROC) -y gen_actions.ysl2 $< -o $@

.statemachines: sync.fsm gen_statemachine.ysl2 fsm.yml2 functions.ysl2
	$(YML2_PROC) -y gen_statemachine.ysl2 $< -o $@

.codecs: sync.fsm gen_codec.ysl2 fsm.yml2 functions.ysl2
	$(YML2_PROC) -y gen_codec.ysl2 $< -o $@

.messages: sync.fsm gen_messages.ysl2 gen_message_func.ysl2 fsm.yml2 functions.ysl2
	$(YML2_PROC) -y gen_messages.ysl2 $< -o $@
	$(YML2_PROC) -y gen_message_func.ysl2 $< -o $@

.PHONY: clean copy

clean:
	rm -f *.xml *.xsl generated/* .statemachines .actions .codecs .messages .codegen *.dot *.svg

copy:
	cp -f generated/*.c generated/*.h ../src

%.xml: %.fsm
	yml2c $< -o $@

%.dot: sync.fsm gen_dot.ysl2
	yml2proc -y gen_dot.ysl2 $<

%.svg: %.dot
	dot -Tsvg -o $@ $<
