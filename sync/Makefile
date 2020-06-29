# This file is under GNU General Public License 3.0
# see LICENSE.txt

include ../Makefile.conf

.PHONY: all clean

all: .copy

generated:
	mkdir -p $@

.actions: sync.fsm gen_actions.ysl2 fsm.yml2 functions.ysl2 $(wildcard cond_act_*.yml2) | generated
	$(YML2_PROC) -y gen_actions.ysl2 $< -o $@

.statemachines: sync.fsm gen_statemachine.ysl2 fsm.yml2 functions.ysl2 | generated
	$(YML2_PROC) -y gen_statemachine.ysl2 $< -o $@

.codecs: sync.fsm distribution.fsm gen_codec.ysl2 fsm.yml2 functions.ysl2 | generated
	$(YML2_PROC) -y gen_codec.ysl2 $< -o $@
	$(YML2_PROC) -y gen_codec.ysl2 distribution.fsm -o $@

.messages: sync.fsm distribution.fsm gen_messages.ysl2 gen_message_func.ysl2 fsm.yml2 functions.ysl2 | generated
	$(YML2_PROC) -y gen_messages.ysl2 $< -o $@
	$(YML2_PROC) -y gen_message_func.ysl2 $< -o $@
	$(YML2_PROC) -y gen_messages.ysl2 distribution.fsm -o $@

clean:
	rm -rf generated
	rm -f *.xml *.xsl .statemachines .actions .codecs .messages .copy *.dot *.svg

.copy: .actions .statemachines .codecs .messages
	cp -f generated/*.c generated/*.h ../src
	cp -f generated/*.asn1 ../asn.1
	touch .copy

%.xml: %.fsm
	yml2c $< -o $@

%.dot: sync.fsm gen_dot.ysl2
	$(YML2_PROC) -y gen_dot.ysl2 $<

%.svg: %.dot
	dot -Tsvg -o $@ $<

