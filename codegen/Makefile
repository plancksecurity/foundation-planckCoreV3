# This file is under GNU General Public License 3.0
# see LICENSE.txt

include ../Makefile.conf

.PHONY: all clean

all: .copy

generated:
	mkdir -p $@

statemachines := $(patsubst %.fsm,%.fsm.gen,$(wildcard *.fsm))

actions := $(patsubst %.act,%.act.gen,$(wildcard *.act))

dot := $(patsubst %.fsm,%.dot,$(wildcard *.fsm))

%.fsm.gen: %.fsm gen_statemachine.ysl2 fsm.yml2 functions.ysl2 | generated
	$(YML2_PROC) -y gen_statemachine.ysl2 $< > /dev/null
	$(YML2_PROC) -y gen_codec.ysl2 $< > /dev/null
	$(YML2_PROC) -y gen_messages.ysl2 $< > /dev/null
	$(YML2_PROC) -y gen_message_func.ysl2 $< -o $@

%.act.gen: %.act %.fsm gen_actions.ysl2 fsm.yml2 functions.ysl2 | generated
	echo 'define actfile = "./$<";' | $(YML2_PROC) - gen_actions.ysl2 | \
		$(YML2_PROC) -X - $(subst .act,.fsm,$<) -o $@

clean:
	rm -rf generated *.gen msc
	rm -f *.xml *.xsl .copy *.dot *.svg

.copy: $(actions) $(statemachines) $(dot) $(msc)
	cp -f generated/*.c generated/*.h ../src
	cp -f generated/*.asn1 ../asn.1
	touch .copy

%.xml: %.fsm
	$(YML2_PROC) $< -o $@

svg: $(patsubst %.dot,%.svg,$(wildcard *.dot))

%.dot: %.fsm gen_dot.ysl2
	$(YML2_PROC) -y gen_dot.ysl2 $< -o $@

%.svg: %.dot
	dot -Tsvg $< -o $@ > /dev/null

msc: $(fsm) gen_msc2.ysl2
	rm -rf msc
	mkdir msc
	$(YML2_PROC) -y gen_msc2.ysl2 sync.fsm -o /dev/null
	find msc/ -iname "*.msc" -exec echo {} \; -exec mscgen -Tpng -i {} -o {}.png \;
