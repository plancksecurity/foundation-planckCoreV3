include ../Makefile.conf

all: ../src/sync_fsm.c

skeleton: ../src/sync_actions.c

../src/sync_actions.c: sync.fsm gen_actions_skeleton.ysl2 fsm.yml2 functions.ysl2
	$(YML2PROC) -y gen_actions_skeleton.ysl2 $< -o $@

../src/sync_fsm.c: sync.fsm gen_statemachine.ysl2 fsm.yml2 functions.ysl2
	$(YML2PROC) -y gen_statemachine.ysl2 $< -o $@

.PHONY: clean

clean:
	rm -f *.xml *.xsl ../src/sync_fsm.*
