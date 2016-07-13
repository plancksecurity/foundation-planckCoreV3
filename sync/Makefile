include ../Makefile.conf

all: .statemachines

skeleton: .skeletons

.skeletons: devicegroup.fsm gen_actions_skeleton.ysl2 fsm.yml2 functions.ysl2
	$(YML2PROC) -y gen_actions_skeleton.ysl2 $< -o $@

.statemachines: devicegroup.fsm gen_statemachine.ysl2 fsm.yml2 functions.ysl2
	$(YML2PROC) -y gen_statemachine.ysl2 $< -o $@

.PHONY: clean

clean:
	rm -f *.xml *.xsl ../src/sync_fsm.* ../src/*.skeleton .statemachines .skeletons
