../src/sync_fsm.c: sync.fsm gen_statemachine.ysl2
	yml2proc -y gen_statemachine.ysl2 $< -o $@

../src/sync_codec.c: sync.fsm gen_codec.ysl2
	yml2proc -y gen_codec.ysl2 $< -o $@

sync.xml: sync.fsm fsm.yml2
	yml2proc -P sync.fsm -o sync.xml

.PHONY: clean

clean:
	rm -f *.xml ../src/sync_fsm.c
