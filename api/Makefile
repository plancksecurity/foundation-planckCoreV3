all: basic_api.h

%.xml: %.yml2
	yml2proc -P $< -o $@

%.h: %.yml2 pEp.yml2 gen_c_header.ysl2 to_c.ysl2
	yml2proc -y gen_c_header.ysl2 pEp.yml2

.PHONY: clean

clean:
	rm -f *.xml *.h
