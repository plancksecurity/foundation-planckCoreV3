#!/bin/bash
g++ -std=gnu++11 -pthread -fdiagnostics-color=always -I../src -I../asn.1 -I/home/krista/include -I./include -g -ggdb   -c -o $1.o $1.cc
#g++ -std=gnu++11 -pthread -fdiagnostics-color=always -I../src -I../asn.1 -I/home/krista/include -I./include -g -ggdb   -c -o TestUtils.o src/util/TestUtils.cc
g++ -std=gnu++11 -pthread -fdiagnostics-color=always -I../src -I../asn.1 -I/home/krista/include -I./include -g -ggdb   -c -o TestUtils.o TestUtils.cc
g++ -std=gnu++11 -pthread $1.o TestUtils.o  -L/home/krista/lib -L../asn.1 -L../src  -letpan -lpEpEngine -lstdc++ -lasn1 -luuid -lsqlite3 -o $1

