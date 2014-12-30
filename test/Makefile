include ../Makefile.conf

ifeq ($(BUILD_FOR),Windoze)
CXX=i686-w64-mingw32-g++
LD=i686-w64-mingw32-c++
LDFLAGS=-lstdc++
else ifeq ($(BUILD_FOR),MINGW32_NT-6.1)
CXX=g++ -std=gnu++11 -DWIN32
LD=g++
LDFLAGS=-pthread -L../src -lpEpEngine -lstdc++
else
CC=g++ -std=gnu++11
CXX=g++ -std=gnu++11
LD=g++
LDFLAGS=-L$(HOME)/lib -pthread -lpEpEngine -lstdc++
endif
CXXFLAGS=-g -O0 -I../src
# CXXFLAGS=-O3 -DNDEBUG

TARGET=pEpEngineTest

ifeq ($(BUILD_FOR),Windoze)
all: $(TARGET).exe

$(TARGET).exe: $(TARGET).o ../src/libpEpEngine.a
	$(CXX) $(LDFLAGS) -o $(TARGET).exe $(TARGET).o ../src/libpEpEngine.a
else ifeq ($(BUILD_FOR),MINGW32_NT-6.1)
all: $(TARGET).exe pEpEngine.dll

$(TARGET).exe: $(TARGET).o ../src/libpEpEngine.a
	$(CXX) $(LDFLAGS) -o $(TARGET).exe $(TARGET).o ../src/libpEpEngine.a
else
all: $(TARGET)

$(TARGET): $(TARGET).o
	$(CXX) $(LDFLAGS) -o $(TARGET) $(TARGET).o
endif

%.o: %.cc ../pEpEngine.h
	$(CXX) $(CXXFLAGS) -c -o $@ $<

pEpEngine.dll: ../src/pEpEngine.dll
	cp $< $@

.PHONY: clean

clean:
	rm -f *.o $(TARGET) *.exe *.a *~ pEpEngine.dll message_api_test

test: all
	LD_LIBRARY_PATH=~/lib:../src ./pEpEngineTest

message_api_test: message_api_test.o
	$(CXX) $(LDFLAGS) -o message_api_test message_api_test.o

