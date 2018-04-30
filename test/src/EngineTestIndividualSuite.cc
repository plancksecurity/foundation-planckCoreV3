#include <stdlib.h>
#include <unistd.h>
#include <ftw.h>

#include "EngineTest.h"
using namespace std;

void EngineTestIndividualSuite::setup() {
    set_full_env(); // This will be called by default before every test
}

void EngineTestIndividualSuite::tear_down() {
    cout << "calling release()\n";
    release(session);
    restore_full_env();
}
