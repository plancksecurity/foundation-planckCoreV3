# Building and Running the Tests for the p≡p Engine

Work in progress.

## Caveat, before you begin

Right now, the engine tests only function on \*nix-like systems (including
MacOS).

*(Conversion to Windows will require, at the very least, looking at some of the
file-handling code. If you want to fix this, start by looking in Engine.cc
in the test/src directory!)*

## Requirements

In addition to the engine requirements, you will need:

  * `cmake`
  * `python3`
  * `git` (for getting the `gtest-parallel` repository, unless you grab the
  tarball from somewhere)

## Building the prerequisites

The Engine test suite now requires (at least) two additional pieces to run:
  * `googletest`
  * `gtest-parallel`

How this proceeds depends on your platform and whether or not you use a packaged
distribution.

These instructions do this with `cmake`. If you can manage it with `bazel`
instead, more power to you ;)

### Installing `googletest`

#### Packaged distributions

This is the currently preferred way to do this, because everyone was doing it
anyway and who am I to judge?

##### Debian and Ubuntu (and derivatives)

Thanks to Erik Smistad for this starting point (condensed from [Getting Started
with Google Test On
Ubuntu](https://www.eriksmistad.no/getting-started-with-google-test-on-ubuntu/)):

  1. Install the packages `cmake` and `libgtest-dev` from the repository. This
  will install the gtest source files to `/usr/src/gtest`. You'll still need to
  compile the code and link the library files to be able to use them.

  2. Compile the source files:
  ```
  cd /usr/src/gtest
  sudo cmake CMakeLists.txt
  sudo make
  ```

  3. Copy/symlink the libraries to the library location of your choice (here,
  it's `/usr/lib`, hence the `sudo`, but as long as it's in your library path,
  it shouldn't matter where you stick it):
  ```
  sudo cp *.a /usr/lib
  ```

##### MacOS

  1. Install package `gtest` from Macports
  
  2. Macports will build the libraries for you.
  
  3. In the next major section ("Building the Test Suite"), under 
  "Makefile and local.conf", set `GTEST_SRC_DIR` to 
  `/opt/local/src/googletest` in `local.conf` (see instructions below)
  
  4. Make sure `/opt/local/lib` is in your library path when compiling and 
  linking the tests.

#### Downloading and compiling the source yourself

  1. Get the source, Fred. (Luke is tired of the source, I hear.)
  ```
  git clone https://github.com/google/googletest.git
  ```
  
  2. Switch into the source directory and find the directory 
  containing the `src` and `include` directories. Mark this directory
  for later. (For me, this is `./googletest/googletest`)
  
  3. Edit `CMakeLists.txt` here to contain the following line at the top:
  ```
  set (CMAKE_CXX_STANDARD 11)
  ```
  (If you don't, it won't compile, and I will shake my fist at you.)
  
  4. Execute, in this directory:
  ```
  cmake CMakeLists.txt
  make
  ```
  
  5. In the lib directory of your current directory are located the
  library files you'll use (`lib/*.a`). Copy or symlink them to the library 
  location  of your choice (make sure this is a directory that can be seen 
  during the test build process - i.e. one that's in one of the library paths 
  used in building. Mine are located in `$HOME/lib`.

  6. See `Makefile` and `local.conf` under "Building the test suite" below -
  In this scenario, I set `GTEST_SRC_DIR` as  `<clone_path>/googletest/googletest`
  (i.e. the absolute path of where the `src` and `include` directories were 
  above - for me, `/Users/krista/googletest/googletest`).
  
### Installing `gtest-parallel`

Pick a source directory and put your `gtest-parallel` source there
(e.g. via `git clone https://github.com/google/gtest-parallel.git`).

We'll deal more with this when preparing to compile the test suite.

## Building the test suite

### `Makefile` and `local.conf`

So `local.conf` in the top-level engine directory is where we stick all of the
Makefile overrides. The test Makefile contains some defaults for relevant
variables here, but if you need to override them, please either create or modify
`local.conf` in the top-level engine directory as needed. The relevant variables
are:

  * `GTEST_SRC_DIR`: This is the directory where you compiled googletest above
  (defaults to `/usr/src/gtest`)
  
  * `GTEST_INC_DIR`: This is where the include files for googletest are located
  (defaults to `$(GTEST_SRC_DIR)/include`)
  
  * `GTEST_PL`: This is the full path to the *python file* for `gtest_parallel`
  (default presumes you cloned it under `src` in your home directory, i.e. it is
  `$(HOME)/src/gtest-parallel/gtest_parallel.py`)

### Building

Presuming the above works, then from the top test directory, simply run make.

## Running the test suite

### To simply run the test suite and see what tests fail...

Do one of:

  1. `make test` OR
  
  2. `python3 <path to gtest-parallel.py> ./EngineTests`

### To run individual test suites, especially for debugging purposes

Note that for some test suites, this will, if something goes dreadfully wrong,
mean that one test's failure may pollute another test. This generally means you
have found a dastardly bug in the engine, but it can also be a test issue.

*Caveat lector*.

  1. To run sequentially, *in the same process*:
  ```
  ./EngineTests --gtest_filter=TestSuiteName*
  ```
  For example, for `DeleteKeyTest`:
  ```
  ./EngineTests --gtest_filter="DeleteKeyTest*"
  ```

  2. To debug the same with lldb:
  ```
  lldb ./EngineTests -- --gtest_filter=TestSuiteName*
  ```
  3. To debug with gdb:
  ```
  gdb --args ./EngineTests --gtest_filter=TestSuiteName*
  ```

### To run and/or debug individual test cases   
  1. To run:
  ```
  ./EngineTests --gtest_filter=TestSuiteName.test_function_name
  ```
  For example, for `check_delete_single_pubkey` in `DeleteKeyTest`:
  ```
  ./EngineTests --gtest_filter="DeleteKeyTest.check_delete_single_pubkey"
  ```

  2. To debug the same with lldb:
  ```
  lldb ./EngineTests -- --gtest_filter=TestSuiteName.test_function_name
  ```

  3. To debug with gdb:
  ```
  gdb --args ./EngineTests --gtest_filter=TestSuiteName.test_function_name
  ```

N.B. The gtest_filter can be globbed and will run all matching tests; if you
want to run every test in a test suite, be sure to use TestSuiteName*.

(Different shells will require different quoting styles for this - YMMV.)

When debugging a failing test, use '--gtest_break_on_failure' to have
gtest automatically break into the debugger where the assertion fails.

### Output

Compile tests with -DDEBUG_OUTPUT to (possibly) see output to cout. May only work
in the tests run directly from ./EngineTests (with or without filter)

# Creating new tests

## Background, Engine.h/cc

In test/src there is an Engine.h/cc, which represents an instance of the engine for the test suite. It’s called automatically in every (generated) test (script) during the initialization phase of the setup. No direct interaction with the file is required.

Engine.h has a ‘Session’ associated with it.

Most engine calls take a session. The test instance that is initiated in the test suite during the setup both sets this session up and makes it available to all tests under the variable “session”.

We test with one Session thread in the test suite. 

start() initiates the engine environment (home directories etc) and the engine/session itself, and shut_down() shuts them down.

Internally they call the init() and release() engine functions.

## Genrating a test shell

In the test directory there is a script called gen_test_skel.py It takes an argument which is the test name.

    python3 ./gen_test_skel.py KeyManipulationTest 

will create KeyManipulationTest.cc in the test/src directory

## Tests

The constructor is mostly just test-internal information and some stuff to send to the initialization function to set up separate test directories for each test.

When we look at the generated text at the bottom of the file we have test fixtures, and they are where the actual test code is run.

    TEST_F(KeyManipulationTest, check_key_manipulation) { // This is just a dummy test case. The convention is check_whatever_you_are_checking // so for multiple test cases in a suite, be more explicit ;)

Each test case within a suite of tests look like this. So if I’ve got a group of key manipulation tests, and my classname is KeyManipultionTest, I’d have a bunch of stuff like this:

    TEST_F(KeyManipulationTest, check_key_manipulation_generate_keypair) { // test stuff here }
    TEST_F(KeyManipulationTest, check_key_manipulation_delete_keypair) { // test stuff here }
    TEST_F(KeyManipulationTest, check_key_manipulation_import_key) { // test stuff here }

SetUp() and TearDown(), along with the constructor, are called anew for every test fixture in the suite SetUp() is run before the test, and is supposed to set up the whole environment before each test is run. TearDown() is run afterwards and should release any resources allocated in the setup.

In most cases it’s not necessary to change them.

SetUp() calls engine->start(), which initializes the engine and engine session. TearDown calls engine->shutdown(), which finalizes engine stuff and calls release() on the engine session

## Setup

    std::vector<std::pair<std::string, std::string>> init_files = std::vector<std::pair<std::string, std::string>>();

Above is a vector of filename pairs. It is used to copy an existing management or key database into the home directory for the test case before the engine starts.

When needed it is used like this: init_files.push_back(std::pair(std::string(“test_files/Engine709_3/keys.db”), std::string(“keys.db”))); or init_files.push_back(std::pair(std::string(“test_files/Engine709_3/pep_mgmt.db”), std::string(“management.db”)));

The first argument is always the name/path of the file you want copied in. The second is just the filename the engine will expect in its home directory. Afterwards, the script takes care of it itself.

After all of this is in order, SetUp calls:

    engine->prep(NULL, NULL, init_files); 

The “init_files” argument is the vector of pairs from above. The first two arguments are callbacks for the engine - one is for sync, and one is for message sending. They are not actually used at the moment.

So with everything in that shell right now, without doing anything, you have the capacity to setup, start, and shutdown the engine before and after each test without worrying about anything. By the time you start the test case, you have a running, blank system with an empty database and keyring, ready to go.

## Test home

There is a directory that gets made called 'pEp_test_home' in the test directory. For each test, a new directory is created - so here, there would be, for the text fixture, pEp_test_home/KeyManipulationTest/check_key_manipulation and in that directory, which is set as the home for that test, there will be a .pEp directory with a keys.db and management.db so if you ever need to step through with gdb/lldb, you can always pause debugging and use sqlite3 to see the state of the relevant database which is often super useful.

These DBs get cleaned up after the tests, so if you need to capture them before shutting down a test for some reason, you need to break before the engine shuts down and copy them out.

# Known Problems

The normal run of the tests in parallel eats output. Try running the individual test case as above if you need to see a test case's output.

