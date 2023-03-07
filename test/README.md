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
  * `faketime`

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
  mkdir -p ~/pep-src/googletest
  git clone https://github.com/google/googletest.git ~/pep-src/googletest
  ```
  
  2. Switch into the source directory and find the subdirectory of
  `googletest` (the source distribution of googletest also contains a
  `googlemock` library which is not useful to us here)
  containing the `src` and `include` directories.  Remember this
  directory's path.  For me it is `~/pep-src/googletest/googletest` .

  3. Edit the file `CMakeLists.txt` in that directory, adding the
  following line at the top:
  ```
  set (CMAKE_CXX_STANDARD 11)
  ```
  (If you don't, it won't compile, and I will shake my fist at you.)
  
  4. Go to the googletest source directory (it should be the parent
  directory of the directory containing the file you edited) and build
  the library.

  ```
  cd ~/pep-src/googletest
  cmake CMakeLists.txt
  make
  ```
  
  5. In the lib directory of your current directory are located the
  library files you'll use (`lib/*.a`).  You may leave them there without
  installing them, if you accept running a more complex command line than
  ```
  make test
  ```
  later.  If you want to install the library, read on.

  Copy or symlink them to the library 
  location  of your choice (make sure this is a directory that can be seen 
  during the test build process - i.e. one that's in one of the library paths 
  used in building. Mine are located in `$HOME/lib`.
  See `Makefile` and `local.conf` under "Building the test suite" below -
  In this scenario, I set `GTEST_SRC_DIR` as  `<clone_path>/googletest/googletest`
  (i.e. the absolute path of where the `src` and `include` directories were 
  above - for example, `/Users/krista/googletest/googletest`).
  
### Installing `gtest-parallel`

Pick a source directory and put your `gtest-parallel` source there
(e.g. via `git clone https://github.com/google/gtest-parallel.git`):

```
mkdir -p ~/pep-src/gtest-parallel
git clone https://github.com/google/gtest-parallel.git ~/pep-src/gtest-parallel
```

This library is written in Python and does not require any actual build.

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
  
  * `GTEST_PL`: This is the full path to the *python file* for `gtest_parallel.py`
  (default presumes you cloned it under `src` in your home directory, i.e. it is
  `$(HOME)/src/gtest-parallel/gtest_parallel.py`)

The sample `local.conf` included in `../doc/build-debian.md` contains correct
definitions for these variables, assuming the user installed from sources under
`~/pep-src` as described here.

### Building

Presuming the above works and you installed every library, then from the top test
directory, simply run ``make``.

Libraries which have not been installed into the `lib` subdirectory of some
standard prefix will not be found automatically.  But this problem is easy to
circumbent by setting environment libraries (on system using the GNU
linked-loader `LD_LIBRARY_PATH` for dynamic libraries, `LIBRARY_PATH` for static
libraries).

For example, this should be sufficient to run the test suite under a debian
system following the instruction at `../doc/build-debian.md`:
```
cd ~/pep-src/pep-engine
LIBRARY_PATH=$LIBRARY_PATH:$HOME/pep-src/googletest/lib LD_LIBRARY_PATH=$LD_LIBRARY_PATH:$HOME/pep-src/pep-engine/src:$HOME/pep-src/sequoia/target/release:$HOME/pep-src/libetpan/build/lib make test
```

Such variable definitions may be prepended to the command lines below for running
individual tests or the entire test suite.

In case of test failures remember to build the database, on which the test suite
depends, and to copy it into the system directory:
```
make dbinstall
```
The database does not need to be rebuilt and reinstalled for every test suite
run: running the `dbinstall` target once suffices.


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
  ./EngineTests DeleteKeyTest*
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
  ./EngineTests DeleteKeyTest.check_delete_single_pubkey
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

Script next on the agenda...

# Known Problems

The normal run of the tests in parallel eats output. Try running the individual test case as above if you need to see a test case's output.

