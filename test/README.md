# Building the Engine Test Suite

## Caveat, before you begin

Right now, the engine tests only function on \*nix-like systems (including MacOS). (Conversion to Windows will require, at the very least, looking at some of the file-handling code.) If you want to fix this, start by looking in Engine.cc in the test/src directory!

## Requirements

In addition to the engine requirements, you will need:

* cmake
* python3

## Preparing to build

The Engine test suite now requires (at least) two additional pieces to run - **googletest** and **gtest-parallel**. You will note that I give specific instructions about where to put these, because that is what I have tried and tested. That does NOT mean other things won’t work; I simply haven’t tried them. So without further ado…

### googletest

**googletest** is an XUnit testing framework we are now using in place of cpptest. Unlike a lot of other testing frameworks, it’s recommended that you compile and link the test code directly within your project. These instructions do with with **cmake**. If you can manage it with **bazel** instead, more power to you ;)

So. To get things started.

In the directory of your choice (default, if you don’t want to change **local.conf** - specifically **GTEST\_DIR** - is the test directory (this one, presumably)):

1. git clone https://github.com/google/googletest.git
2. cd googletest
3. cmake .
4. make

(Note that this hasn’t been tested in other directories, so I am presuming the Makefile works as is, but I could be wrong)

### gtest-parallel

### Again, in the directory of your choice (if you want to use the Makefile out of the box, you should, while still in the googletest directory, do the following):

1. git clone https://github.com/google/gtest-parallel.git
2. If using a different directory, please change **GTEST\_PL\_DIR** to indicate where **gtest-parallel.py** is located.

## Building the test suite

Presuming the above works, then from the top test directory, simply run make.

# Running the Engine Test Suite

## To simply run the test suite and see what tests fail...

Do one of:

1. make test OR
2. python3 \<path to gtest-parallel.py\> ./EngineTests

## To run individual test suites, especially for debugging purposes

1. To run sequentially, IN THE SAME PROCESS: ./EngineTests --gtest_filter=TestSuiteName* (for example, for DeleteKeyTest: ./EngineTests DeleteKeyTest*) 
2. To debug the same: lldb ./EngineTests -- --gtest_filter=TestSuiteName*
3. To run sequentially IN DIFFERENT PROCESSES: (FIXME - is this really the case?) 

# Creating new tests

Script next on the agenda...

