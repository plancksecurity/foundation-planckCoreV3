# Instructions and caveats for using pEpMIME as the built-in engine parser

## Makefile variables and local.conf

We copy the necessary files from the user's *separate* libpEpMIME repository
on the machine. 

**Note: The Makefile in this directory is *different* from the libpEpMIME Makefile.**
**DO NOT REPLACE THE pEpEngine's pEpMIME Makefile with the one from the libpEpMIME repository. It won't work!**

Source files in this directory are local copies only and will be copied over if the repository is
updated. We post-process the source to change the "installed-header" requirements of the "separate"
(quotes intentional) library.

* PEP_MIME=1
* PEP_MIME_SRC=<your checked-out libpEpMIME repo's src directory>

## Known issues
On MacOS, the built-in standard BSD C library provides strlcat et al. **However**, for some weird reason, when
compiling the engine with pEpMIME, the compiler thinks strlcat is no longer defined, though everything links and runs
in the end. 

If you see something like:

```
platform_unix.c:280:5: warning: implicitly declaring library function 'strlcat' with type 'unsigned long (char *, const char *, unsigned long)' [-Wimplicit-function-declaration]
    strlcat(*first, second, size);
    ^
platform_unix.c:280:5: note: include the header <string.h> or explicitly provide a declaration for 'strlcat'
1 warning generated.
```

It doesn't seem to be an actual issue, and maybe it's a problem of compiling part of the engine with clang and part of it with clang++ and c++14, but anyway, watch out for it, and
don't complain to the engine team unless you figure out how to fix it ;)

## TODO

* git submodules would be a good way to handle our "copy this in because it really isn't a separate library" issue
