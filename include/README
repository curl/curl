                                  _   _ ____  _
                              ___| | | |  _ \| |
                             / __| | | | |_) | |
                            | (__| |_| |  _ <| |___
                             \___|\___/|_| \_\_____|

Include files for libcurl, external users.

They're all placed in the curl subdirectory here for better fit in any kind
of environment. You must include files from here using...

        #include <curl/curl.h>

... style and point the compiler's include path to the directory holding the
curl subdirectory. It makes it more likely to survive future modifications.

NOTE FOR LIBCURL HACKERS

* If you check out from git on a non-configure platform, you must run the
  appropriate buildconf* script to set up files before being able of compiling
  the library.

* We cannot assume anything else but very basic compiler features being
  present. While libcurl requires an ANSI C compiler to build, some of the
  earlier ANSI compilers clearly can't deal with some preprocessor operators.

* Newlines must remain unix-style for older compilers' sake.

* Comments must be written in the old-style /* unnested C-fashion */

To figure out how to do good and portable checks for features, operating
systems or specific hardwarare, a very good resource is Bjorn Reese's
collection at https://sourceforge.net/p/predef/wiki/
