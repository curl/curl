                                  _   _ ____  _
                              ___| | | |  _ \| |
                             / __| | | | |_) | |
                            | (__| |_| |  _ <| |___
                             \___|\___/|_| \_\_____|

This directory is for libcurl programming examples. They are meant to show
some simple steps on how you can build your own application to take full
advantage of libcurl.

If you end up with other small but still useful example sources, please mail
them for submission in future packages and on the web site.

BUILDING

The Makefile.example is an example makefile that could be used to build these
examples. Just edit the file according to your system and requirements first.

Most examples should build fine using a command line like this:

  $ `curl-config --cc --cflags --libs` -o example example.c

Some compilers don't like having the arguments in this order but instead
want you do reorganize them like:

  $ `curl-config --cc` -o example example.c `curl-config --cflags --libs`

*PLEASE* do not use the curl.haxx.se site as a test target for your libcurl
applications/experiments. Even if some of the examples use that site as a URL
at some places, it doesn't mean that the URLs work or that we expect you to
actually torture our web site with your tests!  Thanks.

EXAMPLES

Each example source code file is designed to be and work stand-alone and
rather self-explanatory. The examples may at times lack the level of error
checks you need in a real world, but that is then only for the sake of
readability: to make the code smaller and easier to follow.
