                                  _   _ ____  _
                              ___| | | |  _ \| |
                             / __| | | | |_) | |
                            | (__| |_| |  _ <| |___
                             \___|\___/|_| \_\_____|

                                How To Compile with CMake

Building with CMake
==========================
   This document describes how to compile, build and install curl and libcurl
   from source code using the CMake build tool. To build with CMake, you will
   of course have to first install CMake.  The minimum required version of
   CMake is specifed in the file CMakeLists.txt found in the top of the curl
   source tree. Once the correct version of CMake is installed you can follow
   the instructions below for the platform you are building on.

   CMake builds can be configured either from the command line, or from one
   of CMake's GUI's.

Command Line CMake
==================
   A command line build of Curl is similar to the autotools build of Curl. It
   consists of the following steps after you have unpacked the source.
       # 1st create an out of source build tree parallel to the curl source
       # tree and change into that directory
       mkdir curl-build
       cd curl-build
       # now run CMake from the build tree, giving it the path to the top of
       # the Curl source tree.  CMake will pick a compiler for you. If you
       # want to specifiy the compile, you can set the CC environment
       # variable prior to running CMake.
       cmake ../curl
       make
       # currently make test and make install are not implemented
       #make test
       #make install

ccmake
=========
     CMake comes with a curses based interface called ccmake.  To run ccmake on
     a curl use the instructions for the command line cmake, but substitue
     ccmake ../curl for cmake ../curl.  This will bring up a curses interface
     with instructions on the bottom of the screen. You can press the "c" key
     to configure the project, and the "g" key to generate the project. After
     the project is generated, you can run make.

cmake-gui
=========
     CMake also comes with a Qt based GUI called cmake-gui. To configure with
     cmake-gui, you run cmake-gui and follow these steps:
        1. Fill in the "Where is the source code" combo box with the path to
        the curl source tree.
        2. Fill in the "Where to build the binaries" combo box with the path
        to the directory for your build tree, ideally this should not be the
        same as the source tree, but a parallel diretory called curl-build or
        something similar.
        3. Once the source and binary directories are specified, press the
        "Configure" button.
        4. Select the native build tool that you want to use.
        5. At this point you can change any of the options presented in the
        GUI.  Once you have selected all the options you want, click the
        "Generate" button.
        6. Run the native build tool that you used CMake to genratate.

