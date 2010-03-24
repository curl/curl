
 CMake build system and (lib)curl
 ================================

The CMake build support is experimental.

Every now and then people approach us in the project to add support for
another build system. This time, several people wanted us to add support for
CMake. So we did.

Since the introduction, however, there has been little to no maintaining of
this build concept for curl. You cannot build the same set of combinations
that you can with the autotools version of the build, and there have already
been bugs filed against the CMake build system that haven't been addressed -
due to lack of maintainers.

We keep the files included in release archives and git for now in the hope
that people will appreciate it and help us keep them in shape, and even
improve them to become on par with the main build system.

Daniel, November 2009 just before the 7.19.7 release

March 2010: The cmake build support is now completely broken and unless
someone steps forward to help improving it, we will remove the cmake build
support before the next release.
