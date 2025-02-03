<!--
Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.

SPDX-License-Identifier: fetch
-->

# include

Public include files for libfetch, external users.

They are all placed in the fetch subdirectory here for better fit in any kind of
environment. You must include files from here using...

    #include <fetch/fetch.h>

... style and point the compiler's include path to the directory holding the
fetch subdirectory. It makes it more likely to survive future modifications.

The public fetch include files can be shared freely between different platforms
and different architectures.
