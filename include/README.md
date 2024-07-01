<!--
Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.

SPDX-License-Identifier: curl
-->

# include

Public include files for libcurl, external users.

They are all placed in the curl subdirectory here for better fit in any kind of
environment. You must include files from here using...

    #include <curl/curl.h>

... style and point the compiler's include path to the directory holding the
curl subdirectory. It makes it more likely to survive future modifications.

The public curl include files can be shared freely between different platforms
and different architectures.
