---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: fetch_global_cleanup
Section: 3
Source: libfetch
See-also:
  - fetch_global_init (3)
  - libfetch (3)
  - libfetch-thread (3)
Protocol:
  - All
Added-in: 7.8
---

# NAME

fetch_global_cleanup - global libfetch cleanup

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

void fetch_global_cleanup(void);
~~~

# DESCRIPTION

This function releases resources acquired by fetch_global_init(3).

You should call fetch_global_cleanup(3) once for each call you make to
fetch_global_init(3), after you are done using libfetch.

This function is thread-safe since libfetch 7.84.0 if
fetch_version_info(3) has the FETCH_VERSION_THREADSAFE feature bit set
(most platforms).

If this is not thread-safe, you must not call this function when any other
thread in the program (i.e. a thread sharing the same memory) is running.
This does not just mean no other thread that is using libfetch. Because
fetch_global_cleanup(3) calls functions of other libraries that are
similarly thread unsafe, it could conflict with any other thread that uses
these other libraries.

See the description in libfetch(3) of global environment requirements for
details of how to use this function.

# CAUTION

fetch_global_cleanup(3) does not block waiting for any libfetch-created
threads to terminate (such as threads used for name resolving). If a module
containing libfetch is dynamically unloaded while libfetch-created threads are
still running then your program may crash or other corruption may occur. We
recommend you do not run libfetch from any module that may be unloaded
dynamically. This behavior may be addressed in the future.

libfetch may not be able to fully clean up after multi-threaded OpenSSL
depending on how OpenSSL was built and loaded as a library. It is possible in
some rare circumstances a memory leak could occur unless you implement your own
OpenSSL thread cleanup. Refer to libfetch-thread(3).

# %PROTOCOLS%

# EXAMPLE

~~~c
int main(void)
{
  fetch_global_init(FETCH_GLOBAL_DEFAULT);

  /* use libfetch, then before exiting... */

  fetch_global_cleanup();
}
~~~

# %AVAILABILITY%

# RETURN VALUE

None
