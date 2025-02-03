---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: fetch_ws_meta
Section: 3
Source: libfetch
See-also:
  - fetch_easy_getinfo (3)
  - fetch_easy_setopt (3)
  - fetch_ws_recv (3)
  - fetch_ws_send (3)
  - libfetch-ws (3)
Protocol:
  - WS
Added-in: 7.86.0
---

# NAME

fetch_ws_meta - meta data WebSocket information

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

const struct fetch_ws_frame *fetch_ws_meta(FETCH *fetch);
~~~

# DESCRIPTION

When the write callback (FETCHOPT_WRITEFUNCTION(3)) is invoked on
received WebSocket traffic, fetch_ws_meta(3) can be called from within
the callback to provide additional information about the current frame.

This function only works from within the callback, and only when receiving
WebSocket data.

This function requires an easy handle as input argument for libfetch to know
what transfer the question is about, but as there is no such pointer provided
to the callback by libfetch itself, applications that want to use
fetch_ws_meta(3) need to pass it on to the callback on its own.

# struct fetch_ws_frame

~~~c
struct fetch_ws_frame {
  int age;
  int flags;
  fetch_off_t offset;
  fetch_off_t bytesleft;
};
~~~

## `age`

This field specify the age of this struct. It is always zero for now.

## `flags`

This is a bitmask with individual bits set that describes the WebSocket data.
See the list below.

## `offset`

When this frame is a continuation of fragment data already delivered, this is
the offset into the final fragment where this piece belongs.

## `bytesleft`

If this is not a complete fragment, the *bytesleft* field informs about how
many additional bytes are expected to arrive before this fragment is complete.

# FLAGS

## FETCHWS_TEXT

The buffer contains text data. Note that this makes a difference to WebSocket
but libfetch itself does not make any verification of the content or
precautions that you actually receive valid UTF-8 content.

## FETCHWS_BINARY

This is binary data.

## FETCHWS_CONT

This is not the final fragment of the message, it implies that there is
another fragment coming as part of the same message.

## FETCHWS_CLOSE

This transfer is now closed.

## FETCHWS_PING

This as an incoming ping message, that expects a pong response.

# %PROTOCOLS%

# EXAMPLE

~~~c

/* we pass a pointer to this struct to the callback */
struct customdata {
  FETCH *easy;
  void *ptr;
};

static size_t writecb(unsigned char *buffer,
                      size_t size, size_t nitems, void *p)
{
  struct customdata *c = (struct customdata *)p;
  const struct fetch_ws_frame *m = fetch_ws_meta(c->easy);

  printf("flags: %x\n", m->flags);
}

int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    struct customdata custom;
    custom.easy = fetch;
    custom.ptr = NULL;
    fetch_easy_setopt(fetch, FETCHOPT_WRITEFUNCTION, writecb);
    fetch_easy_setopt(fetch, FETCHOPT_WRITEDATA, &custom);

    fetch_easy_perform(fetch);

  }
}
~~~

# %AVAILABILITY%

# RETURN VALUE

This function returns a pointer to a *fetch_ws_frame* struct with read-only
information that is valid for this specific callback invocation. If it cannot
return this information, or if the function is called in the wrong context, it
returns NULL.
