---
c: Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
SPDX-License-Identifier: fetch
Title: fetch_formadd
Section: 3
Source: libfetch
See-also:
  - fetch_easy_setopt (3)
  - fetch_formfree (3)
  - fetch_mime_init (3)
Protocol:
  - HTTP
Added-in: 7.1
---

# NAME

fetch_formadd - add a section to a multipart form POST

# SYNOPSIS

~~~c
#include <fetch/fetch.h>

FETCHFORMcode fetch_formadd(struct fetch_httppost **firstitem,
                          struct fetch_httppost **lastitem, ...);
~~~

# DESCRIPTION

**This function is deprecated.** Use fetch_mime_init(3) instead.

fetch_formadd() is used to append sections when building a multipart form
post. Append one section at a time until you have added all the sections you
want included and then you pass the *firstitem* pointer as parameter to
FETCHOPT_HTTPPOST(3). *lastitem* is set after each fetch_formadd(3) call and
on repeated invokes it should be left as set to allow repeated invokes to find
the end of the list faster.

After the *lastitem* pointer follow the real arguments.

The pointers *firstitem* and *lastitem* should both be pointing to
NULL in the first call to this function. All list-data is allocated by the
function itself. You must call fetch_formfree(3) on the *firstitem*
after the form post has been done to free the resources.

Using POST with HTTP 1.1 implies the use of a "Expect: 100-continue" header.
You can disable this header with FETCHOPT_HTTPHEADER(3) as usual.

First, there are some basics you need to understand about multipart form
posts. Each part consists of at least a NAME and a CONTENTS part. If the part
is made for file upload, there are also a stored CONTENT-TYPE and a FILENAME.
Below, we discuss what options you use to set these properties in the parts
you want to add to your post.

The options listed first are for making normal parts. The options from
*FETCHFORM_FILE* through *FETCHFORM_BUFFERLENGTH* are for file upload
parts.

# OPTIONS

## FETCHFORM_COPYNAME

followed by a string which provides the *name* of this part. libfetch
copies the string so your application does not need to keep it around after
this function call. If the name is not null-terminated, you must set its
length with **FETCHFORM_NAMELENGTH**. The *name* is not allowed to
contain zero-valued bytes. The copied data is freed by fetch_formfree(3).

## FETCHFORM_PTRNAME

followed by a string which provides the *name* of this part. libfetch uses the
pointer and refer to the data in your application, so you must make sure it
remains until fetch no longer needs it. If the name is not null-terminated, you
must set its length with **FETCHFORM_NAMELENGTH**. The *name* is not allowed to
contain zero-valued bytes.

## FETCHFORM_COPYCONTENTS

followed by a pointer to the contents of this part, the actual data to send
away. libfetch copies the provided data, so your application does not need to
keep it around after this function call. If the data is not null terminated,
or if you would like it to contain zero bytes, you must set the length of the
name with **FETCHFORM_CONTENTSLENGTH**. The copied data is freed by
fetch_formfree(3).

## FETCHFORM_PTRCONTENTS

followed by a pointer to the contents of this part, the actual data to send
away. libfetch uses the pointer and refer to the data in your application, so
you must make sure it remains until fetch no longer needs it. If the data is
not null-terminated, or if you would like it to contain zero bytes, you must
set its length with **FETCHFORM_CONTENTSLENGTH**.

## FETCHFORM_CONTENTLEN

followed by a fetch_off_t value giving the length of the contents. Note that
for *FETCHFORM_STREAM* contents, this option is mandatory.

If you pass a 0 (zero) for this option, libfetch calls strlen() on the contents
to figure out the size. If you really want to send a zero byte content then
you must make sure strlen() on the data pointer returns zero.

(Option added in 7.46.0)

## FETCHFORM_CONTENTSLENGTH

(This option is deprecated. Use *FETCHFORM_CONTENTLEN* instead.)

followed by a long giving the length of the contents. Note that for
*FETCHFORM_STREAM* contents, this option is mandatory.

If you pass a 0 (zero) for this option, libfetch calls strlen() on the contents
to figure out the size. If you really want to send a zero byte content then
you must make sure strlen() on the data pointer returns zero.

## FETCHFORM_FILECONTENT

followed by a filename, causes that file to be read and its contents used
as data in this part. This part does *not* automatically become a file
upload part simply because its data was read from a file.

The specified file needs to kept around until the associated transfer is done.

## FETCHFORM_FILE

followed by a filename, makes this part a file upload part. It sets the
*filename* field to the basename of the provided filename, it reads the
contents of the file and passes them as data and sets the content-type if the
given file match one of the internally known file extensions. For
**FETCHFORM_FILE** the user may send one or more files in one part by
providing multiple **FETCHFORM_FILE** arguments each followed by the filename
(and each *FETCHFORM_FILE* is allowed to have a
*FETCHFORM_CONTENTTYPE*).

The given upload file has to exist in its full in the file system already when
the upload starts, as libfetch needs to read the correct file size beforehand.

The specified file needs to kept around until the associated transfer is done.

## FETCHFORM_CONTENTTYPE

is used in combination with *FETCHFORM_FILE*. Followed by a pointer to a
string which provides the content-type for this part, possibly instead of an
internally chosen one.

## FETCHFORM_FILENAME

is used in combination with *FETCHFORM_FILE*. Followed by a pointer to a
string, it tells libfetch to use the given string as the *filename* in the file
upload part instead of the actual filename.

## FETCHFORM_BUFFER

is used for custom file upload parts without use of *FETCHFORM_FILE*. It
tells libfetch that the file contents are already present in a buffer. The
parameter is a string which provides the *filename* field in the content
header.

## FETCHFORM_BUFFERPTR

is used in combination with *FETCHFORM_BUFFER*. The parameter is a pointer
to the buffer to be uploaded. This buffer must not be freed until after
fetch_easy_cleanup(3) is called. You must also use
*FETCHFORM_BUFFERLENGTH* to set the number of bytes in the buffer.

## FETCHFORM_BUFFERLENGTH

is used in combination with *FETCHFORM_BUFFER*. The parameter is a
long which gives the length of the buffer.

## FETCHFORM_STREAM

Tells libfetch to use the FETCHOPT_READFUNCTION(3) callback to get
data. The parameter you pass to *FETCHFORM_STREAM* is the pointer passed on
to the read callback's fourth argument. If you want the part to look like a
file upload one, set the *FETCHFORM_FILENAME* parameter as well. Note that
when using *FETCHFORM_STREAM*, *FETCHFORM_CONTENTSLENGTH* must also be
set with the total expected length of the part unless the formpost is sent
chunked encoded. (Option added in libfetch 7.18.2)

## FETCHFORM_ARRAY

Another possibility to send options to fetch_formadd() is the
**FETCHFORM_ARRAY** option, that passes a struct fetch_forms array pointer as
its value. Each fetch_forms structure element has a *FETCHformoption* and a
char pointer. The final element in the array must be a FETCHFORM_END. All
available options can be used in an array, except the FETCHFORM_ARRAY option
itself. The last argument in such an array must always be **FETCHFORM_END**.

## FETCHFORM_CONTENTHEADER

specifies extra headers for the form POST section. This takes a fetch_slist
prepared in the usual way using **fetch_slist_append** and appends the list
of headers to those libfetch automatically generates. The list must exist while
the POST occurs, if you free it before the post completes you may experience
problems.

When you have passed the *struct fetch_httppost* pointer to
fetch_easy_setopt(3) (using the FETCHOPT_HTTPPOST(3) option), you
must not free the list until after you have called fetch_easy_cleanup(3)
for the fetch handle.

See example below.

# %PROTOCOLS%

# EXAMPLE

~~~c
#include <string.h> /* for strlen */

static const char record[]="data in a buffer";

int main(void)
{
  FETCH *fetch = fetch_easy_init();
  if(fetch) {
    struct fetch_httppost *post = NULL;
    struct fetch_httppost *last = NULL;
    char namebuffer[] = "name buffer";
    long namelength = strlen(namebuffer);
    char buffer[] = "test buffer";
    char htmlbuffer[] = "<HTML>test buffer</HTML>";
    long htmlbufferlength = strlen(htmlbuffer);
    struct fetch_forms forms[3];
    char file1[] = "my-face.jpg";
    char file2[] = "your-face.jpg";
    /* add null character into htmlbuffer, to demonstrate that
       transfers of buffers containing null characters actually work
    */
    htmlbuffer[8] = '\0';

    /* Add simple name/content section */
    fetch_formadd(&post, &last, FETCHFORM_COPYNAME, "name",
                 FETCHFORM_COPYCONTENTS, "content", FETCHFORM_END);

    /* Add simple name/content/contenttype section */
    fetch_formadd(&post, &last, FETCHFORM_COPYNAME, "htmlcode",
                 FETCHFORM_COPYCONTENTS, "<HTML></HTML>",
                 FETCHFORM_CONTENTTYPE, "text/html", FETCHFORM_END);

    /* Add name/ptrcontent section */
    fetch_formadd(&post, &last, FETCHFORM_COPYNAME, "name_for_ptrcontent",
                 FETCHFORM_PTRCONTENTS, buffer, FETCHFORM_END);

    /* Add ptrname/ptrcontent section */
    fetch_formadd(&post, &last, FETCHFORM_PTRNAME, namebuffer,
                 FETCHFORM_PTRCONTENTS, buffer, FETCHFORM_NAMELENGTH,
                 namelength, FETCHFORM_END);

    /* Add name/ptrcontent/contenttype section */
    fetch_formadd(&post, &last, FETCHFORM_COPYNAME, "html_code_with_hole",
                 FETCHFORM_PTRCONTENTS, htmlbuffer,
                 FETCHFORM_CONTENTSLENGTH, htmlbufferlength,
                 FETCHFORM_CONTENTTYPE, "text/html", FETCHFORM_END);

    /* Add simple file section */
    fetch_formadd(&post, &last, FETCHFORM_COPYNAME, "picture",
                 FETCHFORM_FILE, "my-face.jpg", FETCHFORM_END);

    /* Add file/contenttype section */
    fetch_formadd(&post, &last, FETCHFORM_COPYNAME, "picture",
                 FETCHFORM_FILE, "my-face.jpg",
                 FETCHFORM_CONTENTTYPE, "image/jpeg", FETCHFORM_END);

    /* Add two file section */
    fetch_formadd(&post, &last, FETCHFORM_COPYNAME, "pictures",
                 FETCHFORM_FILE, "my-face.jpg",
                 FETCHFORM_FILE, "your-face.jpg", FETCHFORM_END);

    /* Add two file section using FETCHFORM_ARRAY */
    forms[0].option = FETCHFORM_FILE;
    forms[0].value  = file1;
    forms[1].option = FETCHFORM_FILE;
    forms[1].value  = file2;
    forms[2].option  = FETCHFORM_END;

    /* Add a buffer to upload */
    fetch_formadd(&post, &last,
                 FETCHFORM_COPYNAME, "name",
                 FETCHFORM_BUFFER, "data",
                 FETCHFORM_BUFFERPTR, record,
                 FETCHFORM_BUFFERLENGTH, sizeof(record),
                 FETCHFORM_END);

    /* no option needed for the end marker */
    fetch_formadd(&post, &last, FETCHFORM_COPYNAME, "pictures",
                 FETCHFORM_ARRAY, forms, FETCHFORM_END);
    /* Add the content of a file as a normal post text value */
    fetch_formadd(&post, &last, FETCHFORM_COPYNAME, "filecontent",
                 FETCHFORM_FILECONTENT, ".bashrc", FETCHFORM_END);
    /* Set the form info */
    fetch_easy_setopt(fetch, FETCHOPT_HTTPPOST, post);

    fetch_easy_perform(fetch);

    fetch_easy_cleanup(fetch);

    fetch_formfree(post);
  }
}
~~~

# DEPRECATED

Deprecated in 7.56.0. Before this release, field names were allowed to contain
zero-valued bytes. The pseudo-filename "-" to read stdin is discouraged
although still supported, but data is not read before being actually sent: the
effective data size can then not be automatically determined, resulting in a
chunked encoding transfer. Backslashes and double quotes in field and
filenames are now escaped before transmission.

# %AVAILABILITY%

# RETURN VALUE

0 means everything was OK, non-zero means an error occurred corresponding to a
FETCH_FORMADD_* constant defined in *\<fetch/fetch.h\>*.
