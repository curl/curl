/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2010, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at http://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/

/*
  Debug the form generator stand-alone by compiling this source file with:

  gcc -DHAVE_CONFIG_H -I../ -g -D_FORM_DEBUG -DCURLDEBUG -o formdata \
    -I../include formdata.c strequal.c memdebug.c mprintf.c strerror.c

  (depending on circumstances you may need further externals added)

  run the 'formdata' executable the output should end with:
  All Tests seem to have worked ...
  and the following parts should be there:

Content-Disposition: form-data; name="simple_COPYCONTENTS"
value for simple COPYCONTENTS

Content-Disposition: form-data; name="COPYCONTENTS_+_CONTENTTYPE"
Content-Type: image/gif
value for COPYCONTENTS + CONTENTTYPE

Content-Disposition: form-data; name="PRNAME_+_NAMELENGTH_+_COPYNAME_+_CONTENTSLENGTH"
vlue for PTRNAME + NAMELENGTH + COPYNAME + CONTENTSLENGTH
(or you might see P^@RNAME and v^@lue at the start)

Content-Disposition: form-data; name="simple_PTRCONTENTS"
value for simple PTRCONTENTS

Content-Disposition: form-data; name="PTRCONTENTS_+_CONTENTSLENGTH"
vlue for PTRCONTENTS + CONTENTSLENGTH
(or you might see v^@lue at the start)

Content-Disposition: form-data; name="PTRCONTENTS_+_CONTENTSLENGTH_+_CONTENTTYPE"
Content-Type: application/octet-stream
vlue for PTRCONTENTS + CONTENTSLENGTH + CONTENTTYPE
(or you might see v^@lue at the start)

Content-Disposition: form-data; name="FILE1_+_CONTENTTYPE"; filename="formdata.h"
Content-Type: text/html
...

Content-Disposition: form-data; name="FILE1_+_FILE2"
Content-Type: multipart/mixed, boundary=curlz1s0dkticx49MV1KGcYP5cvfSsz
...
Content-Disposition: attachment; filename="formdata.h"
Content-Type: application/octet-stream
...
Content-Disposition: attachment; filename="Makefile.b32"
Content-Type: application/octet-stream
...

Content-Disposition: form-data; name="FILE1_+_FILE2_+_FILE3"
Content-Type: multipart/mixed, boundary=curlirkYPmPwu6FrJ1vJ1u1BmtIufh1
...
Content-Disposition: attachment; filename="formdata.h"
Content-Type: application/octet-stream
...
Content-Disposition: attachment; filename="Makefile.b32"
Content-Type: application/octet-stream
...
Content-Disposition: attachment; filename="formdata.h"
Content-Type: application/octet-stream
...


Content-Disposition: form-data; name="ARRAY: FILE1_+_FILE2_+_FILE3"
Content-Type: multipart/mixed, boundary=curlirkYPmPwu6FrJ1vJ1u1BmtIufh1
...
Content-Disposition: attachment; filename="formdata.h"
Content-Type: application/octet-stream
...
Content-Disposition: attachment; filename="Makefile.b32"
Content-Type: application/octet-stream
...
Content-Disposition: attachment; filename="formdata.h"
Content-Type: application/octet-stream
...

Content-Disposition: form-data; name="FILECONTENT"
...

 */

#include "setup.h"
#include <curl/curl.h>

/* Length of the random boundary string. */
#define BOUNDARY_LENGTH 40

#if !defined(CURL_DISABLE_HTTP) || defined(USE_SSLEAY)

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#if defined(HAVE_LIBGEN_H) && defined(HAVE_BASENAME)
#include <libgen.h>
#endif
#include "urldata.h" /* for struct SessionHandle */
#include "easyif.h" /* for Curl_convert_... prototypes */
#include "formdata.h"
#include "curl_rand.h"
#include "strequal.h"
#include "curl_memory.h"
#include "sendf.h"

#define _MPRINTF_REPLACE /* use our functions only */
#include <curl/mprintf.h>

/* The last #include file should be: */
#include "memdebug.h"

#endif  /* !defined(CURL_DISABLE_HTTP) || defined(USE_SSLEAY) */

#ifndef CURL_DISABLE_HTTP

#ifndef HAVE_BASENAME
static char *Curl_basename(char *path);
#define basename(x)  Curl_basename((x))
#endif

static size_t readfromfile(struct Form *form, char *buffer, size_t size);

/* What kind of Content-Type to use on un-specified files with unrecognized
   extensions. */
#define HTTPPOST_CONTENTTYPE_DEFAULT "application/octet-stream"

#define FORM_FILE_SEPARATOR ','
#define FORM_TYPE_SEPARATOR ';'

/***************************************************************************
 *
 * AddHttpPost()
 *
 * Adds a HttpPost structure to the list, if parent_post is given becomes
 * a subpost of parent_post instead of a direct list element.
 *
 * Returns newly allocated HttpPost on success and NULL if malloc failed.
 *
 ***************************************************************************/
static struct curl_httppost *
AddHttpPost(char *name, size_t namelength,
            char *value, size_t contentslength,
            char *buffer, size_t bufferlength,
            char *contenttype,
            long flags,
            struct curl_slist* contentHeader,
            char *showfilename, char *userp,
            struct curl_httppost *parent_post,
            struct curl_httppost **httppost,
            struct curl_httppost **last_post)
{
  struct curl_httppost *post;
  post = calloc(1, sizeof(struct curl_httppost));
  if(post) {
    post->name = name;
    post->namelength = (long)(name?(namelength?namelength:strlen(name)):0);
    post->contents = value;
    post->contentslength = (long)contentslength;
    post->buffer = buffer;
    post->bufferlength = (long)bufferlength;
    post->contenttype = contenttype;
    post->contentheader = contentHeader;
    post->showfilename = showfilename;
    post->userp = userp,
    post->flags = flags;
  }
  else
    return NULL;

  if(parent_post) {
    /* now, point our 'more' to the original 'more' */
    post->more = parent_post->more;

    /* then move the original 'more' to point to ourselves */
    parent_post->more = post;
  }
  else {
    /* make the previous point to this */
    if(*last_post)
      (*last_post)->next = post;
    else
      (*httppost) = post;

    (*last_post) = post;
  }
  return post;
}

/***************************************************************************
 *
 * AddFormInfo()
 *
 * Adds a FormInfo structure to the list presented by parent_form_info.
 *
 * Returns newly allocated FormInfo on success and NULL if malloc failed/
 * parent_form_info is NULL.
 *
 ***************************************************************************/
static FormInfo * AddFormInfo(char *value,
                              char *contenttype,
                              FormInfo *parent_form_info)
{
  FormInfo *form_info;
  form_info = calloc(1, sizeof(struct FormInfo));
  if(form_info) {
    if(value)
      form_info->value = value;
    if(contenttype)
      form_info->contenttype = contenttype;
    form_info->flags = HTTPPOST_FILENAME;
  }
  else
    return NULL;

  if(parent_form_info) {
    /* now, point our 'more' to the original 'more' */
    form_info->more = parent_form_info->more;

    /* then move the original 'more' to point to ourselves */
    parent_form_info->more = form_info;
  }
  else
    return NULL;

  return form_info;
}

/***************************************************************************
 *
 * ContentTypeForFilename()
 *
 * Provides content type for filename if one of the known types (else
 * (either the prevtype or the default is returned).
 *
 * Returns some valid contenttype for filename.
 *
 ***************************************************************************/
static const char * ContentTypeForFilename (const char *filename,
                                            const char *prevtype)
{
  const char *contenttype = NULL;
  unsigned int i;
  /*
   * No type was specified, we scan through a few well-known
   * extensions and pick the first we match!
   */
  struct ContentType {
    char extension[6];
    const char *type;
  };
  static const struct ContentType ctts[]={
    {".gif",  "image/gif"},
    {".jpg",  "image/jpeg"},
    {".jpeg", "image/jpeg"},
    {".txt",  "text/plain"},
    {".html", "text/html"},
    {".xml", "application/xml"}
  };

  if(prevtype)
    /* default to the previously set/used! */
    contenttype = prevtype;
  else
    contenttype = HTTPPOST_CONTENTTYPE_DEFAULT;

  if(filename) { /* in case a NULL was passed in */
    for(i=0; i<sizeof(ctts)/sizeof(ctts[0]); i++) {
      if(strlen(filename) >= strlen(ctts[i].extension)) {
        if(strequal(filename +
                    strlen(filename) - strlen(ctts[i].extension),
                    ctts[i].extension)) {
          contenttype = ctts[i].type;
          break;
        }
      }
    }
  }
  /* we have a contenttype by now */
  return contenttype;
}

/***************************************************************************
 *
 * memdup()
 *
 * Copies the 'source' data to a newly allocated buffer buffer (that is
 * returned). Uses buffer_length if not null, else uses strlen to determine
 * the length of the buffer to be copied
 *
 * Returns the new pointer or NULL on failure.
 *
 ***************************************************************************/
static char *memdup(const char *src, size_t buffer_length)
{
  size_t length;
  bool add = FALSE;
  char *buffer;

  if(buffer_length)
    length = buffer_length;
  else if(src) {
    length = strlen(src);
    add = TRUE;
  }
  else
    /* no length and a NULL src pointer! */
    return strdup("");

  buffer = malloc(length+add);
  if(!buffer)
    return NULL; /* fail */

  memcpy(buffer, src, length);

  /* if length unknown do null termination */
  if(add)
    buffer[length] = '\0';

  return buffer;
}

/***************************************************************************
 *
 * FormAdd()
 *
 * Stores a formpost parameter and builds the appropriate linked list.
 *
 * Has two principal functionalities: using files and byte arrays as
 * post parts. Byte arrays are either copied or just the pointer is stored
 * (as the user requests) while for files only the filename and not the
 * content is stored.
 *
 * While you may have only one byte array for each name, multiple filenames
 * are allowed (and because of this feature CURLFORM_END is needed after
 * using CURLFORM_FILE).
 *
 * Examples:
 *
 * Simple name/value pair with copied contents:
 * curl_formadd (&post, &last, CURLFORM_COPYNAME, "name",
 * CURLFORM_COPYCONTENTS, "value", CURLFORM_END);
 *
 * name/value pair where only the content pointer is remembered:
 * curl_formadd (&post, &last, CURLFORM_COPYNAME, "name",
 * CURLFORM_PTRCONTENTS, ptr, CURLFORM_CONTENTSLENGTH, 10, CURLFORM_END);
 * (if CURLFORM_CONTENTSLENGTH is missing strlen () is used)
 *
 * storing a filename (CONTENTTYPE is optional!):
 * curl_formadd (&post, &last, CURLFORM_COPYNAME, "name",
 * CURLFORM_FILE, "filename1", CURLFORM_CONTENTTYPE, "plain/text",
 * CURLFORM_END);
 *
 * storing multiple filenames:
 * curl_formadd (&post, &last, CURLFORM_COPYNAME, "name",
 * CURLFORM_FILE, "filename1", CURLFORM_FILE, "filename2", CURLFORM_END);
 *
 * Returns:
 * CURL_FORMADD_OK             on success
 * CURL_FORMADD_MEMORY         if the FormInfo allocation fails
 * CURL_FORMADD_OPTION_TWICE   if one option is given twice for one Form
 * CURL_FORMADD_NULL           if a null pointer was given for a char
 * CURL_FORMADD_MEMORY         if the allocation of a FormInfo struct failed
 * CURL_FORMADD_UNKNOWN_OPTION if an unknown option was used
 * CURL_FORMADD_INCOMPLETE     if the some FormInfo is not complete (or an error)
 * CURL_FORMADD_MEMORY         if a HttpPost struct cannot be allocated
 * CURL_FORMADD_MEMORY         if some allocation for string copying failed.
 * CURL_FORMADD_ILLEGAL_ARRAY  if an illegal option is used in an array
 *
 ***************************************************************************/

static
CURLFORMcode FormAdd(struct curl_httppost **httppost,
                     struct curl_httppost **last_post,
                     va_list params)
{
  FormInfo *first_form, *current_form, *form = NULL;
  CURLFORMcode return_value = CURL_FORMADD_OK;
  const char *prevtype = NULL;
  struct curl_httppost *post = NULL;
  CURLformoption option;
  struct curl_forms *forms = NULL;
  char *array_value=NULL; /* value read from an array */

  /* This is a state variable, that if TRUE means that we're parsing an
     array that we got passed to us. If FALSE we're parsing the input
     va_list arguments. */
  bool array_state = FALSE;

  /*
   * We need to allocate the first struct to fill in.
   */
  first_form = calloc(1, sizeof(struct FormInfo));
  if(!first_form)
    return CURL_FORMADD_MEMORY;

  current_form = first_form;

  /*
   * Loop through all the options set. Break if we have an error to report.
   */
  while(return_value == CURL_FORMADD_OK) {

    /* first see if we have more parts of the array param */
    if( array_state && forms ) {
      /* get the upcoming option from the given array */
      option = forms->option;
      array_value = (char *)forms->value;

      forms++; /* advance this to next entry */
      if(CURLFORM_END == option) {
        /* end of array state */
        array_state = FALSE;
        continue;
      }
    }
    else {
      /* This is not array-state, get next option */
      option = va_arg(params, CURLformoption);
      if(CURLFORM_END == option)
        break;
    }

    switch (option) {
    case CURLFORM_ARRAY:
      if(array_state)
        /* we don't support an array from within an array */
        return_value = CURL_FORMADD_ILLEGAL_ARRAY;
      else {
        forms = va_arg(params, struct curl_forms *);
        if(forms)
          array_state = TRUE;
        else
          return_value = CURL_FORMADD_NULL;
      }
      break;

      /*
       * Set the Name property.
       */
    case CURLFORM_PTRNAME:
#ifdef CURL_DOES_CONVERSIONS
      /* treat CURLFORM_PTR like CURLFORM_COPYNAME so we'll
         have safe memory for the eventual conversion */
#else
      current_form->flags |= HTTPPOST_PTRNAME; /* fall through */
#endif
    case CURLFORM_COPYNAME:
      if(current_form->name)
        return_value = CURL_FORMADD_OPTION_TWICE;
      else {
        char *name = array_state?
          array_value:va_arg(params, char *);
        if(name)
          current_form->name = name; /* store for the moment */
        else
          return_value = CURL_FORMADD_NULL;
      }
      break;
    case CURLFORM_NAMELENGTH:
      if(current_form->namelength)
        return_value = CURL_FORMADD_OPTION_TWICE;
      else
        current_form->namelength =
          array_state?(size_t)array_value:(size_t)va_arg(params, long);
      break;

      /*
       * Set the contents property.
       */
    case CURLFORM_PTRCONTENTS:
      current_form->flags |= HTTPPOST_PTRCONTENTS; /* fall through */
    case CURLFORM_COPYCONTENTS:
      if(current_form->value)
        return_value = CURL_FORMADD_OPTION_TWICE;
      else {
        char *value =
          array_state?array_value:va_arg(params, char *);
        if(value)
          current_form->value = value; /* store for the moment */
        else
          return_value = CURL_FORMADD_NULL;
      }
      break;
    case CURLFORM_CONTENTSLENGTH:
      if(current_form->contentslength)
        return_value = CURL_FORMADD_OPTION_TWICE;
      else
        current_form->contentslength =
          array_state?(size_t)array_value:(size_t)va_arg(params, long);
      break;

      /* Get contents from a given file name */
    case CURLFORM_FILECONTENT:
      if(current_form->flags != 0)
        return_value = CURL_FORMADD_OPTION_TWICE;
      else {
        const char *filename = array_state?
          array_value:va_arg(params, char *);
        if(filename) {
          current_form->value = strdup(filename);
          if(!current_form->value)
            return_value = CURL_FORMADD_MEMORY;
          else {
            current_form->flags |= HTTPPOST_READFILE;
            current_form->value_alloc = TRUE;
          }
        }
        else
          return_value = CURL_FORMADD_NULL;
      }
      break;

      /* We upload a file */
    case CURLFORM_FILE:
      {
        const char *filename = array_state?array_value:
          va_arg(params, char *);

        if(current_form->value) {
          if(current_form->flags & HTTPPOST_FILENAME) {
            if(filename) {
              if((current_form = AddFormInfo(strdup(filename),
                                              NULL, current_form)) == NULL)
                return_value = CURL_FORMADD_MEMORY;
            }
            else
              return_value = CURL_FORMADD_NULL;
          }
          else
            return_value = CURL_FORMADD_OPTION_TWICE;
        }
        else {
          if(filename) {
            current_form->value = strdup(filename);
            if(!current_form->value)
              return_value = CURL_FORMADD_MEMORY;
            else {
              current_form->flags |= HTTPPOST_FILENAME;
              current_form->value_alloc = TRUE;
            }
          }
          else
            return_value = CURL_FORMADD_NULL;
        }
        break;
      }

    case CURLFORM_BUFFER:
      {
        const char *filename = array_state?array_value:
          va_arg(params, char *);

        if(current_form->value) {
          if(current_form->flags & HTTPPOST_BUFFER) {
            if(filename) {
              if((current_form = AddFormInfo(strdup(filename),
                                              NULL, current_form)) == NULL)
                return_value = CURL_FORMADD_MEMORY;
            }
            else
              return_value = CURL_FORMADD_NULL;
          }
          else
            return_value = CURL_FORMADD_OPTION_TWICE;
        }
        else {
          if(filename) {
            current_form->value = strdup(filename);
            if(!current_form->value)
              return_value = CURL_FORMADD_MEMORY;
          }
          else
            return_value = CURL_FORMADD_NULL;
          current_form->flags |= HTTPPOST_BUFFER;
        }
        break;
      }

    case CURLFORM_BUFFERPTR:
      current_form->flags |= HTTPPOST_PTRBUFFER;
      if(current_form->buffer)
        return_value = CURL_FORMADD_OPTION_TWICE;
      else {
        char *buffer =
          array_state?array_value:va_arg(params, char *);
        if(buffer)
          current_form->buffer = buffer; /* store for the moment */
        else
          return_value = CURL_FORMADD_NULL;
      }
      break;

    case CURLFORM_BUFFERLENGTH:
      if(current_form->bufferlength)
        return_value = CURL_FORMADD_OPTION_TWICE;
      else
        current_form->bufferlength =
          array_state?(size_t)array_value:(size_t)va_arg(params, long);
      break;

    case CURLFORM_STREAM:
      current_form->flags |= HTTPPOST_CALLBACK;
      if(current_form->userp)
        return_value = CURL_FORMADD_OPTION_TWICE;
      else {
        char *userp =
          array_state?array_value:va_arg(params, char *);
        if(userp) {
          current_form->userp = userp;
          current_form->value = userp; /* this isn't strictly true but we
                                          derive a value from this later on
                                          and we need this non-NULL to be
                                          accepted as a fine form part */
        }
        else
          return_value = CURL_FORMADD_NULL;
      }
      break;

    case CURLFORM_CONTENTTYPE:
      {
        const char *contenttype =
          array_state?array_value:va_arg(params, char *);
        if(current_form->contenttype) {
          if(current_form->flags & HTTPPOST_FILENAME) {
            if(contenttype) {
              if((current_form = AddFormInfo(NULL,
                                              strdup(contenttype),
                                              current_form)) == NULL)
                return_value = CURL_FORMADD_MEMORY;
            }
            else
              return_value = CURL_FORMADD_NULL;
          }
          else
            return_value = CURL_FORMADD_OPTION_TWICE;
        }
        else {
          if(contenttype) {
            current_form->contenttype = strdup(contenttype);
            if(!current_form->contenttype)
              return_value = CURL_FORMADD_MEMORY;
            else
              current_form->contenttype_alloc = TRUE;
          }
          else
            return_value = CURL_FORMADD_NULL;
        }
        break;
      }
    case CURLFORM_CONTENTHEADER:
      {
        /* this "cast increases required alignment of target type" but
           we consider it OK anyway */
        struct curl_slist* list = array_state?
          (struct curl_slist*)array_value:
          va_arg(params, struct curl_slist*);

        if( current_form->contentheader )
          return_value = CURL_FORMADD_OPTION_TWICE;
        else
          current_form->contentheader = list;

        break;
      }
    case CURLFORM_FILENAME:
      {
        const char *filename = array_state?array_value:
          va_arg(params, char *);
        if( current_form->showfilename )
          return_value = CURL_FORMADD_OPTION_TWICE;
        else {
          current_form->showfilename = strdup(filename);
          if(!current_form->showfilename)
            return_value = CURL_FORMADD_MEMORY;
          else
            current_form->showfilename_alloc = TRUE;
        }
        break;
      }
    default:
      return_value = CURL_FORMADD_UNKNOWN_OPTION;
    }
  }

  if(CURL_FORMADD_OK == return_value) {
    /* go through the list, check for completeness and if everything is
     * alright add the HttpPost item otherwise set return_value accordingly */

    post = NULL;
    for(form = first_form;
        form != NULL;
        form = form->more) {
      if( ((!form->name || !form->value) && !post) ||
          ( (form->contentslength) &&
            (form->flags & HTTPPOST_FILENAME) ) ||
          ( (form->flags & HTTPPOST_FILENAME) &&
            (form->flags & HTTPPOST_PTRCONTENTS) ) ||

          ( (!form->buffer) &&
            (form->flags & HTTPPOST_BUFFER) &&
            (form->flags & HTTPPOST_PTRBUFFER) ) ||

          ( (form->flags & HTTPPOST_READFILE) &&
            (form->flags & HTTPPOST_PTRCONTENTS) )
        ) {
        return_value = CURL_FORMADD_INCOMPLETE;
        break;
      }
      else {
        if( ((form->flags & HTTPPOST_FILENAME) ||
              (form->flags & HTTPPOST_BUFFER)) &&
             !form->contenttype ) {
          /* our contenttype is missing */
          form->contenttype
            = strdup(ContentTypeForFilename(form->value, prevtype));
          if(!form->contenttype) {
            return_value = CURL_FORMADD_MEMORY;
            break;
          }
          form->contenttype_alloc = TRUE;
        }
        if( !(form->flags & HTTPPOST_PTRNAME) &&
             (form == first_form) ) {
          /* Note that there's small risk that form->name is NULL here if the
             app passed in a bad combo, so we better check for that first. */
          if(form->name)
            /* copy name (without strdup; possibly contains null characters) */
            form->name = memdup(form->name, form->namelength);
          if(!form->name) {
            return_value = CURL_FORMADD_MEMORY;
            break;
          }
          form->name_alloc = TRUE;
        }
        if( !(form->flags & (HTTPPOST_FILENAME | HTTPPOST_READFILE |
                             HTTPPOST_PTRCONTENTS | HTTPPOST_PTRBUFFER |
                             HTTPPOST_CALLBACK)) ) {
          /* copy value (without strdup; possibly contains null characters) */
          form->value = memdup(form->value, form->contentslength);
          if(!form->value) {
            return_value = CURL_FORMADD_MEMORY;
            break;
          }
          form->value_alloc = TRUE;
        }
        post = AddHttpPost(form->name, form->namelength,
                           form->value, form->contentslength,
                           form->buffer, form->bufferlength,
                           form->contenttype, form->flags,
                           form->contentheader, form->showfilename,
                           form->userp,
                           post, httppost,
                           last_post);

        if(!post) {
          return_value = CURL_FORMADD_MEMORY;
          break;
        }

        if(form->contenttype)
          prevtype = form->contenttype;
      }
    }
  }

  if(return_value) {
    /* we return on error, free possibly allocated fields */
    if(!form)
      form = current_form;
    if(form) {
      if(form->name_alloc)
        free(form->name);
      if(form->value_alloc)
        free(form->value);
      if(form->contenttype_alloc)
        free(form->contenttype);
      if(form->showfilename_alloc)
        free(form->showfilename);
    }
  }

  /* always delete the allocated memory before returning */
  form = first_form;
  while(form != NULL) {
    FormInfo *delete_form;

    delete_form = form;
    form = form->more;
    free (delete_form);
  }

  return return_value;
}

/*
 * curl_formadd() is a public API to add a section to the multipart formpost.
 */

CURLFORMcode curl_formadd(struct curl_httppost **httppost,
                          struct curl_httppost **last_post,
                          ...)
{
  va_list arg;
  CURLFORMcode result;
  va_start(arg, last_post);
  result = FormAdd(httppost, last_post, arg);
  va_end(arg);
  return result;
}

/*
 * AddFormData() adds a chunk of data to the FormData linked list.
 *
 * size is incremented by the chunk length, unless it is NULL
 */
static CURLcode AddFormData(struct FormData **formp,
                            enum formtype type,
                            const void *line,
                            size_t length,
                            curl_off_t *size)
{
  struct FormData *newform = malloc(sizeof(struct FormData));
  if(!newform)
    return CURLE_OUT_OF_MEMORY;
  newform->next = NULL;

  if(type <= FORM_CONTENT) {
    /* we make it easier for plain strings: */
    if(!length)
      length = strlen((char *)line);

    newform->line = malloc(length+1);
    if(!newform->line) {
      free(newform);
      return CURLE_OUT_OF_MEMORY;
    }
    memcpy(newform->line, line, length);
    newform->length = length;
    newform->line[length]=0; /* zero terminate for easier debugging */
  }
  else
    /* For callbacks and files we don't have any actual data so we just keep a
       pointer to whatever this points to */
    newform->line = (char *)line;

  newform->type = type;

  if(*formp) {
    (*formp)->next = newform;
    *formp = newform;
  }
  else
    *formp = newform;

  if(size) {
    if(type != FORM_FILE)
      /* for static content as well as callback data we add the size given
         as input argument */
      *size += length;
    else {
      /* Since this is a file to be uploaded here, add the size of the actual
         file */
      if(!strequal("-", newform->line)) {
        struct_stat file;
        if(!stat(newform->line, &file)) {
          *size += file.st_size;
        }
      }
    }
  }
  return CURLE_OK;
}

/*
 * AddFormDataf() adds printf()-style formatted data to the formdata chain.
 */

static CURLcode AddFormDataf(struct FormData **formp,
                             curl_off_t *size,
                             const char *fmt, ...)
{
  char s[4096];
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(s, sizeof(s), fmt, ap);
  va_end(ap);

  return AddFormData(formp, FORM_DATA, s, 0, size);
}

/*
 * Curl_formclean() is used from http.c, this cleans a built FormData linked
 * list
 */
void Curl_formclean(struct FormData **form_ptr)
{
  struct FormData *next, *form;

  form = *form_ptr;
  if(!form)
    return;

  do {
    next=form->next;  /* the following form line */
    if(form->type <= FORM_CONTENT)
      free(form->line); /* free the line */
    free(form);       /* free the struct */

  } while((form = next) != NULL); /* continue */

  *form_ptr = NULL;
}

#ifdef CURL_DOES_CONVERSIONS
/*
 * Curl_formcovert() is used from http.c, this converts any
   form items that need to be sent in the network encoding.
   Returns CURLE_OK on success.
 */
CURLcode Curl_formconvert(struct SessionHandle *data, struct FormData *form)
{
  struct FormData *next;
  CURLcode rc;

  if(!form)
    return CURLE_OK;

  if(!data)
    return CURLE_BAD_FUNCTION_ARGUMENT;

  do {
    next=form->next;  /* the following form line */
    if(form->type == FORM_DATA) {
      rc = Curl_convert_to_network(data, form->line, form->length);
      /* Curl_convert_to_network calls failf if unsuccessful */
      if(rc != CURLE_OK)
        return rc;
    }
  } while((form = next) != NULL); /* continue */
  return CURLE_OK;
}
#endif /* CURL_DOES_CONVERSIONS */

/*
 * curl_formget()
 * Serialize a curl_httppost struct.
 * Returns 0 on success.
 */
int curl_formget(struct curl_httppost *form, void *arg,
                 curl_formget_callback append)
{
  CURLcode rc;
  curl_off_t size;
  struct FormData *data, *ptr;

  rc = Curl_getformdata(NULL, &data, form, NULL, &size);
  if(rc != CURLE_OK)
    return (int)rc;

  for (ptr = data; ptr; ptr = ptr->next) {
    if(ptr->type == FORM_FILE) {
      char buffer[8192];
      size_t nread;
      struct Form temp;

      Curl_FormInit(&temp, ptr);

      do {
        nread = readfromfile(&temp, buffer, sizeof(buffer));
        if((nread == (size_t) -1) || (nread != append(arg, buffer, nread))) {
          if(temp.fp) {
            fclose(temp.fp);
          }
          Curl_formclean(&data);
          return -1;
        }
      } while(nread == sizeof(buffer));
    }
    else {
      if(ptr->length != append(arg, ptr->line, ptr->length)) {
        Curl_formclean(&data);
        return -1;
      }
    }
  }
  Curl_formclean(&data);
  return 0;
}

/*
 * curl_formfree() is an external function to free up a whole form post
 * chain
 */
void curl_formfree(struct curl_httppost *form)
{
  struct curl_httppost *next;

  if(!form)
    /* no form to free, just get out of this */
    return;

  do {
    next=form->next;  /* the following form line */

    /* recurse to sub-contents */
    if(form->more)
      curl_formfree(form->more);

    if( !(form->flags & HTTPPOST_PTRNAME) && form->name)
      free(form->name); /* free the name */
    if( !(form->flags & (HTTPPOST_PTRCONTENTS|HTTPPOST_CALLBACK)) &&
        form->contents)
      free(form->contents); /* free the contents */
    if(form->contenttype)
      free(form->contenttype); /* free the content type */
    if(form->showfilename)
      free(form->showfilename); /* free the faked file name */
    free(form);       /* free the struct */

  } while((form = next) != NULL); /* continue */
}

#ifndef HAVE_BASENAME
/*
  (Quote from The Open Group Base Specifications Issue 6 IEEE Std 1003.1, 2004
  Edition)

  The basename() function shall take the pathname pointed to by path and
  return a pointer to the final component of the pathname, deleting any
  trailing '/' characters.

  If the string pointed to by path consists entirely of the '/' character,
  basename() shall return a pointer to the string "/". If the string pointed
  to by path is exactly "//", it is implementation-defined whether '/' or "//"
  is returned.

  If path is a null pointer or points to an empty string, basename() shall
  return a pointer to the string ".".

  The basename() function may modify the string pointed to by path, and may
  return a pointer to static storage that may then be overwritten by a
  subsequent call to basename().

  The basename() function need not be reentrant. A function that is not
  required to be reentrant is not required to be thread-safe.

*/
static char *Curl_basename(char *path)
{
  /* Ignore all the details above for now and make a quick and simple
     implementaion here */
  char *s1;
  char *s2;

  s1=strrchr(path, '/');
  s2=strrchr(path, '\\');

  if(s1 && s2) {
    path = (s1 > s2? s1 : s2)+1;
  }
  else if(s1)
    path = s1 + 1;
  else if(s2)
    path = s2 + 1;

  return path;
}
#endif

static char *strippath(const char *fullfile)
{
  char *filename;
  char *base;
  filename = strdup(fullfile); /* duplicate since basename() may ruin the
                                  buffer it works on */
  if(!filename)
    return NULL;
  base = strdup(basename(filename));

  free(filename); /* free temporary buffer */

  return base; /* returns an allocated string or NULL ! */
}

/*
 * Curl_getformdata() converts a linked list of "meta data" into a complete
 * (possibly huge) multipart formdata. The input list is in 'post', while the
 * output resulting linked lists gets stored in '*finalform'. *sizep will get
 * the total size of the whole POST.
 * A multipart/form_data content-type is built, unless a custom content-type
 * is passed in 'custom_content_type'.
 *
 * This function will not do a failf() for the potential memory failures but
 * should for all other errors it spots. Just note that this function MAY get
 * a NULL pointer in the 'data' argument.
 */

CURLcode Curl_getformdata(struct SessionHandle *data,
                          struct FormData **finalform,
                          struct curl_httppost *post,
                          const char *custom_content_type,
                          curl_off_t *sizep)
{
  struct FormData *form = NULL;
  struct FormData *firstform;
  struct curl_httppost *file;
  CURLcode result = CURLE_OK;

  curl_off_t size=0; /* support potentially ENORMOUS formposts */
  char *boundary;
  char *fileboundary=NULL;
  struct curl_slist* curList;

  *finalform=NULL; /* default form is empty */

  if(!post)
    return result; /* no input => no output! */

  boundary = Curl_FormBoundary();
  if(!boundary)
    return CURLE_OUT_OF_MEMORY;

  /* Make the first line of the output */
  result = AddFormDataf(&form, NULL,
                        "%s; boundary=%s\r\n",
                        custom_content_type?custom_content_type:
                        "Content-Type: multipart/form-data",
                        boundary);

  if(result) {
    free(boundary);
    return result;
  }
  /* we DO NOT include that line in the total size of the POST, since it'll be
     part of the header! */

  firstform = form;

  do {

    if(size) {
      result = AddFormDataf(&form, &size, "\r\n");
      if(result)
        break;
    }

    /* boundary */
    result = AddFormDataf(&form, &size, "--%s\r\n", boundary);
    if(result)
      break;

    /* Maybe later this should be disabled when a custom_content_type is
       passed, since Content-Disposition is not meaningful for all multipart
       types.
    */
    result = AddFormDataf(&form, &size,
                          "Content-Disposition: form-data; name=\"");
    if(result)
      break;

    result = AddFormData(&form, FORM_DATA, post->name, post->namelength,
                         &size);
    if(result)
      break;

    result = AddFormDataf(&form, &size, "\"");
    if(result)
      break;

    if(post->more) {
      /* If used, this is a link to more file names, we must then do
         the magic to include several files with the same field name */

      fileboundary = Curl_FormBoundary();

      result = AddFormDataf(&form, &size,
                            "\r\nContent-Type: multipart/mixed,"
                            " boundary=%s\r\n",
                            fileboundary);
      if(result)
        break;
    }

    file = post;

    do {

      /* If 'showfilename' is set, that is a faked name passed on to us
         to use to in the formpost. If that is not set, the actually used
         local file name should be added. */

      if(post->more) {
        /* if multiple-file */
        char *filebasename= NULL;
        if(!file->showfilename) {
          filebasename = strippath(file->contents);
          if(!filebasename) {
            Curl_formclean(&firstform);
            free(boundary);
            return CURLE_OUT_OF_MEMORY;
          }
        }

        result = AddFormDataf(&form, &size,
                              "\r\n--%s\r\nContent-Disposition: "
                              "attachment; filename=\"%s\"",
                              fileboundary,
                              (file->showfilename?file->showfilename:
                               filebasename));
        if(filebasename)
          free(filebasename);
        if(result)
          break;
      }
      else if(post->flags & (HTTPPOST_FILENAME|HTTPPOST_BUFFER|
                             HTTPPOST_CALLBACK)) {
        /* it should be noted that for the HTTPPOST_FILENAME and
           HTTPPOST_CALLBACK cases the ->showfilename struct member is always
           assigned at this point */
        char *filebasename=
          (!post->showfilename)?strippath(post->contents):NULL;

        result = AddFormDataf(&form, &size,
                              "; filename=\"%s\"",
                              (post->showfilename?post->showfilename:
                               filebasename));
        if(filebasename)
          free(filebasename);

        if(result)
          break;
      }

      if(file->contenttype) {
        /* we have a specified type */
        result = AddFormDataf(&form, &size,
                              "\r\nContent-Type: %s",
                              file->contenttype);
        if(result)
          break;
      }

      curList = file->contentheader;
      while( curList ) {
        /* Process the additional headers specified for this form */
        result = AddFormDataf( &form, &size, "\r\n%s", curList->data );
        if(result)
          break;
        curList = curList->next;
      }
      if(result) {
        Curl_formclean(&firstform);
        free(boundary);
        return result;
      }

      result = AddFormDataf(&form, &size, "\r\n\r\n");
      if(result)
        break;

      if((post->flags & HTTPPOST_FILENAME) ||
         (post->flags & HTTPPOST_READFILE)) {
        /* we should include the contents from the specified file */
        FILE *fileread;

        fileread = strequal("-", file->contents)?
          stdin:fopen(file->contents, "rb"); /* binary read for win32  */

        /*
         * VMS: This only allows for stream files on VMS.  Stream files are
         * OK, as are FIXED & VAR files WITHOUT implied CC For implied CC,
         * every record needs to have a \n appended & 1 added to SIZE
         */

        if(fileread) {
          if(fileread != stdin) {
            /* close the file again */
            fclose(fileread);
            /* add the file name only - for later reading from this */
            result = AddFormData(&form, FORM_FILE, file->contents, 0, &size);
          }
          else {
            /* When uploading from stdin, we can't know the size of the file,
             * thus must read the full file as before. We *could* use chunked
             * transfer-encoding, but that only works for HTTP 1.1 and we
             * can't be sure we work with such a server.
             */
            size_t nread;
            char buffer[512];
            while((nread = fread(buffer, 1, sizeof(buffer), fileread)) != 0) {
              result = AddFormData(&form, FORM_CONTENT, buffer, nread, &size);
              if(result)
                break;
            }
          }
        }
        else {
          if(data)
            failf(data, "couldn't open file \"%s\"\n", file->contents);
          *finalform = NULL;
          result = CURLE_READ_ERROR;
        }
      }
      else if(post->flags & HTTPPOST_BUFFER)
        /* include contents of buffer */
        result = AddFormData(&form, FORM_CONTENT, post->buffer,
                             post->bufferlength, &size);
      else if(post->flags & HTTPPOST_CALLBACK)
        /* the contents should be read with the callback and the size
           is set with the contentslength */
        result = AddFormData(&form, FORM_CALLBACK, post->userp,
                             post->contentslength, &size);
      else
        /* include the contents we got */
        result = AddFormData(&form, FORM_CONTENT, post->contents,
                             post->contentslength, &size);

      file = file->more;
    } while(file && !result); /* for each specified file for this field */

    if(result) {
      Curl_formclean(&firstform);
      free(boundary);
      return result;
    }

    if(post->more) {
      /* this was a multiple-file inclusion, make a termination file
         boundary: */
      result = AddFormDataf(&form, &size,
                           "\r\n--%s--",
                           fileboundary);
      free(fileboundary);
      if(result)
        break;
    }

  } while((post = post->next) != NULL); /* for each field */
  if(result) {
    Curl_formclean(&firstform);
    free(boundary);
    return result;
  }

  /* end-boundary for everything */
  result = AddFormDataf(&form, &size,
                       "\r\n--%s--\r\n",
                       boundary);
  if(result) {
    Curl_formclean(&firstform);
    free(boundary);
    return result;
  }

  *sizep = size;

  free(boundary);

  *finalform=firstform;

  return result;
}

/*
 * Curl_FormInit() inits the struct 'form' points to with the 'formdata'
 * and resets the 'sent' counter.
 */
int Curl_FormInit(struct Form *form, struct FormData *formdata )
{
  if(!formdata)
    return 1; /* error */

  form->data = formdata;
  form->sent = 0;
  form->fp = NULL;
  form->fread_func = ZERO_NULL;

  return 0;
}

static size_t readfromfile(struct Form *form, char *buffer,
                           size_t size)
{
  size_t nread;
  bool callback = (bool)(form->data->type == FORM_CALLBACK);

  if(callback)
    nread = form->fread_func(buffer, 1, size, form->data->line);
  else {
    if(!form->fp) {
      /* this file hasn't yet been opened */
      form->fp = fopen(form->data->line, "rb"); /* b is for binary */
      if(!form->fp)
        return (size_t)-1; /* failure */
    }
    nread = fread(buffer, 1, size, form->fp);
  }
  if(!nread || nread > size) {
    /* this is the last chunk from the file, move on */
    if(!callback) {
      fclose(form->fp);
      form->fp = NULL;
    }
    form->data = form->data->next;
  }

  return nread;
}

/*
 * Curl_FormReader() is the fread() emulation function that will be used to
 * deliver the formdata to the transfer loop and then sent away to the peer.
 */
size_t Curl_FormReader(char *buffer,
                       size_t size,
                       size_t nitems,
                       FILE *mydata)
{
  struct Form *form;
  size_t wantedsize;
  size_t gotsize = 0;

  form=(struct Form *)mydata;

  wantedsize = size * nitems;

  if(!form->data)
    return 0; /* nothing, error, empty */

  if((form->data->type == FORM_FILE) ||
     (form->data->type == FORM_CALLBACK)) {
    gotsize = readfromfile(form, buffer, wantedsize);

    if(gotsize)
      /* If positive or -1, return. If zero, continue! */
      return gotsize;
  }
  do {

    if( (form->data->length - form->sent ) > wantedsize - gotsize) {

      memcpy(buffer + gotsize , form->data->line + form->sent,
             wantedsize - gotsize);

      form->sent += wantedsize-gotsize;

      return wantedsize;
    }

    memcpy(buffer+gotsize,
           form->data->line + form->sent,
           (form->data->length - form->sent) );
    gotsize += form->data->length - form->sent;

    form->sent = 0;

    form->data = form->data->next; /* advance */

  } while(form->data && (form->data->type < FORM_CALLBACK));
  /* If we got an empty line and we have more data, we proceed to the next
     line immediately to avoid returning zero before we've reached the end. */

  return gotsize;
}

/*
 * Curl_formpostheader() returns the first line of the formpost, the
 * request-header part (which is not part of the request-body like the rest of
 * the post).
 */
char *Curl_formpostheader(void *formp, size_t *len)
{
  char *header;
  struct Form *form=(struct Form *)formp;

  if(!form->data)
    return 0; /* nothing, ERROR! */

  header = form->data->line;
  *len = form->data->length;

  form->data = form->data->next; /* advance */

  return header;
}


#ifdef _FORM_DEBUG
int FormAddTest(const char * errormsg,
                 struct curl_httppost **httppost,
                 struct curl_httppost **last_post,
                 ...)
{
  int result;
  va_list arg;
  va_start(arg, last_post);
  if((result = FormAdd(httppost, last_post, arg)))
    fprintf (stderr, "ERROR doing FormAdd ret: %d action: %s\n", result,
             errormsg);
  va_end(arg);
  return result;
}


int main(int argc, argv_item_t argv[])
{
  char name1[] = "simple_COPYCONTENTS";
  char name2[] = "COPYCONTENTS_+_CONTENTTYPE";
  char name3[] = "PTRNAME_+_NAMELENGTH_+_COPYNAME_+_CONTENTSLENGTH";
  char name4[] = "simple_PTRCONTENTS";
  char name5[] = "PTRCONTENTS_+_CONTENTSLENGTH";
  char name6[] = "PTRCONTENTS_+_CONTENTSLENGTH_+_CONTENTTYPE";
  char name7[] = "FILE1_+_CONTENTTYPE";
  char name8[] = "FILE1_+_FILE2";
  char name9[] = "FILE1_+_FILE2_+_FILE3";
  char name10[] = "ARRAY: FILE1_+_FILE2_+_FILE3";
  char name11[] = "FILECONTENT";
  char value1[] = "value for simple COPYCONTENTS";
  char value2[] = "value for COPYCONTENTS + CONTENTTYPE";
  char value3[] = "value for PTRNAME + NAMELENGTH + COPYNAME + CONTENTSLENGTH";
  char value4[] = "value for simple PTRCONTENTS";
  char value5[] = "value for PTRCONTENTS + CONTENTSLENGTH";
  char value6[] = "value for PTRCONTENTS + CONTENTSLENGTH + CONTENTTYPE";
  char value7[] = "formdata.h";
  char value8[] = "Makefile.b32";
  char type2[] = "image/gif";
  char type6[] = "text/plain";
  char type7[] = "text/html";
  int name3length = strlen(name3);
  int value3length = strlen(value3);
  int value5length = strlen(value5);
  int value6length = strlen(value6);
  int errors = 0;
  CURLcode rc;
  curl_off_t size;
  size_t nread;
  char buffer[4096];
  struct curl_httppost *httppost=NULL;
  struct curl_httppost *last_post=NULL;
  struct curl_forms forms[4];

  struct FormData *form;
  struct Form formread;

  (void) argc;
  (void) argv;

  Curl_srand();         /* Because we do not call curl_global_init() here. */

  if(FormAddTest("simple COPYCONTENTS test", &httppost, &last_post,
                  CURLFORM_COPYNAME, name1, CURLFORM_COPYCONTENTS, value1,
                  CURLFORM_END))
    ++errors;
  if(FormAddTest("COPYCONTENTS  + CONTENTTYPE test", &httppost, &last_post,
                  CURLFORM_COPYNAME, name2, CURLFORM_COPYCONTENTS, value2,
                  CURLFORM_CONTENTTYPE, type2, CURLFORM_END))
    ++errors;
  /* make null character at start to check that contentslength works
     correctly */
  name3[1] = '\0';
  value3[1] = '\0';
  if(FormAddTest("PTRNAME + NAMELENGTH + COPYNAME + CONTENTSLENGTH test",
                  &httppost, &last_post,
                  CURLFORM_PTRNAME, name3, CURLFORM_COPYCONTENTS, value3,
                  CURLFORM_CONTENTSLENGTH, value3length,
                  CURLFORM_NAMELENGTH, name3length, CURLFORM_END))
    ++errors;
  if(FormAddTest("simple PTRCONTENTS test", &httppost, &last_post,
                  CURLFORM_COPYNAME, name4, CURLFORM_PTRCONTENTS, value4,
                  CURLFORM_END))
    ++errors;
  /* make null character at start to check that contentslength works
     correctly */
  value5[1] = '\0';
  if(FormAddTest("PTRCONTENTS + CONTENTSLENGTH test", &httppost, &last_post,
                  CURLFORM_COPYNAME, name5, CURLFORM_PTRCONTENTS, value5,
                  CURLFORM_CONTENTSLENGTH, value5length, CURLFORM_END))
    ++errors;
  /* make null character at start to check that contentslength works
     correctly */
  value6[1] = '\0';
  if(FormAddTest("PTRCONTENTS + CONTENTSLENGTH + CONTENTTYPE test",
                  &httppost, &last_post,
                  CURLFORM_COPYNAME, name6, CURLFORM_PTRCONTENTS, value6,
                  CURLFORM_CONTENTSLENGTH, value6length,
                  CURLFORM_CONTENTTYPE, type6, CURLFORM_END))
    ++errors;
  if(FormAddTest("FILE + CONTENTTYPE test", &httppost, &last_post,
                  CURLFORM_COPYNAME, name7, CURLFORM_FILE, value7,
                  CURLFORM_CONTENTTYPE, type7, CURLFORM_END))
    ++errors;
  if(FormAddTest("FILE1 + FILE2 test", &httppost, &last_post,
                  CURLFORM_COPYNAME, name8, CURLFORM_FILE, value7,
                  CURLFORM_FILE, value8, CURLFORM_END))
    ++errors;
  if(FormAddTest("FILE1 + FILE2 + FILE3 test", &httppost, &last_post,
                  CURLFORM_COPYNAME, name9, CURLFORM_FILE, value7,
                  CURLFORM_FILE, value8, CURLFORM_FILE, value7, CURLFORM_END))
    ++errors;
  forms[0].option = CURLFORM_FILE;
  forms[0].value  = value7;
  forms[1].option = CURLFORM_FILE;
  forms[1].value  = value8;
  forms[2].option = CURLFORM_FILE;
  forms[2].value  = value7;
  forms[3].option  = CURLFORM_END;
  if(FormAddTest("FILE1 + FILE2 + FILE3 ARRAY test", &httppost, &last_post,
                  CURLFORM_COPYNAME, name10, CURLFORM_ARRAY, forms,
                  CURLFORM_END))
    ++errors;
  if(FormAddTest("FILECONTENT test", &httppost, &last_post,
                  CURLFORM_COPYNAME, name11, CURLFORM_FILECONTENT, value7,
                  CURLFORM_END))
    ++errors;

  rc = Curl_getformdata(NULL, &form, httppost, NULL, &size);
  if(rc != CURLE_OK) {
    if(rc != CURLE_READ_ERROR) {
      const char *errortext = curl_easy_strerror(rc);
      fprintf(stdout, "\n==> Curl_getformdata error: %s\n", errortext);
    }
    return 0;
  }

  Curl_FormInit(&formread, form);

  for(;;) {
    nread = Curl_FormReader(buffer, 1, sizeof(buffer),
                            (FILE *)&formread);

    if(nread < 1)
      break;
    fwrite(buffer, nread, 1, stdout);
  }

  fprintf(stdout, "size: ");
  fprintf(stdout, "%" FORMAT_OFF_T, size);
  fprintf(stdout, "\n");
  if(errors)
    fprintf(stdout, "\n==> %d Test(s) failed!\n", errors);
  else
    fprintf(stdout, "\nAll Tests seem to have worked (please check output)\n");

  return 0;
}

#endif  /* _FORM_DEBUG */

#else  /* CURL_DISABLE_HTTP */
CURLFORMcode curl_formadd(struct curl_httppost **httppost,
                          struct curl_httppost **last_post,
                          ...)
{
  (void)httppost;
  (void)last_post;
  return CURL_FORMADD_DISABLED;
}

int curl_formget(struct curl_httppost *form, void *arg,
                 curl_formget_callback append)
{
  (void) form;
  (void) arg;
  (void) append;
  return CURL_FORMADD_DISABLED;
}

void curl_formfree(struct curl_httppost *form)
{
  (void)form;
  /* does nothing HTTP is disabled */
}

#endif  /* CURL_DISABLE_HTTP */

#if !defined(CURL_DISABLE_HTTP) || defined(USE_SSLEAY)

/*
 * Curl_FormBoundary() creates a suitable boundary string and returns an
 * allocated one. This is also used by SSL-code so it must be present even
 * if HTTP is disabled!
 */
char *Curl_FormBoundary(void)
{
  char *retstring;
  size_t i;

  static const char table16[]="0123456789abcdef";

  retstring = malloc(BOUNDARY_LENGTH+1);

  if(!retstring)
    return NULL; /* failed */

  strcpy(retstring, "----------------------------");

  for(i=strlen(retstring); i<BOUNDARY_LENGTH; i++)
    retstring[i] = table16[Curl_rand()%16];

  /* 28 dashes and 12 hexadecimal digits makes 12^16 (184884258895036416)
     combinations */
  retstring[BOUNDARY_LENGTH]=0; /* zero terminate */

  return retstring;
}

#endif  /* !defined(CURL_DISABLE_HTTP) || defined(USE_SSLEAY) */
