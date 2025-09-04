/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * SPDX-License-Identifier: curl
 *
 ***************************************************************************/

#include "curl_setup.h"

#include <curl/curl.h>

struct Curl_easy;

#include "formdata.h"
#if !defined(CURL_DISABLE_HTTP) && !defined(CURL_DISABLE_FORM_API)

#include "urldata.h" /* for struct Curl_easy */
#include "mime.h"
#include "vtls/vtls.h"
#include "sendf.h"
#include "strdup.h"
#include "rand.h"
#include "curlx/warnless.h"
/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"


#define HTTPPOST_PTRNAME CURL_HTTPPOST_PTRNAME
#define HTTPPOST_FILENAME CURL_HTTPPOST_FILENAME
#define HTTPPOST_PTRCONTENTS CURL_HTTPPOST_PTRCONTENTS
#define HTTPPOST_READFILE CURL_HTTPPOST_READFILE
#define HTTPPOST_PTRBUFFER CURL_HTTPPOST_PTRBUFFER
#define HTTPPOST_CALLBACK CURL_HTTPPOST_CALLBACK
#define HTTPPOST_BUFFER CURL_HTTPPOST_BUFFER

/***************************************************************************
 *
 * AddHttpPost()
 *
 * Adds an HttpPost structure to the list, if parent_post is given becomes
 * a subpost of parent_post instead of a direct list element.
 *
 * Returns newly allocated HttpPost on success and NULL if malloc failed.
 *
 ***************************************************************************/
static struct curl_httppost *
AddHttpPost(struct FormInfo *src,
            struct curl_httppost *parent_post,
            struct curl_httppost **httppost,
            struct curl_httppost **last_post)
{
  struct curl_httppost *post;
  size_t namelength = src->namelength;
  if(!namelength && src->name)
    namelength = strlen(src->name);
  if((src->bufferlength > LONG_MAX) || (namelength > LONG_MAX))
    /* avoid overflow in typecasts below */
    return NULL;
  post = calloc(1, sizeof(struct curl_httppost));
  if(post) {
    post->name = src->name;
    post->namelength = (long)namelength;
    post->contents = src->value;
    post->contentlen = src->contentslength;
    post->buffer = src->buffer;
    post->bufferlength = (long)src->bufferlength;
    post->contenttype = src->contenttype;
    post->flags = src->flags | CURL_HTTPPOST_LARGE;
    post->contentheader = src->contentheader;
    post->showfilename = src->showfilename;
    post->userp = src->userp;
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
static struct FormInfo *AddFormInfo(char *value,
                                    char *contenttype,
                                    struct FormInfo *parent_form_info)
{
  struct FormInfo *form_info;
  form_info = calloc(1, sizeof(struct FormInfo));
  if(!form_info)
    return NULL;
  if(value)
    form_info->value = value;
  if(contenttype)
    form_info->contenttype = contenttype;
  form_info->flags = HTTPPOST_FILENAME;

  if(parent_form_info) {
    /* now, point our 'more' to the original 'more' */
    form_info->more = parent_form_info->more;

    /* then move the original 'more' to point to ourselves */
    parent_form_info->more = form_info;
  }

  return form_info;
}

static void free_formlist(struct FormInfo *ptr)
{
  for(; ptr != NULL; ptr = ptr->more) {
    if(ptr->name_alloc) {
      Curl_safefree(ptr->name);
      ptr->name_alloc = FALSE;
    }
    if(ptr->value_alloc) {
      Curl_safefree(ptr->value);
      ptr->value_alloc = FALSE;
    }
    if(ptr->contenttype_alloc) {
      Curl_safefree(ptr->contenttype);
      ptr->contenttype_alloc = FALSE;
    }
    if(ptr->showfilename_alloc) {
      Curl_safefree(ptr->showfilename);
      ptr->showfilename_alloc = FALSE;
    }
  }
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
 * curl_formadd(&post, &last, CURLFORM_COPYNAME, "name",
 *              CURLFORM_COPYCONTENTS, "value", CURLFORM_END);
 *
 * name/value pair where only the content pointer is remembered:
 * curl_formadd(&post, &last, CURLFORM_COPYNAME, "name",
 *              CURLFORM_PTRCONTENTS, ptr, CURLFORM_CONTENTSLENGTH, 10,
 *              CURLFORM_END);
 * (if CURLFORM_CONTENTSLENGTH is missing strlen () is used)
 *
 * storing a filename (CONTENTTYPE is optional!):
 * curl_formadd(&post, &last, CURLFORM_COPYNAME, "name",
 *              CURLFORM_FILE, "filename1", CURLFORM_CONTENTTYPE, "plain/text",
 *              CURLFORM_END);
 *
 * storing multiple filenames:
 * curl_formadd(&post, &last, CURLFORM_COPYNAME, "name",
 *              CURLFORM_FILE, "filename1", CURLFORM_FILE, "filename2",
 *              CURLFORM_END);
 *
 * Returns:
 * CURL_FORMADD_OK             on success
 * CURL_FORMADD_MEMORY         if the FormInfo allocation fails
 * CURL_FORMADD_OPTION_TWICE   if one option is given twice for one Form
 * CURL_FORMADD_NULL           if a null pointer was given for a char
 * CURL_FORMADD_MEMORY         if the allocation of a FormInfo struct failed
 * CURL_FORMADD_UNKNOWN_OPTION if an unknown option was used
 * CURL_FORMADD_INCOMPLETE     if the some FormInfo is not complete (or error)
 * CURL_FORMADD_MEMORY         if an HttpPost struct cannot be allocated
 * CURL_FORMADD_MEMORY         if some allocation for string copying failed.
 * CURL_FORMADD_ILLEGAL_ARRAY  if an illegal option is used in an array
 *
 ***************************************************************************/

static CURLFORMcode FormAddCheck(struct FormInfo *first_form,
                                 struct curl_httppost **httppost,
                                 struct curl_httppost **last_post)
{
  const char *prevtype = NULL;
  struct FormInfo *form = NULL;
  struct curl_httppost *post = NULL;

  /* go through the list, check for completeness and if everything is
   * alright add the HttpPost item otherwise set retval accordingly */

  for(form = first_form;
      form != NULL;
      form = form->more) {
    if(((!form->name || !form->value) && !post) ||
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
      return CURL_FORMADD_INCOMPLETE;
    }
    if(((form->flags & HTTPPOST_FILENAME) ||
        (form->flags & HTTPPOST_BUFFER)) &&
       !form->contenttype) {
      char *f = (form->flags & HTTPPOST_BUFFER) ?
        form->showfilename : form->value;
      char const *type;
      type = Curl_mime_contenttype(f);
      if(!type)
        type = prevtype;
      if(!type)
        type = FILE_CONTENTTYPE_DEFAULT;

      /* our contenttype is missing */
      form->contenttype = strdup(type);
      if(!form->contenttype)
        return CURL_FORMADD_MEMORY;

      form->contenttype_alloc = TRUE;
    }
    if(form->name && form->namelength) {
      if(memchr(form->name, 0, form->namelength))
        return CURL_FORMADD_NULL;
    }
    if(!(form->flags & HTTPPOST_PTRNAME) && form->name) {
      /* Note that there is small risk that form->name is NULL here if the app
         passed in a bad combo, so we check for that. */

      /* copy name (without strdup; possibly not null-terminated) */
      char *dupname = Curl_memdup0(form->name, form->namelength ?
                                   form->namelength : strlen(form->name));
      if(!dupname)
        return CURL_FORMADD_MEMORY;

      form->name = dupname;
      form->name_alloc = TRUE;
    }
    if(!(form->flags & (HTTPPOST_FILENAME | HTTPPOST_READFILE |
                        HTTPPOST_PTRCONTENTS | HTTPPOST_PTRBUFFER |
                        HTTPPOST_CALLBACK)) && form->value) {
      /* copy value (without strdup; possibly contains null characters) */
      size_t clen  = (size_t) form->contentslength;
      if(!clen)
        clen = strlen(form->value) + 1;

      form->value = Curl_memdup(form->value, clen);

      if(!form->value)
        return CURL_FORMADD_MEMORY;

      form->value_alloc = TRUE;
    }
    post = AddHttpPost(form, post, httppost, last_post);

    if(!post)
      return CURL_FORMADD_MEMORY;

    if(form->contenttype)
      prevtype = form->contenttype;
  }

  return CURL_FORMADD_OK;
}

/* Shallow cleanup. Remove the newly created chain, the structs only and not
   the content they point to */
static void free_chain(struct curl_httppost *c)
{
  while(c) {
    struct curl_httppost *next = c->next;
    if(c->more)
      free_chain(c->more);
    free(c);
    c = next;
  }
}

static
CURLFORMcode FormAdd(struct curl_httppost **httppost,
                     struct curl_httppost **last_post,
                     va_list params)
{
  struct FormInfo *first_form, *curr, *form = NULL;
  CURLFORMcode retval = CURL_FORMADD_OK;
  CURLformoption option;
  struct curl_forms *forms = NULL;
  char *avalue = NULL;
  struct curl_httppost *newchain = NULL;
  struct curl_httppost *lastnode = NULL;

  /* This is a state variable, that if TRUE means that we are parsing an
     array that we got passed to us. If FALSE we are parsing the input
     va_list arguments. */
  bool array_state = FALSE;

  /*
   * We need to allocate the first struct to fill in.
   */
  first_form = calloc(1, sizeof(struct FormInfo));
  if(!first_form)
    return CURL_FORMADD_MEMORY;

  curr = first_form;

  /*
   * Loop through all the options set. Break if we have an error to report.
   */
  while(retval == CURL_FORMADD_OK) {

    /* first see if we have more parts of the array param */
    if(array_state && forms) {
      /* get the upcoming option from the given array */
      option = forms->option;
      avalue = (char *)CURL_UNCONST(forms->value);

      forms++; /* advance this to next entry */
      if(CURLFORM_END == option) {
        /* end of array state */
        array_state = FALSE;
        continue;
      }
    }
    else {
      /* This is not array-state, get next option. This gets an 'int' with
         va_arg() because CURLformoption might be a smaller type than int and
         might cause compiler warnings and wrong behavior. */
      option = (CURLformoption)va_arg(params, int);
      if(CURLFORM_END == option)
        break;
    }

    switch(option) {
    case CURLFORM_ARRAY:
      if(array_state)
        /* we do not support an array from within an array */
        retval = CURL_FORMADD_ILLEGAL_ARRAY;
      else {
        forms = va_arg(params, struct curl_forms *);
        if(forms)
          array_state = TRUE;
        else
          retval = CURL_FORMADD_NULL;
      }
      break;

      /*
       * Set the Name property.
       */
    case CURLFORM_PTRNAME:
      curr->flags |= HTTPPOST_PTRNAME; /* fall through */

      FALLTHROUGH();
    case CURLFORM_COPYNAME:
      if(curr->name)
        retval = CURL_FORMADD_OPTION_TWICE;
      else {
        if(!array_state)
          avalue = va_arg(params, char *);
        if(avalue)
          curr->name = avalue; /* store for the moment */
        else
          retval = CURL_FORMADD_NULL;
      }
      break;
    case CURLFORM_NAMELENGTH:
      if(curr->namelength)
        retval = CURL_FORMADD_OPTION_TWICE;
      else
        curr->namelength =
          array_state ? (size_t)avalue : (size_t)va_arg(params, long);
      break;

      /*
       * Set the contents property.
       */
    case CURLFORM_PTRCONTENTS:
      curr->flags |= HTTPPOST_PTRCONTENTS;
      FALLTHROUGH();
    case CURLFORM_COPYCONTENTS:
      if(curr->value)
        retval = CURL_FORMADD_OPTION_TWICE;
      else {
        if(!array_state)
          avalue = va_arg(params, char *);
        if(avalue)
          curr->value = avalue; /* store for the moment */
        else
          retval = CURL_FORMADD_NULL;
      }
      break;
    case CURLFORM_CONTENTSLENGTH:
      curr->contentslength =
        array_state ? (size_t)avalue : (size_t)va_arg(params, long);
      break;

    case CURLFORM_CONTENTLEN:
      curr->flags |= CURL_HTTPPOST_LARGE;
      curr->contentslength =
        array_state ? (curl_off_t)(size_t)avalue :
        va_arg(params, curl_off_t);
      break;

      /* Get contents from a given filename */
    case CURLFORM_FILECONTENT:
      if(curr->flags & (HTTPPOST_PTRCONTENTS|HTTPPOST_READFILE))
        retval = CURL_FORMADD_OPTION_TWICE;
      else {
        if(!array_state)
          avalue = va_arg(params, char *);
        if(avalue) {
          curr->value = strdup(avalue);
          if(!curr->value)
            retval = CURL_FORMADD_MEMORY;
          else {
            curr->flags |= HTTPPOST_READFILE;
            curr->value_alloc = TRUE;
          }
        }
        else
          retval = CURL_FORMADD_NULL;
      }
      break;

      /* We upload a file */
    case CURLFORM_FILE:
      if(!array_state)
        avalue = va_arg(params, char *);

      if(curr->value) {
        if(curr->flags & HTTPPOST_FILENAME) {
          if(avalue) {
            char *fname = strdup(avalue);
            if(!fname)
              retval = CURL_FORMADD_MEMORY;
            else {
              form = AddFormInfo(fname, NULL, curr);
              if(!form) {
                free(fname);
                retval = CURL_FORMADD_MEMORY;
              }
              else {
                form->value_alloc = TRUE;
                curr = form;
                form = NULL;
              }
            }
          }
          else
            retval = CURL_FORMADD_NULL;
        }
        else
          retval = CURL_FORMADD_OPTION_TWICE;
      }
      else {
        if(avalue) {
          curr->value = strdup(avalue);
          if(!curr->value)
            retval = CURL_FORMADD_MEMORY;
          else {
            curr->flags |= HTTPPOST_FILENAME;
            curr->value_alloc = TRUE;
          }
        }
        else
          retval = CURL_FORMADD_NULL;
      }
      break;

    case CURLFORM_BUFFERPTR:
      curr->flags |= HTTPPOST_PTRBUFFER|HTTPPOST_BUFFER;
      if(curr->buffer)
        retval = CURL_FORMADD_OPTION_TWICE;
      else {
        if(!array_state)
          avalue = va_arg(params, char *);
        if(avalue) {
          curr->buffer = avalue; /* store for the moment */
          curr->value = avalue; /* make it non-NULL to be accepted
                                           as fine */
        }
        else
          retval = CURL_FORMADD_NULL;
      }
      break;

    case CURLFORM_BUFFERLENGTH:
      if(curr->bufferlength)
        retval = CURL_FORMADD_OPTION_TWICE;
      else
        curr->bufferlength =
          array_state ? (size_t)avalue : (size_t)va_arg(params, long);
      break;

    case CURLFORM_STREAM:
      curr->flags |= HTTPPOST_CALLBACK;
      if(curr->userp)
        retval = CURL_FORMADD_OPTION_TWICE;
      else {
        if(!array_state)
          avalue  = va_arg(params, char *);
        if(avalue) {
          curr->userp = avalue;
          curr->value = avalue; /* this is not strictly true but we derive a
                                   value from this later on and we need this
                                   non-NULL to be accepted as a fine form
                                   part */
        }
        else
          retval = CURL_FORMADD_NULL;
      }
      break;

    case CURLFORM_CONTENTTYPE:
      if(!array_state)
        avalue = va_arg(params, char *);
      if(curr->contenttype) {
        if(curr->flags & HTTPPOST_FILENAME) {
          if(avalue) {
            char *type = strdup(avalue);
            if(!type)
              retval = CURL_FORMADD_MEMORY;
            else {
              form = AddFormInfo(NULL, type, curr);
              if(!form) {
                free(type);
                retval = CURL_FORMADD_MEMORY;
              }
              else {
                form->contenttype_alloc = TRUE;
                curr = form;
                form = NULL;
              }
            }
          }
          else
            retval = CURL_FORMADD_NULL;
        }
        else
          retval = CURL_FORMADD_OPTION_TWICE;
      }
      else {
        if(avalue) {
          curr->contenttype = strdup(avalue);
          if(!curr->contenttype)
            retval = CURL_FORMADD_MEMORY;
          else
            curr->contenttype_alloc = TRUE;
        }
        else
          retval = CURL_FORMADD_NULL;
      }
      break;

    case CURLFORM_CONTENTHEADER:
      {
        /* this "cast increases required alignment of target type" but
           we consider it OK anyway */
        struct curl_slist *list = array_state ?
          (struct curl_slist *)(void *)avalue :
          va_arg(params, struct curl_slist *);

        if(curr->contentheader)
          retval = CURL_FORMADD_OPTION_TWICE;
        else
          curr->contentheader = list;

        break;
      }
    case CURLFORM_FILENAME:
    case CURLFORM_BUFFER:
      if(!array_state)
        avalue = va_arg(params, char *);
      if(curr->showfilename)
        retval = CURL_FORMADD_OPTION_TWICE;
      else {
        curr->showfilename = strdup(avalue);
        if(!curr->showfilename)
          retval = CURL_FORMADD_MEMORY;
        else
          curr->showfilename_alloc = TRUE;
      }
      break;

    default:
      retval = CURL_FORMADD_UNKNOWN_OPTION;
      break;
    }
  }

  if(!retval)
    retval = FormAddCheck(first_form, &newchain, &lastnode);

  if(retval)
    /* On error, free allocated fields for all nodes of the FormInfo linked
       list without deallocating nodes. List nodes are deallocated later on */
    free_formlist(first_form);

  /* Always deallocate FormInfo linked list nodes without touching node
     fields given that these have either been deallocated or are owned
     now by the httppost linked list */
  while(first_form) {
    struct FormInfo *ptr = first_form->more;
    free(first_form);
    first_form = ptr;
  }

  if(!retval) {
    /* Only if all is fine, link the new chain into the provided list */
    if(*last_post)
      (*last_post)->next = newchain;
    else
      (*httppost) = newchain;

    (*last_post) = lastnode;
  }
  else
    free_chain(newchain);

  return retval;
}

/*
 * curl_formadd() is a public API to add a section to the multipart formpost.
 *
 * @unittest: 1308
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
 * curl_formget()
 * Serialize a curl_httppost struct.
 * Returns 0 on success.
 *
 * @unittest: 1308
 */
int curl_formget(struct curl_httppost *form, void *arg,
                 curl_formget_callback append)
{
  CURLcode result;
  curl_mimepart toppart;

  Curl_mime_initpart(&toppart); /* default form is empty */
  result = Curl_getformdata(NULL, &toppart, form, NULL);
  if(!result)
    result = Curl_mime_prepare_headers(NULL, &toppart, "multipart/form-data",
                                       NULL, MIMESTRATEGY_FORM);

  while(!result) {
    char buffer[8192];
    size_t nread = Curl_mime_read(buffer, 1, sizeof(buffer), &toppart);

    if(!nread)
      break;

    if(nread > sizeof(buffer) || append(arg, buffer, nread) != nread) {
      result = CURLE_READ_ERROR;
      if(nread == CURL_READFUNC_ABORT)
        result = CURLE_ABORTED_BY_CALLBACK;
    }
  }

  Curl_mime_cleanpart(&toppart);
  return (int) result;
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
    next = form->next;  /* the following form line */

    /* recurse to sub-contents */
    curl_formfree(form->more);

    if(!(form->flags & HTTPPOST_PTRNAME))
      free(form->name); /* free the name */
    if(!(form->flags &
         (HTTPPOST_PTRCONTENTS|HTTPPOST_BUFFER|HTTPPOST_CALLBACK))
      )
      free(form->contents); /* free the contents */
    free(form->contenttype); /* free the content type */
    free(form->showfilename); /* free the faked filename */
    free(form);       /* free the struct */
    form = next;
  } while(form); /* continue */
}


/* Set mime part name, taking care of non null-terminated name string. */
static CURLcode setname(curl_mimepart *part, const char *name, size_t len)
{
  char *zname;
  CURLcode res;

  if(!name || !len)
    return curl_mime_name(part, name);
  zname = Curl_memdup0(name, len);
  if(!zname)
    return CURLE_OUT_OF_MEMORY;
  res = curl_mime_name(part, zname);
  free(zname);
  return res;
}

/* wrap call to fseeko so it matches the calling convention of callback */
static int fseeko_wrapper(void *stream, curl_off_t offset, int whence)
{
#if defined(_WIN32) && defined(USE_WIN32_LARGE_FILES)
  return _fseeki64(stream, (__int64)offset, whence);
#elif defined(HAVE_FSEEKO) && defined(HAVE_DECL_FSEEKO)
  return fseeko(stream, (off_t)offset, whence);
#else
  if(offset > LONG_MAX)
    return -1;
  return fseek(stream, (long)offset, whence);
#endif
}

/*
 * Curl_getformdata() converts a linked list of "meta data" into a mime
 * structure. The input list is in 'post', while the output is stored in
 * mime part at '*finalform'.
 *
 * This function will not do a failf() for the potential memory failures but
 * should for all other errors it spots. Just note that this function MAY get
 * a NULL pointer in the 'data' argument.
 */

CURLcode Curl_getformdata(CURL *data,
                          curl_mimepart *finalform,
                          struct curl_httppost *post,
                          curl_read_callback fread_func)
{
  CURLcode result = CURLE_OK;
  curl_mime *form = NULL;
  curl_mimepart *part;
  struct curl_httppost *file;

  Curl_mime_cleanpart(finalform); /* default form is empty */

  if(!post)
    return result; /* no input => no output! */

  form = curl_mime_init(data);
  if(!form)
    result = CURLE_OUT_OF_MEMORY;

  if(!result)
    result = curl_mime_subparts(finalform, form);

  /* Process each top part. */
  for(; !result && post; post = post->next) {
    /* If we have more than a file here, create a mime subpart and fill it. */
    curl_mime *multipart = form;
    if(post->more) {
      part = curl_mime_addpart(form);
      if(!part)
        result = CURLE_OUT_OF_MEMORY;
      if(!result)
        result = setname(part, post->name, post->namelength);
      if(!result) {
        multipart = curl_mime_init(data);
        if(!multipart)
          result = CURLE_OUT_OF_MEMORY;
      }
      if(!result)
        result = curl_mime_subparts(part, multipart);
    }

    /* Generate all the part contents. */
    for(file = post; !result && file; file = file->more) {
      /* Create the part. */
      part = curl_mime_addpart(multipart);
      if(!part)
        result = CURLE_OUT_OF_MEMORY;

      /* Set the headers. */
      if(!result)
        result = curl_mime_headers(part, file->contentheader, 0);

      /* Set the content type. */
      if(!result && file->contenttype)
        result = curl_mime_type(part, file->contenttype);

      /* Set field name. */
      if(!result && !post->more)
        result = setname(part, post->name, post->namelength);

      /* Process contents. */
      if(!result) {
        curl_off_t clen = post->contentslength;

        if(post->flags & CURL_HTTPPOST_LARGE)
          clen = post->contentlen;

        if(post->flags & (HTTPPOST_FILENAME | HTTPPOST_READFILE)) {
          if(!strcmp(file->contents, "-")) {
            /* There are a few cases where the code below will not work; in
               particular, freopen(stdin) by the caller is not guaranteed
               to result as expected. This feature has been kept for backward
               compatibility: use of "-" pseudo filename should be avoided. */
#if defined(__clang__) && __clang_major__ >= 16
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wcast-function-type-strict"
#endif
            result = curl_mime_data_cb(part, (curl_off_t) -1,
                                       (curl_read_callback) fread,
                                       fseeko_wrapper,
                                       NULL, (void *) stdin);
#if defined(__clang__) && __clang_major__ >= 16
#pragma clang diagnostic pop
#endif
          }
          else
            result = curl_mime_filedata(part, file->contents);
          if(!result && (post->flags & HTTPPOST_READFILE))
            result = curl_mime_filename(part, NULL);
        }
        else if(post->flags & HTTPPOST_BUFFER)
          result = curl_mime_data(part, post->buffer,
                                  post->bufferlength ?
                                  post->bufferlength : -1);
        else if(post->flags & HTTPPOST_CALLBACK) {
          /* the contents should be read with the callback and the size is set
             with the contentslength */
          if(!clen)
            clen = -1;
          result = curl_mime_data_cb(part, clen,
                                     fread_func, NULL, NULL, post->userp);
        }
        else {
          size_t uclen;
          if(!clen)
            uclen = CURL_ZERO_TERMINATED;
          else
            uclen = (size_t)clen;
          result = curl_mime_data(part, post->contents, uclen);
        }
      }

      /* Set fake filename. */
      if(!result && post->showfilename)
        if(post->more || (post->flags & (HTTPPOST_FILENAME | HTTPPOST_BUFFER |
                                        HTTPPOST_CALLBACK)))
          result = curl_mime_filename(part, post->showfilename);
    }
  }

  if(result)
    Curl_mime_cleanpart(finalform);

  return result;
}

#else
/* if disabled */
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
  (void)form;
  (void)arg;
  (void)append;
  return CURL_FORMADD_DISABLED;
}

void curl_formfree(struct curl_httppost *form)
{
  (void)form;
  /* Nothing to do. */
}

#endif  /* if disabled */
