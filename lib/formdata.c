/*****************************************************************************
 *                                  _   _ ____  _     
 *  Project                     ___| | | |  _ \| |    
 *                             / __| | | | |_) | |    
 *                            | (__| |_| |  _ <| |___ 
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2000, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * In order to be useful for every potential user, curl and libcurl are
 * dual-licensed under the MPL and the MIT/X-derivate licenses.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the MPL or the MIT/X-derivate
 * licenses. You may pick one of these licenses.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 * $Id$
 *****************************************************************************/

/*
  Debug the form generator stand-alone by compiling this source file with:

  gcc -DHAVE_CONFIG_H -I../ -g -D_FORM_DEBUG -o formdata -I../include formdata.c strequal.c

  run the 'formdata' executable the output should end with:
  All Tests seem to have worked ...
  and the following parts should be there:

Content-Disposition: form-data; name="simple_COPYCONTENTS"
value for simple COPYCONTENTS

Content-Disposition: form-data; name="COPYCONTENTS_+_CONTENTTYPE"
Content-Type: image/gif
value for COPYCONTENTS + CONTENTTYPE

Content-Disposition: form-data; name="simple_PTRCONTENTS"
value for simple PTRCONTENTS

Content-Disposition: form-data; name="PTRCONTENTS_+_CONTENTSLENGTH"
vlue for PTRCONTENTS + CONTENTSLENGTH
(or you might see v^@lue at the start)

Content-Disposition: form-data; name="PTRCONTENTS_+_CONTENTSLENGTH_+_CONTENTTYPE"
Content-Type: text/plain
vlue for PTRCOTNENTS + CONTENTSLENGTH + CONTENTTYPE

Content-Disposition: form-data; name="FILE1_+_CONTENTTYPE"; filename="inet_ntoa_r.h"
Content-Type: text/html
...

Content-Disposition: form-data; name="FILE1_+_FILE2"
Content-Type: multipart/mixed, boundary=curlz1s0dkticx49MV1KGcYP5cvfSsz
Content-Disposition: attachment; filename="inet_ntoa_r.h"
Content-Type: text/plain
...
Content-Disposition: attachment; filename="Makefile.b32.resp"
Content-Type: text/plain
...

  For the old FormParse used by curl_formparse use:

  gcc -DHAVE_CONFIG_H -I../ -g -D_OLD_FORM_DEBUG -o formdata -I../include formdata.c strequal.c

  run the 'formdata' executable and make sure the output is ok!

  try './formdata "name=Daniel" "poo=noo" "foo=bar"' and similarly

 */

#include "setup.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

#include <time.h>

#include <curl/curl.h>
#include "formdata.h"

#include "strequal.h"

/* The last #include file should be: */
#ifdef MALLOCDEBUG
#include "memdebug.h"
#endif

/* Length of the random boundary string. The risk of this being used
   in binary data is very close to zero, 64^32 makes
   6277101735386680763835789423207666416102355444464034512896
   combinations... */
#define BOUNDARY_LENGTH 32

/* What kind of Content-Type to use on un-specified files with unrecognized
   extensions. */
#define HTTPPOST_CONTENTTYPE_DEFAULT "text/plain"

/* This is a silly duplicate of the function in main.c to enable this source
   to compile stand-alone for better debugging */
static void GetStr(char **string,
		   const char *value)
{
  if(*string)
    free(*string);
  *string = strdup(value);
}

/***************************************************************************
 *
 * FormParse()
 *	
 * Reads a 'name=value' paramter and builds the appropriate linked list.
 *
 * Specify files to upload with 'name=@filename'. Supports specified
 * given Content-Type of the files. Such as ';type=<content-type>'.
 *
 * You may specify more than one file for a single name (field). Specify
 * multiple files by writing it like:
 *
 * 'name=@filename,filename2,filename3'
 *
 * If you want content-types specified for each too, write them like:
 *
 * 'name=@filename;type=image/gif,filename2,filename3'
 *
 ***************************************************************************/

#define FORM_FILE_SEPARATOR ','
#define FORM_TYPE_SEPARATOR ';'

static
int FormParse(char *input,
	      struct HttpPost **httppost,
	      struct HttpPost **last_post)
{
  /* nextarg MUST be a string in the format 'name=contents' and we'll
     build a linked list with the info */
  char name[256];
  char *contents;
  char major[128];
  char minor[128];
  long flags = 0;
  char *contp;
  const char *type = NULL;
  char *prevtype = NULL;
  char *sep;
  char *sep2;
  struct HttpPost *post;
  struct HttpPost *subpost; /* a sub-node */
  unsigned int i;

  /* Preallocate contents to the length of input to make sure we don't
     overwrite anything. */
  contents = malloc(strlen(input));
  contents[0] = '\000';
 
  if(1 <= sscanf(input, "%255[^=]=%[^\n]", name, contents)) {
    /* the input was using the correct format */
    contp = contents;

    if('@' == contp[0]) {
      /* we use the @-letter to indicate file name(s) */
      
      flags = HTTPPOST_FILENAME;
      contp++;

      post=NULL;

      do {
	/* since this was a file, it may have a content-type specifier
	   at the end too */

	sep=strchr(contp, FORM_TYPE_SEPARATOR);
	sep2=strchr(contp, FORM_FILE_SEPARATOR);

	/* pick the closest */
	if(sep2 && (sep2 < sep)) {
	  sep = sep2;

	  /* no type was specified! */
	}
	if(sep) {

	  /* if we got here on a comma, don't do much */
	  if(FORM_FILE_SEPARATOR != *sep)
	    type = strstr(sep+1, "type=");
	  else
	    type=NULL;

	  *sep=0; /* terminate file name at separator */

	  if(type) {
	    type += strlen("type=");
	    
	    if(2 != sscanf(type, "%127[^/]/%127[^,\n]",
			   major, minor)) {
	      fprintf(stderr, "Illegally formatted content-type field!\n");
              free(contents);
	      return 2; /* illegal content-type syntax! */
	    }
	    /* now point beyond the content-type specifier */
	    sep = (char *)type + strlen(major)+strlen(minor)+1;

	    /* find the following comma */
	    sep=strchr(sep, FORM_FILE_SEPARATOR);
	  }
	}
	else {
	  type=NULL;
	  sep=strchr(contp, FORM_FILE_SEPARATOR);
	}
	if(sep) {
	  /* the next file name starts here */
	  *sep =0;
	  sep++;
	}
	if(!type) {
	  /*
	   * No type was specified, we scan through a few well-known
	   * extensions and pick the first we match!
	   */
	  struct ContentType {
	    const char *extension;
	    const char *type;
	  };
          static struct ContentType ctts[]={
	    {".gif",  "image/gif"},
	    {".jpg",  "image/jpeg"},
	    {".jpeg", "image/jpeg"},
	    {".txt",  "text/plain"},
	    {".html", "text/plain"}
	  };

	  if(prevtype)
	    /* default to the previously set/used! */
	    type = prevtype;
	  else
	    /* It seems RFC1867 defines no Content-Type to default to
	       text/plain so we don't actually need to set this: */
	    type = HTTPPOST_CONTENTTYPE_DEFAULT;

	  for(i=0; i<sizeof(ctts)/sizeof(ctts[0]); i++) {
	    if(strlen(contp) >= strlen(ctts[i].extension)) {
	      if(strequal(contp +
			  strlen(contp) - strlen(ctts[i].extension),
			  ctts[i].extension)) {
		type = ctts[i].type;
		break;
	      }	      
	    }
	  }
	  /* we have a type by now */
	}

	if(NULL == post) {
	  /* For the first file name, we allocate and initiate the main list
	     node */

	  post = (struct HttpPost *)malloc(sizeof(struct HttpPost));
	  if(post) {
	    memset(post, 0, sizeof(struct HttpPost));
	    GetStr(&post->name, name);      /* get the name */
	    GetStr(&post->contents, contp); /* get the contents */
            post->contentslength = 0;
	    post->flags = flags;
	    if(type) {
	      GetStr(&post->contenttype, (char *)type); /* get type */
	      prevtype=post->contenttype; /* point to the allocated string! */
	    }
	    /* make the previous point to this */
	    if(*last_post)
	      (*last_post)->next = post;
	    else
	      (*httppost) = post;

	    (*last_post) = post;	  
	  }

	}
	else {
	  /* we add a file name to the previously allocated node, known as
             'post' now */
	  subpost =(struct HttpPost *)malloc(sizeof(struct HttpPost));
	  if(subpost) {
	     memset(subpost, 0, sizeof(struct HttpPost));
	     GetStr(&subpost->name, name);      /* get the name */
	     GetStr(&subpost->contents, contp); /* get the contents */
             subpost->contentslength = 0;
	     subpost->flags = flags;
	     if(type) {
	       GetStr(&subpost->contenttype, (char *)type); /* get type */
	       prevtype=subpost->contenttype; /* point to allocated string! */
	     }
	     /* now, point our 'more' to the original 'more' */
	     subpost->more = post->more;

	     /* then move the original 'more' to point to ourselves */
	     post->more = subpost;	     
	  }
	}
	contp = sep; /* move the contents pointer to after the separator */
      } while(sep && *sep); /* loop if there's another file name */
    }
    else {
      post = (struct HttpPost *)malloc(sizeof(struct HttpPost));
      if(post) {
	memset(post, 0, sizeof(struct HttpPost));
	GetStr(&post->name, name);      /* get the name */
	if( contp[0]=='<' ) {
	  GetStr(&post->contents, contp+1); /* get the contents */
          post->contentslength = 0;
	  post->flags = HTTPPOST_READFILE;
	}
	else {
	  GetStr(&post->contents, contp); /* get the contents */
          post->contentslength = 0;
	  post->flags = 0;
	}

	/* make the previous point to this */
	if(*last_post)
	  (*last_post)->next = post;
	else
	  (*httppost) = post;

	(*last_post) = post;	  
      }

    }

  }
  else {
    fprintf(stderr, "Illegally formatted input field!\n");
    free(contents);
    return 1;
  }
  free(contents);
  return 0;
}

int curl_formparse(char *input,
                   struct HttpPost **httppost,
                   struct HttpPost **last_post)
{
  return FormParse(input, httppost, last_post);
}

/***************************************************************************
 *
 * AddHttpPost()
 *	
 * Adds a HttpPost structure to the list, if parent_post is given becomes
 * a subpost of parent_post instead of a direct list element.
 *
 * Returns 0 on success and 1 if malloc failed.
 *
 ***************************************************************************/
static struct HttpPost * AddHttpPost (char * name,
                                      char * value,
                                      long contentslength,
                                      long flags,
                                      struct HttpPost *parent_post,
                                      struct HttpPost **httppost,
                                      struct HttpPost **last_post)
{
  struct HttpPost *post;
  post = (struct HttpPost *)malloc(sizeof(struct HttpPost));
  if(post) {
    memset(post, 0, sizeof(struct HttpPost));
    post->name = name;
    post->contents = value;
    post->contentslength = contentslength;
    post->flags = flags;
  }
  else
    return NULL;
  
  if (parent_post) {
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
 * FormAdd()
 *	
 * Stores a 'name=value' formpost parameter and builds the appropriate
 * linked list.
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
 * CURLFORM_COPYCONTENTS, "value");
 *
 * name/value pair where only the content pointer is remembered:
 * curl_formadd (&post, &last, CURLFORM_COPYNAME, "name",
 * CURLFORM_PTRCONTENTS, ptr, CURLFORM_CONTENTSLENGTH, 10);
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
 * Returns 0 on success, 1 if the first option is not CURLFORM_COPYNAME,
 * 2 if AddHttpPost failes, and 3 if an unknown option is encountered
 *
 ***************************************************************************/

static
int FormAdd(struct HttpPost **httppost,
            struct HttpPost **last_post,
            va_list params)
{
  int go_on = TRUE;
  int read_argument = TRUE;
  unsigned int i;
  char *name;
  char *value;
  const char *prevtype = NULL;
  struct HttpPost *post = NULL;
  CURLformoption next_option;

  /* We always expect CURLFORM_COPYNAME first for the moment. */
  next_option = va_arg(params, CURLformoption);
  if (next_option != CURLFORM_COPYNAME)
    return 1;

  name = va_arg(params, char *);
  do
  {
    /* if not already read read next argument */
    if (read_argument)
      next_option = va_arg(params, CURLformoption);
    else
      read_argument = TRUE;
      
    switch (next_option)
    {
      case CURLFORM_COPYCONTENTS:
      { /* simple name/value storage of duplicated data */
        const char * contenttype = NULL;
        value = va_arg(params, char *);
        next_option = va_arg(params, CURLformoption);
        if (next_option == CURLFORM_CONTENTTYPE)
          contenttype = va_arg(params, char *);
        else
          read_argument = FALSE;
        if ((post = AddHttpPost(strdup(name), strdup(value), 0, 0, NULL,
                                httppost, last_post)) == NULL) {
          return 2;
        }
        if (contenttype)
          post->contenttype = strdup(contenttype);
        /* at the moment no more options are allowd in this case */
        go_on = FALSE;
        break;
      }
      case CURLFORM_PTRCONTENTS:
      { /* name/value storage with value stored as a pointer */
        const char * contenttype = NULL;
        void * ptr_contents = va_arg(params, void *);
        long contentslength;
        int got_contentslength = FALSE;
        /* either use provided length or use strlen () to get it */
        next_option = va_arg(params, CURLformoption);
        while ( (next_option == CURLFORM_CONTENTSLENGTH) ||
                (next_option == CURLFORM_CONTENTTYPE) ) {
          if (next_option == CURLFORM_CONTENTSLENGTH) {
            contentslength = va_arg(params, long);
            got_contentslength = TRUE;
          }
          else { /* CURLFORM_CONTENTTYPE */
            contenttype = va_arg(params, char *);
          }
          next_option = va_arg(params, CURLformoption);
        };
        /* we already read the next CURLformoption */
        read_argument = FALSE;
        if (!got_contentslength)
          /* no length given, use strlen to find out */
          contentslength = strlen (ptr_contents);
        if ((post = AddHttpPost(strdup(name), ptr_contents, contentslength,
                                HTTPPOST_PTRCONTENTS, NULL, httppost,
                                last_post))
            == NULL) {
          return 2;
        }
        if (contenttype)
          post->contenttype = strdup(contenttype);
        /* at the moment no more options are allowd in this case */
        go_on = FALSE;
        break;
      }
      case CURLFORM_FILE:
      {
        const char * contenttype = NULL;
        value = va_arg(params, char *);
        next_option = va_arg(params, CURLformoption);
        /* if contenttype was provided retrieve it */
        if (next_option == CURLFORM_CONTENTTYPE) {
          contenttype = va_arg(params, char *);
        }
        else {
	  /*
	   * No type was specified, we scan through a few well-known
	   * extensions and pick the first we match!
	   */
	  struct ContentType {
	    const char *extension;
	    const char *type;
	  };
          static struct ContentType ctts[]={
	    {".gif",  "image/gif"},
	    {".jpg",  "image/jpeg"},
	    {".jpeg", "image/jpeg"},
	    {".txt",  "text/plain"},
	    {".html", "text/plain"}
	  };

	  if(prevtype)
	    /* default to the previously set/used! */
	    contenttype = prevtype;
	  else
	    /* It seems RFC1867 defines no Content-Type to default to
	       text/plain so we don't actually need to set this: */
	    contenttype = HTTPPOST_CONTENTTYPE_DEFAULT;

	  for(i=0; i<sizeof(ctts)/sizeof(ctts[0]); i++) {
	    if(strlen(value) >= strlen(ctts[i].extension)) {
	      if(strequal(value +
			  strlen(value) - strlen(ctts[i].extension),
			  ctts[i].extension)) {
		contenttype = ctts[i].type;
		break;
	      }	      
	    }
	  }
	  /* we have a contenttype by now */
          /* do not try to read the next option we already did that */
          read_argument = FALSE;
        }
        if ( (post = AddHttpPost (strdup(name), strdup(value), 0,
                                  HTTPPOST_FILENAME, post, httppost,
                                  last_post)) == NULL) {
          return 2;
        }
        post->contenttype = strdup (contenttype);
        prevtype = post->contenttype;
        /* we do not set go_on to false as multiple files are allowed */
        break;
      }
      case CURLFORM_END:
        /* this ends our loop */
        break;
      default:
        fprintf (stderr, "got: %d\n", next_option);
        return 3;
    };

  } while (go_on && next_option != CURLFORM_END);

  return 0;
}

int curl_formadd(struct HttpPost **httppost,
                 struct HttpPost **last_post,
                 ...)
{
  va_list arg;
  int result;
  va_start(arg, last_post);
  result = FormAdd(httppost, last_post, arg);
  va_end(arg);
  return result;
}

static int AddFormData(struct FormData **formp,
                       const void *line,
                       long length)
{
  struct FormData *newform = (struct FormData *)
    malloc(sizeof(struct FormData));
  newform->next = NULL;

  /* we make it easier for plain strings: */
  if(!length)
    length = strlen((char *)line);

  newform->line = (char *)malloc(length+1);
  memcpy(newform->line, line, length+1);
  newform->length = length;
  newform->line[length]=0; /* zero terminate for easier debugging */
  
  if(*formp) {
    (*formp)->next = newform;
    *formp = newform;
  }
  else
    *formp = newform;

  return length;
}


static int AddFormDataf(struct FormData **formp,
                        const char *fmt, ...)
{
  char s[4096];
  va_list ap;
  va_start(ap, fmt);
  vsprintf(s, fmt, ap);
  va_end(ap);

  return AddFormData(formp, s, 0);
}


char *Curl_FormBoundary(void)
{
  char *retstring;
  static int randomizer=0; /* this is just so that two boundaries within
			      the same form won't be identical */
  int i;

  static char table64[]=
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

  retstring = (char *)malloc(BOUNDARY_LENGTH);

  if(!retstring)
    return NULL; /* failed */

  srand(time(NULL)+randomizer++); /* seed */

  strcpy(retstring, "curl"); /* bonus commercials 8*) */

  for(i=4; i<(BOUNDARY_LENGTH-1); i++) {
    retstring[i] = table64[rand()%64];
  }
  retstring[BOUNDARY_LENGTH-1]=0; /* zero terminate */

  return retstring;
}

/* Used from http.c, this cleans a built FormData linked list */ 
void Curl_formclean(struct FormData *form)
{
  struct FormData *next;

  do {
    next=form->next;  /* the following form line */
    free(form->line); /* free the line */
    free(form);       /* free the struct */
  
  } while((form=next)); /* continue */
}

/* external function to free up a whole form post chain */
void curl_formfree(struct HttpPost *form)
{
  struct HttpPost *next;

  if(!form)
    /* no form to free, just get out of this */
    return;

  do {
    next=form->next;  /* the following form line */

    /* recurse to sub-contents */
    if(form->more)
      curl_formfree(form->more);

    if(form->name)
      free(form->name); /* free the name */
    if( !(form->flags & HTTPPOST_PTRCONTENTS) && form->contents)
      free(form->contents); /* free the contents */
    if(form->contenttype)
      free(form->contenttype); /* free the content type */
    free(form);       /* free the struct */

  } while((form=next)); /* continue */
}

struct FormData *Curl_getFormData(struct HttpPost *post,
                                  int *sizep)
{
  struct FormData *form = NULL;
  struct FormData *firstform;

  struct HttpPost *file;

  int size =0;
  char *boundary;
  char *fileboundary=NULL;

  if(!post)
    return NULL; /* no input => no output! */

  boundary = Curl_FormBoundary();
  
  /* Make the first line of the output */
  AddFormDataf(&form,
               "Content-Type: multipart/form-data;"
               " boundary=%s\r\n",
               boundary);
  /* we DO NOT count that line since that'll be part of the header! */

  firstform = form;
  
  do {

    /* boundary */
    size += AddFormDataf(&form, "\r\n--%s\r\n", boundary);

    size += AddFormDataf(&form,
			 "Content-Disposition: form-data; name=\"%s\"",
			 post->name);

    if(post->more) {
      /* If used, this is a link to more file names, we must then do
         the magic to include several files with the same field name */

      fileboundary = Curl_FormBoundary();

      size += AddFormDataf(&form,
			   "\r\nContent-Type: multipart/mixed,"
			   " boundary=%s\r\n",
			   fileboundary);
    }

    file = post;

    do {
      if(post->more) {
	/* if multiple-file */
	size += AddFormDataf(&form,
			     "\r\n--%s\r\nContent-Disposition: attachment; filename=\"%s\"",
			     fileboundary, file->contents);
      }
      else if(post->flags & HTTPPOST_FILENAME) {
	size += AddFormDataf(&form,
			     "; filename=\"%s\"",
			     post->contents);
      }
      
      if(file->contenttype) {
	/* we have a specified type */
	size += AddFormDataf(&form,
			     "\r\nContent-Type: %s",
			     file->contenttype);
      }

#if 0
      /* The header Content-Transfer-Encoding: seems to confuse some receivers
       * (like the built-in PHP engine). While I can't see any reason why it
       * should, I can just as well skip this to the benefit of the users who
       * are using such confused receivers.
       */
      
      if(file->contenttype &&
	 !strnequal("text/", file->contenttype, 5)) {
	/* this is not a text content, mention our binary encoding */
	size += AddFormData(&form, "\r\nContent-Transfer-Encoding: binary", 0);
      }
#endif

      size += AddFormData(&form, "\r\n\r\n", 0);

      if((post->flags & HTTPPOST_FILENAME) ||
	 (post->flags & HTTPPOST_READFILE)) {
	/* we should include the contents from the specified file */
	FILE *fileread;
	char buffer[1024];
	int nread;

	fileread = strequal("-", file->contents)?stdin:
          /* binary read for win32 crap */
/*VMS??*/ fopen(file->contents, "rb");  /* ONLY ALLOWS FOR STREAM FILES ON VMS */
/*VMS?? Stream files are OK, as are FIXED & VAR files WITHOUT implied CC */
/*VMS?? For implied CC, every record needs to have a \n appended & 1 added to SIZE */
	if(fileread) {
	  while((nread = fread(buffer, 1, 1024, fileread))) {
	    size += AddFormData(&form,
				buffer,
				nread);
	  }
          if(fileread != stdin)
            fclose(fileread);
	} else {
	  size += AddFormData(&form, "[File wasn't found by client]", 0);
	}
      } else {
	/* include the contents we got */
	size += AddFormData(&form, post->contents, post->contentslength);
      }
    } while((file = file->more)); /* for each specified file for this field */

    if(post->more) {
      /* this was a multiple-file inclusion, make a termination file
         boundary: */
      size += AddFormDataf(&form,
			   "\r\n--%s--",
			   fileboundary);     
      free(fileboundary);
    }

  } while((post=post->next)); /* for each field */

  /* end-boundary for everything */
  size += AddFormDataf(&form,
		       "\r\n--%s--\r\n",
		       boundary);

  *sizep = size;

  free(boundary);

  return firstform;
}

int Curl_FormInit(struct Form *form, struct FormData *formdata )
{
  if(!formdata)
    return 1; /* error */

  form->data = formdata;
  form->sent = 0;

  return 0;
}

/* fread() emulation */
int Curl_FormReader(char *buffer,
                    size_t size,
                    size_t nitems,
                    FILE *mydata)
{
  struct Form *form;
  int wantedsize;
  int gotsize = 0;

  form=(struct Form *)mydata;

  wantedsize = size * nitems;

  if(!form->data)
    return -1; /* nothing, error, empty */

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

  } while(form->data);
  /* If we got an empty line and we have more data, we proceed to the next
     line immediately to avoid returning zero before we've reached the end.
     This is the bug reported November 22 1999 on curl 6.3. (Daniel) */

  return gotsize;
}

/* possible (old) fread() emulation that copies at most one line */
int Curl_FormReadOneLine(char *buffer,
                         size_t size,
                         size_t nitems,
                         FILE *mydata)
{
  struct Form *form;
  int wantedsize;
  int gotsize;

  form=(struct Form *)mydata;

  wantedsize = size * nitems;

  if(!form->data)
    return -1; /* nothing, error, empty */

  do {
  
    if( (form->data->length - form->sent ) > wantedsize ) {

      memcpy(buffer, form->data->line + form->sent, wantedsize);

      form->sent += wantedsize;

      return wantedsize;
    }

    memcpy(buffer,
           form->data->line + form->sent,
           gotsize = (form->data->length - form->sent) );

    form->sent = 0;

    form->data = form->data->next; /* advance */

  } while(!gotsize && form->data);
  /* If we got an empty line and we have more data, we proceed to the next
     line immediately to avoid returning zero before we've reached the end.
     This is the bug reported November 22 1999 on curl 6.3. (Daniel) */

  return gotsize;
}


#ifdef _FORM_DEBUG
int FormAddTest(const char * errormsg,
                 struct HttpPost **httppost,
                 struct HttpPost **last_post,
                 ...)
{
  int result;
  va_list arg;
  CURLformoption next_option;
  char * value;
  va_start(arg, last_post);
  if ((result = FormAdd(httppost, last_post, arg)))
    fprintf (stderr, "ERROR doing FormAdd ret: %d action: %s\n", result,
             errormsg);
  va_end(arg);
  return result;
}


int main()
{
  char name1[] = "simple_COPYCONTENTS";
  char name2[] = "COPYCONTENTS_+_CONTENTTYPE";
  char name3[] = "simple_PTRCONTENTS";
  char name4[] = "PTRCONTENTS_+_CONTENTSLENGTH";
  char name5[] = "PTRCONTENTS_+_CONTENTSLENGTH_+_CONTENTTYPE";
  char name6[] = "FILE1_+_CONTENTTYPE";
  char name7[] = "FILE1_+_FILE2";
  char value1[] = "value for simple COPYCONTENTS";
  char value2[] = "value for COPYCONTENTS + CONTENTTYPE";
  char value3[] = "value for simple PTRCONTENTS";
  char value4[] = "value for PTRCONTENTS + CONTENTSLENGTH";
  char value5[] = "value for PTRCOTNENTS + CONTENTSLENGTH + CONTENTTYPE";
  char value6[] = "inet_ntoa_r.h";
  char value7[] = "Makefile.b32.resp";
  char type2[] = "image/gif";
  char type5[] = "text/plain";
  char type6[] = "text/html";
  int value4length = strlen(value4);
  int value5length = strlen(value5);
  int errors = 0;
  int size;
  int nread;
  char buffer[4096];
  struct HttpPost *httppost=NULL;
  struct HttpPost *last_post=NULL;
  struct HttpPost *post;

  struct FormData *form;
  struct Form formread;

  if (FormAddTest("simple COPYCONTENTS test", &httppost, &last_post,
                  CURLFORM_COPYNAME, name1, CURLFORM_COPYCONTENTS, value1,
                  CURLFORM_END))
    ++errors;
  if (FormAddTest("COPYCONTENTS  + CONTENTTYPE test", &httppost, &last_post,
                  CURLFORM_COPYNAME, name2, CURLFORM_COPYCONTENTS, value2,
                  CURLFORM_CONTENTTYPE, type2, CURLFORM_END))
    ++errors;
  if (FormAddTest("simple PTRCONTENTS test", &httppost, &last_post,
                  CURLFORM_COPYNAME, name3, CURLFORM_PTRCONTENTS, value3,
                  CURLFORM_END))
    ++errors;
  /* make null character at start to check that contentslength works
     correctly */
  value4[1] = '\0';
  if (FormAddTest("PTRCONTENTS + CONTENTSLENGTH test", &httppost, &last_post,
                  CURLFORM_COPYNAME, name4, CURLFORM_PTRCONTENTS, value4,
                  CURLFORM_CONTENTSLENGTH, value4length, CURLFORM_END))
    ++errors;
  /* make null character at start to check that contentslength works
     correctly */
  value5[1] = '\0';
  if (FormAddTest("PTRCONTENTS + CONTENTSLENGTH + CONTENTTYPE test",
                  &httppost, &last_post,
                  CURLFORM_COPYNAME, name5, CURLFORM_PTRCONTENTS, value5,
                  CURLFORM_CONTENTSLENGTH, value5length,
                  CURLFORM_CONTENTTYPE, type5, CURLFORM_END))
    ++errors;
  if (FormAddTest("FILE + CONTENTTYPE test", &httppost, &last_post,
                  CURLFORM_COPYNAME, name6, CURLFORM_FILE, value6,
                  CURLFORM_CONTENTTYPE, type6, CURLFORM_END))
    ++errors;
  if (FormAddTest("FILE1 + FILE2 test", &httppost, &last_post,
                  CURLFORM_COPYNAME, name7, CURLFORM_FILE, value6,
                  CURLFORM_FILE, value7, CURLFORM_END))
    ++errors;

  form=Curl_getFormData(httppost, &size);

  Curl_FormInit(&formread, form);

  do {
    nread = Curl_FormReader(buffer, 1, sizeof(buffer),
                            (FILE *)&formread);

    if(-1 == nread)
      break;
    fwrite(buffer, nread, 1, stderr);
  } while(1);

  fprintf(stderr, "size: %d\n", size);
  if (errors)
    fprintf(stderr, "\n==> %d Test(s) failed!\n", errors);
  else
    fprintf(stdout, "\nAll Tests seem to have worked (please check output)\n");

  return 0;
}

#endif

#ifdef _OLD_FORM_DEBUG

int main(int argc, char **argv)
{
#if 0
  char *testargs[]={
    "name1 = data in number one",
    "name2 = number two data",
    "test = @upload"
  };
#endif
  int i;
  char *nextarg;
  struct HttpPost *httppost=NULL;
  struct HttpPost *last_post=NULL;
  struct HttpPost *post;
  int size;
  int nread;
  char buffer[4096];

  struct FormData *form;
  struct Form formread;

  for(i=1; i<argc; i++) {

    if( FormParse( argv[i],
		   &httppost,
		   &last_post)) {
      fprintf(stderr, "Illegally formatted input field: '%s'!\n",
	      argv[i]);
      return 1;
    }
  }

  form=Curl_getFormData(httppost, &size);

  Curl_FormInit(&formread, form);

  do {
    nread = Curl_FormReader(buffer, 1, sizeof(buffer),
                            (FILE *)&formread);

    if(-1 == nread)
      break;
    fwrite(buffer, nread, 1, stderr);
  } while(1);

  fprintf(stderr, "size: %d\n", size);

  return 0;
}

#endif
