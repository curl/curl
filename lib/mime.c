/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2017, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/

#include "curl_setup.h"

#include <curl/curl.h>

#include "mime.h"
#include "non-ascii.h"

#if !defined(CURL_DISABLE_HTTP) || !defined(CURL_DISABLE_SMTP) || \
    !defined(CURL_DISABLE_IMAP)

#if defined(HAVE_LIBGEN_H) && defined(HAVE_BASENAME)
#include <libgen.h>
#endif

#include "rand.h"
#include "slist.h"
#include "strcase.h"
/* The last 3 #include files should be in this order */
#include "curl_printf.h"
#include "curl_memory.h"
#include "memdebug.h"


#define DATA_CONTENTTYPE_DEFAULT        "text/plain"
#define FILE_CONTENTTYPE_DEFAULT        "application/octet-stream"
#define MULTIPART_CONTENTTYPE_DEFAULT   "multipart/mixed"
#define DISPOSITION_DEFAULT             "attachment"


#ifndef __VMS
#define filesize(name, stat_data) (stat_data.st_size)
#define fopen_read fopen

#else

#include <fabdef.h>
/*
 * get_vms_file_size does what it takes to get the real size of the file
 *
 * For fixed files, find out the size of the EOF block and adjust.
 *
 * For all others, have to read the entire file in, discarding the contents.
 * Most posted text files will be small, and binary files like zlib archives
 * and CD/DVD images should be either a STREAM_LF format or a fixed format.
 *
 */
curl_off_t VmsRealFileSize(const char *name,
                           const struct_stat *stat_buf)
{
  char buffer[8192];
  curl_off_t count;
  int ret_stat;
  FILE * file;

  file = fopen(name, FOPEN_READTEXT); /* VMS */
  if(file == NULL)
    return 0;

  count = 0;
  ret_stat = 1;
  while(ret_stat > 0) {
    ret_stat = fread(buffer, 1, sizeof(buffer), file);
    if(ret_stat != 0)
      count += ret_stat;
  }
  fclose(file);

  return count;
}

/*
 *
 *  VmsSpecialSize checks to see if the stat st_size can be trusted and
 *  if not to call a routine to get the correct size.
 *
 */
static curl_off_t VmsSpecialSize(const char *name,
                                 const struct_stat *stat_buf)
{
  switch(stat_buf->st_fab_rfm) {
  case FAB$C_VAR:
  case FAB$C_VFC:
    return VmsRealFileSize(name, stat_buf);
    break;
  default:
    return stat_buf->st_size;
  }
}

#define filesize(name, stat_data) VmsSpecialSize(name, &stat_data)

/*
 * vmsfopenread
 *
 * For upload to work as expected on VMS, different optional
 * parameters must be added to the fopen command based on
 * record format of the file.
 *
 */
static FILE * vmsfopenread(const char *file, const char *mode)
{
  struct_stat statbuf;
  int result;

  result = stat(file, &statbuf);

  switch(statbuf.st_fab_rfm) {
  case FAB$C_VAR:
  case FAB$C_VFC:
  case FAB$C_STMCR:
    return fopen(file, FOPEN_READTEXT); /* VMS */
    break;
  default:
    return fopen(file, FOPEN_READTEXT, "rfm=stmlf", "ctx=stm");
  }
}

#define fopen_read vmsfopenread
#endif


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

#define basename(x)  Curl_basename((x))
#endif


/* Set readback state. */
static void mimesetstate(struct mime_state *state,
                         enum mimestate tok, void *ptr)
{
  state->state = tok;
  state->ptr = ptr;
  state->offset = 0;
}


/* Escape header string into allocated memory. */
static char *escape_string(const char *src, ssize_t *srclen)
{
  size_t len = *srclen < 0? strlen(src): (size_t) *srclen;
  size_t bytecount = len;
  size_t i;
  char *dst;

  for(i = 0; i < len; i++)
    if(src[i] == '"' || src[i] == '\\')
      bytecount++;

  dst = malloc(bytecount + 1);
  if(!dst)
    return NULL;

  *srclen = bytecount;

  for(i = 0; len; len--) {
    if(*src == '"' || *src == '\\')
      dst[i++] = '\\';
    dst[i++] = *src++;
  }

  dst[i] = '\0';
  return dst;
}

/* Check if header matches. */
static char *match_header(struct curl_slist *hdr, const char *lbl, size_t len)
{
  char *value = NULL;

  if(strncasecompare(hdr->data, lbl, len) && hdr->data[len] == ':')
    for(value = hdr->data + len + 1; *value == ' '; value++)
      ;
  return value;
}

/* Get a header from an slist. */
static char *search_header(struct curl_slist *hdrlist, const char *hdr)
{
  size_t len = strlen(hdr);
  char *value = NULL;

  for(; !value && hdrlist; hdrlist = hdrlist->next)
    value = match_header(hdrlist, hdr, len);

  return value;
}

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


/* In-memory data callbacks. */
/* Argument is a pointer to the mime part. */
static size_t mime_mem_read(char *buffer, size_t size, size_t nitems,
                            void *instream)
{
  struct Curl_mimepart *part = (struct Curl_mimepart *) instream;
  size_t sz = part->datasize - part->state.offset;

  (void) size;   /* Always 1.*/

  if(sz > nitems)
    sz = nitems;

  if(sz)
    memcpy(buffer, (char *) part->data, sz);

  part->state.offset += sz;
  return sz;
}

static int mime_mem_seek(void *instream, curl_off_t offset, int whence)
{
  struct Curl_mimepart *part = (struct Curl_mimepart *) instream;

  switch(whence) {
  case SEEK_CUR:
    offset += part->state.offset;
    break;
  case SEEK_END:
    offset += part->datasize;
    break;
  }

  if(offset < 0 || offset > part->datasize)
    return CURL_SEEKFUNC_FAIL;

  part->state.offset = offset;
  return CURL_SEEKFUNC_OK;
}

static void mime_mem_free(void *ptr)
{
  Curl_safefree(((struct Curl_mimepart *) ptr)->data);
}


/* Open file callbacks. */
/* Argument is the FILE pointer. */
static size_t mime_file_read(char *buffer, size_t size, size_t nitems,
                             void *instream)
{
  ssize_t ret = fread(buffer, size, nitems, instream);

  return ret < 0? CURL_READFUNC_ABORT: (size_t) ret;
}

static int mime_file_seek(void *instream, curl_off_t offset, int whence)
{
  FILE *fp = (FILE *) instream;

  return fseek(fp, offset, whence)? CURL_SEEKFUNC_CANTSEEK: CURL_SEEKFUNC_OK;
}


/* Named file callbacks. */
/* Argument is a pointer to the mime part. */
static int mime_open_namedfile(struct Curl_mimepart * part)
{
  /* Open a MIMEKIND_NAMEDFILE part. */

  if(part->namedfp)
    return 0;
  part->namedfp = fopen_read(part->data, "rb");
  return part->namedfp? 0: -1;
}

static size_t mime_namedfile_read(char *buffer, size_t size, size_t nitems,
                                  void *instream)
{
  struct Curl_mimepart *part = (struct Curl_mimepart *) instream;

  if(mime_open_namedfile(part))
    return -1;

  return mime_file_read(buffer, size, nitems, part->namedfp);
}

static int mime_namedfile_seek(void *instream, curl_off_t offset, int whence)
{
  struct Curl_mimepart *part = (struct Curl_mimepart *) instream;

  switch(whence) {
  case SEEK_CUR:
    if(part->namedfp)
      offset += ftell(part->namedfp);
    break;
  case SEEK_END:
    offset += part->datasize;
    break;
  }

  if(!offset && !part->namedfp)
    return CURL_SEEKFUNC_OK;

  if(mime_open_namedfile(part))
    return CURL_SEEKFUNC_FAIL;

  return mime_file_seek(part->namedfp, offset, SEEK_SET);
}

static void mime_namedfile_free(void *ptr)
{
  struct Curl_mimepart *part = (struct Curl_mimepart *) ptr;

  if(part->namedfp) {
    fclose(part->namedfp);
    part->namedfp = NULL;
  }
  Curl_safefree(part->data);
  part->data = NULL;
}


/* Subparts callbacks. */
/* Argument is a pointer to the mime structure. */

/* Readback a byte string segment. */
static size_t readback_bytes(struct mime_state *state,
                             char *buffer, size_t bufsize,
                             const char *bytes, size_t numbytes,
                             const char *trail)
{
  size_t sz;

  sz = numbytes - state->offset;

  if(numbytes > state->offset) {
    sz = numbytes - state->offset;
    bytes += state->offset;
  }
  else {
    size_t tsz = strlen(trail);

    sz = state->offset - numbytes;
    if(sz >= tsz)
      return 0;
    bytes = trail + sz;
    sz = tsz - sz;
  }

  if(sz > bufsize)
    sz = bufsize;

  memcpy(buffer, bytes, sz);
  state->offset += sz;
  return sz;
}

/* Readback a mime part. */
static size_t readback_part(struct Curl_mimepart *part,
                            char *buffer, size_t bufsize)
{
  size_t cursize = 0;
  size_t sz;
  struct curl_slist *hdr;
#ifdef CURL_DOES_CONVERSIONS
  char *convbuf = buffer;
#endif

  /* Readback from part. */

  while(bufsize) {
    sz = 0;
    hdr = (struct curl_slist *) part->state.ptr;
    switch(part->state.state) {
    case MIMESTATE_BEGIN:
      mimesetstate(&part->state, MIMESTATE_CURLHEADERS, part->curlheaders);
      break;
    case MIMESTATE_USERHEADERS:
      if(!hdr) {
        mimesetstate(&part->state, MIMESTATE_EOH, NULL);
        break;
      }
      if(match_header(hdr, "Content-Type", 12)) {
        mimesetstate(&part->state, MIMESTATE_USERHEADERS, hdr->next);
        break;
      }
      /* FALLTHROUGH */
    case MIMESTATE_CURLHEADERS:
      if(!hdr)
        mimesetstate(&part->state, MIMESTATE_USERHEADERS, part->userheaders);
      else {
        sz = readback_bytes(&part->state, buffer, bufsize,
                            hdr->data, strlen(hdr->data), "\r\n");
        if(!sz)
          mimesetstate(&part->state, part->state.state, hdr->next);
      }
      break;
    case MIMESTATE_EOH:
      sz = readback_bytes(&part->state, buffer, bufsize, "\r\n", 2, "");
      if(!sz)
        mimesetstate(&part->state, MIMESTATE_BODY, NULL);
      break;
    case MIMESTATE_BODY:
#ifdef CURL_DOES_CONVERSIONS
      if(part->easy && convbuf < buffer) {
        CURLcode result = Curl_convert_to_network(part->easy, convbuf,
                                                  buffer - convbuf);
        if(result)
          return CURL_READFUNC_ABORT;
        convbuf = buffer;
      }
#endif
      mimesetstate(&part->state, MIMESTATE_CONTENT, NULL);
      break;
    case MIMESTATE_CONTENT:
      if(part->readfunc)
        sz = part->readfunc(buffer, 1, bufsize, part->arg);
      switch(sz) {
      case 0:
        mimesetstate(&part->state, MIMESTATE_END, NULL);
        /* Try sparing open file descriptors. */
        if(!cursize && part->kind == MIMEKIND_NAMEDFILE && part->namedfp) {
          fclose(part->namedfp);
          part->namedfp = NULL;
        }
        /* FALLTHROUGH */
      case CURL_READFUNC_ABORT:
      case CURL_READFUNC_PAUSE:
        return cursize? cursize: sz;
      }
        break;
    case MIMESTATE_END:
      return cursize;
    default:
      break;    /* Other values not in part state. */
    }

    /* Bump buffer and counters according to read size. */
    cursize += sz;
    buffer += sz;
    bufsize -= sz;
  }

#ifdef CURL_DOES_CONVERSIONS
      if(part->easy && convbuf < buffer &&
         part->state.state < MIMESTATE_BODY) {
        CURLcode result = Curl_convert_to_network(part->easy, convbuf,
                                                  buffer - convbuf);
        if(result)
          return CURL_READFUNC_ABORT;
      }
#endif

  return cursize;
}

/* Readback from mime. */
static size_t mime_subparts_read(char *buffer, size_t size, size_t nitems,
                                 void *instream)
{
  struct Curl_mime *mime = (struct Curl_mime *) instream;
  size_t cursize = 0;
  size_t sz;
  struct Curl_mimepart *part;
#ifdef CURL_DOES_CONVERSIONS
  char *convbuf = buffer;
#endif

  (void) size;   /* Always 1. */

  while(nitems) {
    sz = 0;
    part = mime->state.ptr;
    switch(mime->state.state) {
    case MIMESTATE_BEGIN:
    case MIMESTATE_BODY:
      mimesetstate(&mime->state, MIMESTATE_BOUNDARY1, mime->firstpart);
      /* The first boundary always follows the header termination empty line,
         so is always preceded by a CRLK. We can then spare 2 characters
         by skipping the leading CRLF in boundary. */
      mime->state.offset += 2;
      break;
    case MIMESTATE_BOUNDARY1:
#ifdef CURL_DOES_CONVERSIONS
      convbuf = buffer;
#endif
      sz = readback_bytes(&mime->state, buffer, nitems, "\r\n--", 4, "");
      if(!sz)
        mimesetstate(&mime->state, MIMESTATE_BOUNDARY2, part);
      break;
    case MIMESTATE_BOUNDARY2:
      sz = readback_bytes(&mime->state, buffer, nitems, mime->boundary,
                          strlen(mime->boundary), part? "\r\n": "--\r\n");
      if(!sz) {
#ifdef CURL_DOES_CONVERSIONS
        if(mime->easy && convbuf < buffer) {
          CURLcode result = Curl_convert_to_network(mime->easy, convbuf,
                                                    buffer - convbuf);
          if(result)
            return CURL_READFUNC_ABORT;
          convbuf = buffer;
        }
#endif
        mimesetstate(&mime->state,
                     part? MIMESTATE_CONTENT: MIMESTATE_END, part);
      }
      break;
    case MIMESTATE_CONTENT:
      sz = readback_part(part, buffer, nitems);
      switch(sz) {
      case CURL_READFUNC_ABORT:
      case CURL_READFUNC_PAUSE:
        return cursize? cursize: sz;
      case 0:
        mimesetstate(&mime->state, MIMESTATE_BOUNDARY1, part->nextpart);
        break;
      }
      break;
    case MIMESTATE_END:
      return cursize;
    default:
      break;    /* other values not used in mime state. */
    }

    /* Bump buffer and counters according to read size. */
    cursize += sz;
    buffer += sz;
    nitems -= sz;
  }

#ifdef CURL_DOES_CONVERSIONS
      if(mime->easy && convbuf < buffer &&
         mime->state.state <= MIMESTATE_CONTENT) {
        CURLcode result = Curl_convert_to_network(mime->easy, convbuf,
                                                  buffer - convbuf);
        if(result)
          return CURL_READFUNC_ABORT;
      }
#endif

  return cursize;
}

static int mime_subparts_seek(void *instream, curl_off_t offset, int whence)
{
  struct Curl_mime *mime = (struct Curl_mime *) instream;
  struct Curl_mimepart *part;
  int result = CURL_SEEKFUNC_OK;
  CURLcode res;

  if(whence != SEEK_SET || offset)
    return CURL_SEEKFUNC_CANTSEEK;    /* Only support full rewind. */

  if(mime->state.state == MIMESTATE_BEGIN)
   return CURL_SEEKFUNC_OK;           /* Already rewound. */

  for(part = mime->firstpart; part; part = part->nextpart) {
    if(part->state.state == MIMESTATE_CONTENT && mime->state.offset) {
      res = CURL_SEEKFUNC_CANTSEEK;
      if(part->seekfunc)
        res = part->seekfunc(part->arg, part->origin, SEEK_SET);
      if(res != CURL_SEEKFUNC_OK)
        result = res;
    }
    mimesetstate(&part->state, MIMESTATE_BEGIN, NULL);
  }

  mimesetstate(&mime->state, MIMESTATE_BEGIN, NULL);
  return result;
}

static void mime_subparts_free(void *ptr)
{
  struct Curl_mime *mime = (struct Curl_mime *) ptr;
  curl_mime_free(mime);
}


/* Release part content. */
static void cleanup_part_content(struct Curl_mimepart *part)
{
  if(part->freefunc)
    part->freefunc(part->arg);

  part->readfunc = NULL;
  part->seekfunc = NULL;
  part->freefunc = NULL;
  part->arg = NULL;
  part->data = NULL;
  part->namedfp = NULL;
  part->origin = 0;
  part->datasize = (curl_off_t) 0;    /* No size yet. */
  part->kind = MIMEKIND_NONE;
}

void Curl_mime_cleanpart(struct Curl_mimepart *part)
{
  cleanup_part_content(part);
  curl_slist_free_all(part->curlheaders);
  if(part->flags & MIME_USERHEADERS_OWNER)
    curl_slist_free_all(part->userheaders);
  Curl_safefree(part->mimetype);
  Curl_safefree(part->name);
  Curl_safefree(part->filename);
  Curl_mime_initpart(part, part->easy);
}

/* Recursively delete a mime handle and its parts. */
void curl_mime_free(struct Curl_mime *mime)
{
  struct Curl_mimepart *part;

  if(mime) {
    while((part = mime->firstpart)) {
      mime->firstpart = part->nextpart;
      Curl_mime_cleanpart(part);
      free(part);
    }

    free(mime->boundary);
    free(mime);
  }
}

/*
 * Mime build functions.
 */

/* Create a mime handle. */
struct Curl_mime *curl_mime_init(struct Curl_easy *easy)
{
  struct Curl_mime *mime;

  mime = (struct Curl_mime *) malloc(sizeof *mime);

  if(mime) {
    mime->easy = easy;
    mime->parent = NULL;
    mime->firstpart = NULL;
    mime->lastpart = NULL;

    /* Get a part boundary. */
    mime->boundary = malloc(24 + MIME_RAND_BOUNDARY_CHARS + 1);
    if(!mime->boundary) {
      free(mime);
      return NULL;
    }

    memset(mime->boundary, '-', 24);
    Curl_rand_hex(easy, (unsigned char *) mime->boundary + 24,
                  MIME_RAND_BOUNDARY_CHARS + 1);
    mimesetstate(&mime->state, MIMESTATE_BEGIN, NULL);
  }

  return mime;
}

/* Initialize a mime part. */
void Curl_mime_initpart(struct Curl_mimepart *part, struct Curl_easy *easy)
{
    memset((char *) part, 0, sizeof *part);
    part->easy = easy;
    mimesetstate(&part->state, MIMESTATE_BEGIN, NULL);
}

/* Create a mime part and append it to a mime handle's part list. */
struct Curl_mimepart *curl_mime_addpart(struct Curl_mime *mime)
{
  struct Curl_mimepart *part;

  if(!mime)
    return NULL;

  part = (struct Curl_mimepart *) malloc(sizeof *part);

  if(part) {
    Curl_mime_initpart(part, mime->easy);
    part->parent = mime;

    if(mime->lastpart)
      mime->lastpart->nextpart = part;
    else {
      mime->firstpart = part;
      mimesetstate(&mime->state, MIMESTATE_BOUNDARY1, part);
    }

    mime->lastpart = part;
  }

  return part;
}

/* Set mime part name. */
CURLcode curl_mime_name(struct Curl_mimepart *part,
                        const char *name, ssize_t namesize)
{
  if(!part)
    return CURLE_BAD_FUNCTION_ARGUMENT;

  Curl_safefree(part->name);
  part->name = NULL;
  part->namesize = 0;

  if(name) {
    part->name = escape_string(name, &namesize);
    if(!part->name)
      return CURLE_OUT_OF_MEMORY;
    part->namesize = namesize;
  }

  return CURLE_OK;
}

/* Set mime part remote file name. */
CURLcode curl_mime_filename(struct Curl_mimepart *part, const char *filename)
{
  char *escaped;
  ssize_t len = -1;

  if(!part)
    return CURLE_BAD_FUNCTION_ARGUMENT;

  Curl_safefree(part->filename);
  part->filename = NULL;

  if(filename) {
    escaped = escape_string(filename, &len);
    if(!escaped)
      return CURLE_OUT_OF_MEMORY;
    part->filename = escaped;
  }

  return CURLE_OK;
}

/* Set mime part content from memory data. */
CURLcode curl_mime_data(struct Curl_mimepart *part,
                        const char *data, ssize_t datasize)
{
  if(!part)
    return CURLE_BAD_FUNCTION_ARGUMENT;

  cleanup_part_content(part);

  if(data) {
    if(datasize < 0)
      datasize = strlen(data);

    part->data = malloc(datasize? datasize: 1);
    if(!part->data)
      return CURLE_OUT_OF_MEMORY;

    part->datasize = datasize;

    if(datasize)
      memcpy(part->data, data, datasize);

    part->readfunc = mime_mem_read;
    part->seekfunc = mime_mem_seek;
    part->freefunc = mime_mem_free;
    part->arg = part;
    part->kind = MIMEKIND_DATA;
  }

  return CURLE_OK;
}

/* Set mime part content from opened file. */
CURLcode curl_mime_file(struct Curl_mimepart *part,
                        FILE *fp, int closewhendone)
{
  if(!part || !fp)
    return CURLE_BAD_FUNCTION_ARGUMENT;

  cleanup_part_content(part);

  part->arg = fp;
  part->readfunc = (curl_read_callback) mime_file_read;
  if(closewhendone)
    part->freefunc = (curl_free_callback) fclose;
  part->origin = ftell(fp);
  /* Check if file is seekable and get its size. */
  part->datasize = (curl_off_t) -1;    /* Unknown size. */
  if(!fseek(fp, 0L, SEEK_END)) {
    part->datasize = ftell(fp);
    if(part->datasize >= 0) {
      if(part->datasize < part->origin)
        part->datasize = 0;
      else
        part->datasize -= part->origin;
      part->seekfunc = mime_file_seek;
    }
    fseek(fp, part->origin, SEEK_SET);
  }
  part->kind = MIMEKIND_FILE;
  return CURLE_OK;
}

/* Set mime part content from named local file. */
CURLcode curl_mime_filedata(struct Curl_mimepart *part, const char *filename)
{
  struct_stat sbuf;
  char *base;
  CURLcode result;

  if(!part || !filename)
    return CURLE_BAD_FUNCTION_ARGUMENT;

  if(!strcmp(filename, "-"))
    return curl_mime_file(part, stdin, 0);

  if(stat(filename, &sbuf) || access(filename, R_OK))
    return CURLE_READ_ERROR;

  cleanup_part_content(part);

  part->data = strdup(filename);
  if(!part->data)
    return CURLE_OUT_OF_MEMORY;

  part->datasize = -1;
  if(S_ISREG(sbuf.st_mode)) {
    part->datasize = filesize(filename, sbuf);
    part->seekfunc = mime_namedfile_seek;
  }

  part->readfunc = mime_namedfile_read;
  part->freefunc = mime_namedfile_free;
  part->arg = part;
  part->kind = MIMEKIND_NAMEDFILE;

  /* As a side effect, set the filename to the current file's base name.
     It is possible to withdraw this by explicitly calling curl_mime_filename()
     with a NULL filename argument after the current call. */
  base = strippath(filename);
  if(!base)
    return CURLE_OUT_OF_MEMORY;
  result = curl_mime_filename(part, base);
  free(base);
  return result;
}

/* Set mime part type. */
CURLcode curl_mime_type(struct Curl_mimepart *part, const char *mimetype)
{
  if(!part)
    return CURLE_BAD_FUNCTION_ARGUMENT;

  Curl_safefree(part->mimetype);
  part->mimetype = NULL;

  if(mimetype) {
    part->mimetype = strdup(mimetype);
    if(!part->mimetype)
      return CURLE_OUT_OF_MEMORY;
  }

  return CURLE_OK;
}

/* Set mime data transfer encoder. */
CURLcode curl_mime_encoder(struct Curl_mimepart *part, const char *encoding)
{
  CURLcode result = CURLE_OK;

  /* Encoding feature not yet implemented. */

  if(!part)
    return CURLE_BAD_FUNCTION_ARGUMENT;

  if(encoding)
    return CURLE_BAD_FUNCTION_ARGUMENT;

  return result;
}

/* Set mime part headers. */
CURLcode curl_mime_headers(struct Curl_mimepart *part,
                           struct curl_slist *headers, int take_ownership)
{
  if(!part)
    return CURLE_BAD_FUNCTION_ARGUMENT;

  if(part->flags & MIME_USERHEADERS_OWNER) {
    curl_slist_free_all(part->userheaders);
    part->flags &= ~MIME_USERHEADERS_OWNER;
  }
  part->userheaders = headers;
  if(headers && take_ownership)
    part->flags |= MIME_USERHEADERS_OWNER;
  return CURLE_OK;
}

/* Set mime part content from callback. */
CURLcode curl_mime_data_cb(struct Curl_mimepart *part, curl_off_t datasize,
                           curl_read_callback readfunc,
                           curl_seek_callback seekfunc,
                           curl_free_callback freefunc, void *arg)
{
  if(!part)
    return CURLE_BAD_FUNCTION_ARGUMENT;

  cleanup_part_content(part);

  if(readfunc) {
    part->readfunc = readfunc;
    part->seekfunc = seekfunc;
    part->freefunc = freefunc;
    part->arg = arg;
    part->datasize = datasize;
    part->kind = MIMEKIND_CALLBACK;
  }

  return CURLE_OK;
}

/* Set mime part content from subparts. */
CURLcode curl_mime_subparts(struct Curl_mimepart *part,
                            struct Curl_mime *subparts)
{
  if(!part)
    return CURLE_BAD_FUNCTION_ARGUMENT;

  /* Accept setting twice the same subparts. */
  if(part->kind == MIMEKIND_MULTIPART && part->arg == subparts)
    return CURLE_OK;

  cleanup_part_content(part);

  if(subparts) {
    /* Must belong to the same data handle. */
    if(part->easy && subparts->easy && part->easy != subparts->easy)
      return CURLE_BAD_FUNCTION_ARGUMENT;

    /* Should not have been attached already. */
    if(subparts->parent)
      return CURLE_BAD_FUNCTION_ARGUMENT;

    subparts->parent = part;
    part->readfunc = mime_subparts_read;
    part->seekfunc = mime_subparts_seek;
    part->freefunc = mime_subparts_free;
    part->arg = subparts;
    part->datasize = -1;
    part->kind = MIMEKIND_MULTIPART;
  }

  return CURLE_OK;
}


/* Readback from top mime. */
/* Argument is the dummy top part. */
size_t Curl_mime_read(char *buffer, size_t size, size_t nitems, void *instream)
{
  struct Curl_mimepart *part = (struct Curl_mimepart *) instream;

  (void) size;   /* Always 1. */
  return readback_part(part, buffer, nitems);
}

/* Rewind mime stream. */
CURLcode Curl_mime_rewind(struct Curl_mimepart *part)
{
  int res = CURL_SEEKFUNC_OK;
  enum mimestate targetstate = MIMESTATE_BEGIN;

  if(part->flags & MIME_BODY_ONLY)
    targetstate = MIMESTATE_BODY;
  if(part->state.state > targetstate) {
    res = CURL_SEEKFUNC_CANTSEEK;
    if(part->seekfunc)
      res = part->seekfunc(part->arg, part->origin, SEEK_SET);
    if(res != CURL_SEEKFUNC_OK)
      return CURLE_SEND_FAIL_REWIND;
  }
  if(res == CURL_SEEKFUNC_OK)
    mimesetstate(&part->state, targetstate, NULL);
  return CURLE_OK;
}

/* Compute header list size. */
static size_t slist_size(struct curl_slist *s,
                         size_t overhead, const char *skip)
{
  size_t size = 0;
  size_t skiplen = skip? strlen(skip): 0;

  for(; s; s = s->next)
    if(!skip || !match_header(s, skip, skiplen))
      size += strlen(s->data) + overhead;
  return size;
}

/* Get/compute multipart size. */
static curl_off_t multipart_size(struct Curl_mime *mime)
{
  curl_off_t size;
  curl_off_t sz;
  size_t boundarysize;
  struct Curl_mimepart *part;

  if(!mime)
    return 0;           /* Not present -> empty. */

  boundarysize = 4 + strlen(mime->boundary) + 2;
  size = boundarysize;  /* Final boundary - CRLF after headers. */

  for(part = mime->firstpart; part; part = part->nextpart) {
    sz = Curl_mime_size(part);

    if(sz < 0)
      size = sz;

    if(size >= 0)
      size += boundarysize + sz;
  }

  return size;
}

/* Get/compute mime size. */
curl_off_t Curl_mime_size(struct Curl_mimepart *part)
{
  curl_off_t size;

  if(part->datasize < 0 && part->kind == MIMEKIND_MULTIPART)
    part->datasize = multipart_size(part->arg);

  size = part->datasize;
  if(size >= 0 && !(part->flags & MIME_BODY_ONLY)) {
    /* Compute total part size. */
    size += slist_size(part->curlheaders, 2, NULL);
    size += slist_size(part->userheaders, 2, "Content-Type");
    size += 2;    /* CRLF after headers. */
  }
  return size;
}

/* Add a header. */
/* VARARGS2 */
CURLcode Curl_mime_add_header(struct curl_slist **slp, const char *fmt, ...)
{
  struct curl_slist *hdr;
  char *s = NULL;
  va_list ap;

  va_start(ap, fmt);
  s = curl_mvaprintf(fmt, ap);
  va_end(ap);

  if(s) {
    hdr = Curl_slist_append_nodup(*slp, s);
    if(hdr)
      *slp = hdr;
    else
      free(s);
  }

  return hdr? CURLE_OK: CURLE_OUT_OF_MEMORY;
}

/* Add a content type header. */
static CURLcode add_content_type(struct curl_slist **slp,
                                 const char *type, const char *boundary)
{
  return Curl_mime_add_header(slp, "Content-Type: %s%s%s", type,
                              boundary? "; boundary=": "",
                              boundary? boundary: "");
}


CURLcode Curl_mime_prepare_headers(struct Curl_mimepart *part,
                                   const char *contenttype,
                                   const char *disposition,
                                   enum mimestrategy strategy)
{
  struct Curl_mime *mime;
  const char *boundary = NULL;
  char *s;
  CURLcode ret = CURLE_OK;
  unsigned int i;

  /*
   * If no content type was specified, we scan through a few well-known
   * extensions and pick the first we match!
   */
  struct ContentType {
    const char *extension;
    const char *type;
  };
  static const struct ContentType ctts[] = {
    {".gif",  "image/gif"},
    {".jpg",  "image/jpeg"},
    {".jpeg", "image/jpeg"},
    {".png",  "image/png"},
    {".svg",  "image/svg+xml"},
    {".txt",  "text/plain"},
    {".htm",  "text/html"},
    {".html", "text/html"},
    {".pdf",  "application/pdf"},
    {".xml",  "application/xml"}
  };

  /* Get rid of previously prepared headers. */
  curl_slist_free_all(part->curlheaders);
  part->curlheaders = NULL;

  /* Build the content-type header. */
  s = search_header(part->userheaders, "Content-Type");
  if(s)
    contenttype = s;
  if(part->mimetype)
    contenttype = part->mimetype;
  if(!contenttype) {
    if(part->kind == MIMEKIND_MULTIPART)
      contenttype = MULTIPART_CONTENTTYPE_DEFAULT;
    else if(!part->filename)
      contenttype = DATA_CONTENTTYPE_DEFAULT;
    else {
      size_t len1 = strlen(part->filename);

      contenttype = FILE_CONTENTTYPE_DEFAULT;
      for(i = 0; i < sizeof ctts / sizeof ctts[0]; i++) {
        size_t len2 = strlen(ctts[i].extension);

        if(len1 >= len2 && strcasecompare(part->filename + len1 - len2,
                                          ctts[i].extension)) {
          contenttype = ctts[i].type;
          break;
        }
      }
    }
  }

  if(part->kind == MIMEKIND_MULTIPART) {
    mime = (struct Curl_mime *) part->arg;
    if(mime)
      boundary = mime->boundary;
  }
  else if(strcasecompare(contenttype, "text/plain"))
    if(strategy == MIMESTRATEGY_MAIL || !part->filename)
      contenttype = NULL;

  /* Issue content-disposition header only if not already set by caller. */
  if(!search_header(part->userheaders, "Content-Disposition")) {
    if(!disposition)
      if(part->filename || part->name ||
        (contenttype && !strncasecompare(contenttype, "multipart/", 10)))
          disposition = DISPOSITION_DEFAULT;
    if(disposition && curl_strequal(disposition, "attachment") &&
     !part->name && !part->filename)
      disposition = NULL;
    if(disposition) {
      ret = Curl_mime_add_header(&part->curlheaders,
                                 "Content-Disposition: %s%s%s%s%s%s%s",
                                 disposition,
                                 part->name? "; name=\"": "",
                                 part->name? part->name: "",
                                 part->name? "\"": "",
                                 part->filename? "; filename=\"": "",
                                 part->filename? part->filename: "",
                                 part->filename? "\"": "");
      if(ret)
        return ret;
      }
    }

  /* Issue Content-Type header. */
  if(contenttype) {
    ret = add_content_type(&part->curlheaders, contenttype, boundary);
    if(ret)
      return ret;
  }

  /* Content-Transfer-Encoding header. */
  if(contenttype && strategy == MIMESTRATEGY_MAIL &&
     part->kind != MIMEKIND_MULTIPART &&
     !search_header(part->userheaders, "Content-Transfer-Encoding")) {
    ret = Curl_mime_add_header(&part->curlheaders,
                               "Content-Transfer-Encoding: 8bit");
    if(ret)
      return ret;
  }

  /* Process subparts. */
  if(part->kind == MIMEKIND_MULTIPART && mime) {
    struct Curl_mimepart *subpart;

    disposition = NULL;
    if(strcasecompare(contenttype, "multipart/form-data"))
      disposition = "form-data";
    for(subpart = mime->firstpart; subpart; subpart = subpart->nextpart) {
      ret = Curl_mime_prepare_headers(subpart, NULL, disposition, strategy);
      if(ret)
        return ret;
    }

    /* Rewind subparts. */
    mimesetstate(&mime->state, MIMESTATE_BEGIN, NULL);
  }

  /* Rewind part. */
  mimesetstate(&part->state, MIMESTATE_BEGIN, NULL);
  return ret;
}

#else /* !CURL_DISABLE_HTTP || !CURL_DISABLE_SMTP || !CURL_DISABLE_IMAP */

/* Mime not compiled in: define stubs for externally-referenced functions. */
curl_mime *curl_mime_init(CURL *easy)
{
  (void) easy;
  return NULL;
}

void curl_mime_free(curl_mime *mime)
{
  (void) mime;
}

curl_mimepart *curl_mime_addpart(curl_mime *mime)
{
  (void) mime;
  return NULL;
}

CURLcode curl_mime_name(curl_mimepart *part,
                        const char *name, ssize_t namesize)
{
  (void) part;
  (void) name;
  (void) namesize;
  return CURLE_NOT_BUILT_IN;
}

CURLcode curl_mime_filename(curl_mimepart *part, const char *filename)
{
  (void) part;
  (void) filename;
  return CURLE_NOT_BUILT_IN;
}

CURLcode curl_mime_type(curl_mimepart *part, const char *mimetype)
{
  (void) part;
  (void) mimetype;
  return CURLE_NOT_BUILT_IN;
}

CURLcode curl_mime_encoder(struct Curl_mimepart *part, const char *encoding)
{
  (void) part;
  (void) encoding;
  return CURLE_NOT_BUILT_IN;
}

CURLcode curl_mime_data(curl_mimepart *part,
                        const char *data, ssize_t datasize)
{
  (void) part;
  (void) data;
  (void) datasize;
  return CURLE_NOT_BUILT_IN;
}

CURLcode curl_mime_file(curl_mimepart *part, FILE *fp, int closewhendone)
{
  (void) part;
  (void) fp;
  (void) closewhendone;
  return CURLE_NOT_BUILT_IN;
}

CURLcode curl_mime_filedata(curl_mimepart *part, const char *filename)
{
  (void) part;
  (void) filename;
  return CURLE_NOT_BUILT_IN;
}

CURLcode curl_mime_data_cb(curl_mimepart *part,
                           curl_off_t datasize,
                           curl_read_callback readfunc,
                           curl_seek_callback seekfunc,
                           curl_free_callback freefunc,
                           void *arg)
{
  (void) part;
  (void) datasize;
  (void) readfunc;
  (void) seekfunc;
  (void) freefunc;
  (void) arg;
  return CURLE_NOT_BUILT_IN;
}

CURLcode curl_mime_subparts(curl_mimepart *part, curl_mime *subparts)
{
  (void) part;
  (void) subparts;
  return CURLE_NOT_BUILT_IN;
}

CURLcode curl_mime_headers(curl_mimepart *part,
                           struct curl_slist *headers, int take_ownership)
{
  (void) part;
  (void) headers;
  (void) take_ownership;
  return CURLE_NOT_BUILT_IN;
}

void Curl_mime_initpart(struct Curl_mimepart *part, struct Curl_easy *easy)
{
  (void) part;
  (void) data;
}

void Curl_mime_cleanpart(struct Curl_mimepart *part)
{
  (void) part;
}

CURLcode Curl_mime_prepare_headers(struct Curl_mimepart *part,
                                   const char *contenttype,
                                   const char *disposition,
                                   enum mimestrategy strategy)
{
  (void) part;
  (void) contenttype;
  (void) disposition;
  (void) strategy;
  return CURLE_NOT_BUILT_IN;
}

curl_off_t Curl_mime_size(struct Curl_mimepart *part)
{
  (void) part;
  return (curl_off_t) -1;
}

size_t Curl_mime_read(char *buffer, size_t size, size_t nitems, void *instream)
{
  (void) buffer;
  (void) size;
  (void) nitems;
  (void) instream;
  return 0;
}

CURLcode Curl_mime_rewind(struct Curl_mimepart *part)
{
  (void) part;
  return CURLE_NOT_BUILT_IN;
}

/* VARARGS2 */
CURLcode Curl_mime_add_header(struct curl_slist **slp, const char *fmt, ...)
{
  (void) slp;
  (void) fmt;
  return CURLE_NOT_BUILT_IN;
}

#endif /* !CURL_DISABLE_HTTP || !CURL_DISABLE_SMTP || !CURL_DISABLE_IMAP */
