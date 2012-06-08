/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2012, Daniel Stenberg, <daniel@haxx.se>, et al.
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
#include "tool_setup.h"

#ifdef USE_METALINK

#include <metalink/metalink_parser.h>

#ifdef USE_SSLEAY
#  ifdef USE_OPENSSL
#    include <openssl/md5.h>
#    include <openssl/sha.h>
#  else
#    include <md5.h>
#    include <sha.h>
#  endif
#elif defined(USE_GNUTLS_NETTLE)
#  include <nettle/md5.h>
#  include <nettle/sha.h>
#  define MD5_CTX    struct md5_ctx
#  define SHA_CTX    struct sha1_ctx
#  define SHA256_CTX struct sha256_ctx
#elif defined(USE_GNUTLS)
#  include <gcrypt.h>
#  define MD5_CTX    gcry_md_hd_t
#  define SHA_CTX    gcry_md_hd_t
#  define SHA256_CTX gcry_md_hd_t
#else
#  error "Can't compile METALINK support without a crypto library."
#endif

#include "rawstr.h"

#define ENABLE_CURLX_PRINTF
/* use our own printf() functions */
#include "curlx.h"

#include "tool_getparam.h"
#include "tool_paramhlp.h"
#include "tool_cfgable.h"
#include "tool_metalink.h"

#include "memdebug.h" /* keep this as LAST include */

/* Copied from tool_getparam.c */
#define GetStr(str,val) do { \
  if(*(str)) { \
    free(*(str)); \
    *(str) = NULL; \
  } \
  if((val)) \
    *(str) = strdup((val)); \
  if(!(val)) \
    return PARAM_NO_MEM; \
} WHILE_FALSE

const digest_params MD5_DIGEST_PARAMS[] = {
  {
    (Curl_digest_init_func) MD5_Init,
    (Curl_digest_update_func) MD5_Update,
    (Curl_digest_final_func) MD5_Final,
    sizeof(MD5_CTX),
    16
  }
};

const digest_params SHA1_DIGEST_PARAMS[] = {
  {
    (Curl_digest_init_func) SHA1_Init,
    (Curl_digest_update_func) SHA1_Update,
    (Curl_digest_final_func) SHA1_Final,
    sizeof(SHA_CTX),
    20
  }
};

const digest_params SHA256_DIGEST_PARAMS[] = {
  {
    (Curl_digest_init_func) SHA256_Init,
    (Curl_digest_update_func) SHA256_Update,
    (Curl_digest_final_func) SHA256_Final,
    sizeof(SHA256_CTX),
    32
  }
};

static const metalink_digest_def SHA256_DIGEST_DEF[] = {
  {"sha-256", SHA256_DIGEST_PARAMS}
};

static const metalink_digest_def SHA1_DIGEST_DEF[] = {
  {"sha-1", SHA1_DIGEST_PARAMS}
};

static const metalink_digest_def MD5_DIGEST_DEF[] = {
  {"md5", MD5_DIGEST_PARAMS}
};

/*
 * The alias of supported hash functions in the order by preference
 * (basically stronger hash comes first). We included "sha-256" and
 * "sha256". The former is the name defined in the IANA registry named
 * "Hash Function Textual Names". The latter is widely (and
 * historically) used in Metalink version 3.
 */
static const metalink_digest_alias digest_aliases[] = {
  {"sha-256", SHA256_DIGEST_DEF},
  {"sha256", SHA256_DIGEST_DEF},
  {"sha-1", SHA1_DIGEST_DEF},
  {"sha1", SHA1_DIGEST_DEF},
  {"md5", MD5_DIGEST_DEF},
  {NULL, NULL}
};

#ifdef USE_GNUTLS_NETTLE

static void MD5_Init(MD5_CTX *ctx)
{
  md5_init(ctx);
}

static void MD5_Update(MD5_CTX *ctx,
                       const unsigned char *input,
                       unsigned int inputLen)
{
  md5_update(ctx, inputLen, input);
}

static void MD5_Final(unsigned char digest[16], MD5_CTX *ctx)
{
  md5_digest(ctx, 16, digest);
}

static void SHA1_Init(SHA_CTX *ctx)
{
  sha1_init(ctx);
}

static void SHA1_Update(SHA_CTX *ctx,
                        const unsigned char *input,
                        unsigned int inputLen)
{
  sha1_update(ctx, inputLen, input);
}

static void SHA1_Final(unsigned char digest[20], SHA_CTX *ctx)
{
  sha1_digest(ctx, 20, digest);
}

static void SHA256_Init(SHA256_CTX *ctx)
{
  sha256_init(ctx);
}

static void SHA256_Update(SHA256_CTX *ctx,
                          const unsigned char *input,
                          unsigned int inputLen)
{
  sha256_update(ctx, inputLen, input);
}

static void SHA256_Final(unsigned char digest[32], SHA256_CTX *ctx)
{
  sha256_digest(ctx, 32, digest);
}

#elif defined(USE_GNUTLS)

static void MD5_Init(MD5_CTX *ctx)
{
  gcry_md_open(ctx, GCRY_MD_MD5, 0);
}

static void MD5_Update(MD5_CTX *ctx,
                       const unsigned char *input,
                       unsigned int inputLen)
{
  gcry_md_write(*ctx, input, inputLen);
}

static void MD5_Final(unsigned char digest[16], MD5_CTX *ctx)
{
  memcpy(digest, gcry_md_read(*ctx, 0), 16);
  gcry_md_close(*ctx);
}

static void SHA1_Init(SHA_CTX *ctx)
{
  gcry_md_open(ctx, GCRY_MD_SHA1, 0);
}

static void SHA1_Update(SHA_CTX *ctx,
                        const unsigned char *input,
                        unsigned int inputLen)
{
  gcry_md_write(*ctx, input, inputLen);
}

static void SHA1_Final(unsigned char digest[20], SHA_CTX *ctx)
{
  memcpy(digest, gcry_md_read(*ctx, 0), 20);
  gcry_md_close(*ctx);
}

static void SHA256_Init(SHA256_CTX *ctx)
{
  gcry_md_open(ctx, GCRY_MD_SHA256, 0);
}

static void SHA256_Update(SHA256_CTX *ctx,
                          const unsigned char *input,
                          unsigned int inputLen)
{
  gcry_md_write(*ctx, input, inputLen);
}

static void SHA256_Final(unsigned char digest[32], SHA256_CTX *ctx)
{
  memcpy(digest, gcry_md_read(*ctx, 0), 32);
  gcry_md_close(*ctx);
}

#endif /* CRYPTO LIBS */

digest_context *Curl_digest_init(const digest_params *dparams)
{
  digest_context *ctxt;

  /* Create digest context */
  ctxt = malloc(sizeof *ctxt);

  if(!ctxt)
    return ctxt;

  ctxt->digest_hashctx = malloc(dparams->digest_ctxtsize);

  if(!ctxt->digest_hashctx) {
    free(ctxt);
    return NULL;
  }

  ctxt->digest_hash = dparams;

  dparams->digest_init(ctxt->digest_hashctx);

  return ctxt;
}

int Curl_digest_update(digest_context *context,
                       const unsigned char *data,
                       unsigned int len)
{
  (*context->digest_hash->digest_update)(context->digest_hashctx, data, len);

  return 0;
}

int Curl_digest_final(digest_context *context, unsigned char *result)
{
  (*context->digest_hash->digest_final)(result, context->digest_hashctx);

  free(context->digest_hashctx);
  free(context);

  return 0;
}

static unsigned char hex_to_uint(const char *s)
{
  int v[2];
  int i;
  for(i = 0; i < 2; ++i) {
    v[i] = Curl_raw_toupper(s[i]);
    if('0' <= v[i] && v[i] <= '9') {
      v[i] -= '0';
    }
    else if('A' <= v[i] && v[i] <= 'Z') {
      v[i] -= 'A'-10;
    }
  }
  return (unsigned char)((v[0] << 4) | v[1]);
}

/*
 * Check checksum of file denoted by filename. The expected hash value
 * is given in hex_hash which is hex-encoded string.
 *
 * This function returns 1 if it succeeds or one of the following
 * integers:
 *
 * 0:
 *   Checksum didn't match.
 * -1:
 *   Could not open file; or could not read data from file.
 */
static int check_hash(const char *filename,
                      const metalink_digest_def *digest_def,
                      const char *hex_hash, FILE *error)
{
  unsigned char *result;
  digest_context *dctx;
  int check_ok;
  int fd;
  size_t i;
  fprintf(error, "Checking %s checksum of file %s\n", digest_def->hash_name,
          filename);
  fd = open(filename, O_RDONLY);
  if(fd == -1) {
    fprintf(error, "Could not open file %s: %s\n", filename, strerror(errno));
    return -1;
  }
  dctx = Curl_digest_init(digest_def->dparams);
  result = malloc(digest_def->dparams->digest_resultlen);
  while(1) {
    unsigned char buf[4096];
    ssize_t len = read(fd, buf, sizeof(buf));
    if(len == 0) {
      break;
    }
    else if(len == -1) {
      fprintf(error, "Could not read file %s: %s\n", filename,
              strerror(errno));
      Curl_digest_final(dctx, result);
      close(fd);
      return -1;
    }
    Curl_digest_update(dctx, buf, (unsigned int)len);
  }
  Curl_digest_final(dctx, result);
  check_ok = 1;
  for(i = 0; i < digest_def->dparams->digest_resultlen; ++i) {
    if(hex_to_uint(&hex_hash[i*2]) != result[i]) {
      check_ok = 0;
      break;
    }
  }
  free(result);
  close(fd);
  return check_ok;
}

int metalink_check_hash(struct Configurable *config,
                        metalinkfile *mlfile,
                        const char *filename)
{
  metalink_checksum *chksum;
  const metalink_digest_alias *digest_alias;
  int rv;
  if(mlfile->checksum == NULL) {
    return -2;
  }
  for(digest_alias = digest_aliases; digest_alias->alias_name;
      ++digest_alias) {
    for(chksum = mlfile->checksum; chksum; chksum = chksum->next) {
      if(Curl_raw_equal(digest_alias->alias_name, chksum->hash_name) &&
         strlen(chksum->hash_value) ==
         digest_alias->digest_def->dparams->digest_resultlen*2) {
        break;
      }
    }
    if(chksum) {
      break;
    }
  }
  if(!digest_alias->alias_name) {
    fprintf(config->errors, "No supported checksum in Metalink file\n");
    return -2;
  }
  rv = check_hash(filename, digest_alias->digest_def,
                  chksum->hash_value, config->errors);
  if(rv == 1) {
    fprintf(config->errors, "Checksum matched\n");
  }
  else if(rv == 0) {
    fprintf(config->errors, "Checksum didn't match\n");
  }
  return rv;
}

static metalink_checksum *new_metalink_checksum(const char *hash_name,
                                                const char *hash_value)
{
  metalink_checksum *chksum;
  chksum = malloc(sizeof(metalink_checksum));
  chksum->next = NULL;
  chksum->hash_name = strdup(hash_name);
  chksum->hash_value = strdup(hash_value);
  return chksum;
}

static metalink_resource *new_metalink_resource(const char *url)
{
  metalink_resource *res;
  res = malloc(sizeof(metalink_resource));
  res->next = NULL;
  res->url = strdup(url);
  return res;
}

static metalinkfile *new_metalinkfile(metalink_file_t *fileinfo)
{
  metalinkfile *f;
  f = (metalinkfile*)malloc(sizeof(metalinkfile));
  f->next = NULL;
  f->filename = strdup(fileinfo->name);
  f->checksum = NULL;
  f->resource = NULL;
  if(fileinfo->checksums) {
    metalink_checksum_t **p;
    metalink_checksum root, *tail;
    root.next = NULL;
    tail = &root;
    for(p = fileinfo->checksums; *p; ++p) {
      metalink_checksum *chksum;
      chksum = new_metalink_checksum((*p)->type, (*p)->hash);
      tail->next = chksum;
      tail = chksum;
    }
    f->checksum = root.next;
  }
  if(fileinfo->resources) {
    metalink_resource_t **p;
    metalink_resource root, *tail;
    root.next = NULL;
    tail = &root;
    for(p = fileinfo->resources; *p; ++p) {
      metalink_resource *res;
      res = new_metalink_resource((*p)->url);
      tail->next = res;
      tail = res;
    }
    f->resource = root.next;
  }
  return f;
}

int parse_metalink(struct Configurable *config, const char *infile)
{
  metalink_error_t r;
  metalink_t* metalink;
  metalink_file_t **files;

  r = metalink_parse_file(infile, &metalink);
  if(r != 0) {
    return -1;
  }
  if(metalink->files == NULL) {
    fprintf(config->errors, "\nMetalink does not contain any file.\n");
    metalink_delete(metalink);
    return 0;
  }
  for(files = metalink->files; *files; ++files) {
    struct getout *url;
    /* Skip an entry which has no resource. */
    if(!(*files)->resources) {
      fprintf(config->errors, "\nFile %s does not have any resource.\n",
              (*files)->name);
      continue;
    }
    if(config->url_get ||
       ((config->url_get = config->url_list) != NULL)) {
      /* there's a node here, if it already is filled-in continue to
         find an "empty" node */
      while(config->url_get && (config->url_get->flags & GETOUT_URL))
        config->url_get = config->url_get->next;
    }

    /* now there might or might not be an available node to fill in! */

    if(config->url_get)
      /* existing node */
      url = config->url_get;
    else
      /* there was no free node, create one! */
      url = new_getout(config);

    if(url) {
      metalinkfile *mlfile;
      mlfile = new_metalinkfile(*files);

      /* Set name as url */
      GetStr(&url->url, mlfile->filename);

      /* set flag metalink here */
      url->flags |= GETOUT_URL | GETOUT_METALINK;

      if(config->metalinkfile_list) {
        config->metalinkfile_last->next = mlfile;
        config->metalinkfile_last = mlfile;
      }
      else {
        config->metalinkfile_list = config->metalinkfile_last = mlfile;
      }
    }
  }
  metalink_delete(metalink);
  return 0;
}

/*
 * Returns nonzero if content_type includes mediatype.
 */
static int check_content_type(const char *content_type, const char *media_type)
{
  const char *ptr = content_type;
  size_t media_type_len = strlen(media_type);
  for(; *ptr && (*ptr == ' ' || *ptr == '\t'); ++ptr);
  if(!*ptr) {
    return 0;
  }
  return Curl_raw_nequal(ptr, media_type, media_type_len) &&
    (*(ptr+media_type_len) == '\0' || *(ptr+media_type_len) == ' ' ||
     *(ptr+media_type_len) == '\t' || *(ptr+media_type_len) == ';');
}

int check_metalink_content_type(const char *content_type)
{
  return check_content_type(content_type, "application/metalink+xml");
}

int count_next_metalink_resource(metalinkfile *mlfile)
{
  int count = 0;
  metalink_resource *res;
  for(res = mlfile->resource; res; res = res->next, ++count);
  return count;
}

static void delete_metalink_checksum(metalink_checksum *chksum)
{
  if(chksum == NULL) {
    return;
  }
  Curl_safefree(chksum->hash_value);
  Curl_safefree(chksum->hash_name);
  Curl_safefree(chksum);
}

static void delete_metalink_resource(metalink_resource *res)
{
  if(res == NULL) {
    return;
  }
  Curl_safefree(res->url);
  Curl_safefree(res);
}

static void delete_metalinkfile(metalinkfile *mlfile)
{
  metalink_checksum *mc;
  metalink_resource *res;
  if(mlfile == NULL) {
    return;
  }
  Curl_safefree(mlfile->filename);
  for(mc = mlfile->checksum; mc;) {
    metalink_checksum *next;
    next = mc->next;
    delete_metalink_checksum(mc);
    mc = next;
  }
  for(res = mlfile->resource; res;) {
    metalink_resource *next;
    next = res->next;
    delete_metalink_resource(res);
    res = next;
  }
  Curl_safefree(mlfile);
}

void clean_metalink(struct Configurable *config)
{
  while(config->metalinkfile_list) {
    metalinkfile *mlfile = config->metalinkfile_list;
    config->metalinkfile_list = config->metalinkfile_list->next;
    delete_metalinkfile(mlfile);
  }
  config->metalinkfile_last = 0;
}

#endif /* USE_METALINK */
