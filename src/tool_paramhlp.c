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
#include "tool_setup.h"

#include "tool_cfgable.h"
#include "tool_getparam.h"
#include "tool_getpass.h"
#include "tool_msgs.h"
#include "tool_paramhlp.h"
#include "tool_libinfo.h"
#include "tool_util.h"
#include "tool_version.h"

#include "memdebug.h" /* keep this as LAST include */

struct getout *new_getout(struct OperationConfig *config)
{
  struct getout *node = calloc(1, sizeof(struct getout));
  struct getout *last = config->url_last;
  if(node) {
    static int outnum = 0;

    /* append this new node last in the list */
    if(last)
      last->next = node;
    else
      config->url_list = node; /* first node */

    /* move the last pointer */
    config->url_last = node;

    node->useremote = config->remote_name_all;
    node->num = outnum++;
  }
  return node;
}

#define ISCRLF(x) (((x) == '\r') || ((x) == '\n') || ((x) == '\0'))

/* memcrlf() has two modes. Both operate on a given memory area with
   a specified size.

   countcrlf FALSE - return number of bytes from the start that DO NOT include
   any CR or LF or NULL

   countcrlf TRUE - return number of bytes from the start that are ONLY CR or
   LF or NULL.

*/
static size_t memcrlf(char *orig,
                      bool countcrlf, /* TRUE if we count CRLF, FALSE
                                         if we count non-CRLF */
                      size_t max)
{
  char *ptr;
  size_t total = max;
  for(ptr = orig; max; max--, ptr++) {
    bool crlf = ISCRLF(*ptr);
    if(countcrlf ^ crlf)
      return ptr - orig;
  }
  return total; /* no delimiter found */
}

#define MAX_FILE2STRING MAX_FILE2MEMORY

ParameterError file2string(char **bufp, FILE *file)
{
  struct dynbuf dyn;
  curlx_dyn_init(&dyn, MAX_FILE2STRING);
  if(file) {
    do {
      char buffer[4096];
      char *ptr;
      size_t nread = fread(buffer, 1, sizeof(buffer), file);
      if(ferror(file)) {
        curlx_dyn_free(&dyn);
        *bufp = NULL;
        return PARAM_READ_ERROR;
      }
      ptr = buffer;
      while(nread) {
        size_t nlen = memcrlf(ptr, FALSE, nread);
        if(curlx_dyn_addn(&dyn, ptr, nlen))
          return PARAM_NO_MEM;
        nread -= nlen;

        if(nread) {
          ptr += nlen;
          nlen = memcrlf(ptr, TRUE, nread);
          ptr += nlen;
          nread -= nlen;
        }
      }
    } while(!feof(file));
  }
  *bufp = curlx_dyn_ptr(&dyn);
  return PARAM_OK;
}

static int myfseek(void *stream, curl_off_t offset, int whence)
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

ParameterError file2memory_range(char **bufp, size_t *size, FILE *file,
                                 curl_off_t starto, curl_off_t endo)
{
  if(file) {
    size_t nread;
    struct dynbuf dyn;
    curl_off_t offset = 0;
    curl_off_t throwaway = 0;

    if(starto) {
      if(file != stdin) {
        if(myfseek(file, starto, SEEK_SET))
          return PARAM_READ_ERROR;
        offset = starto;
      }
      else
        /* we can't seek stdin, read 'starto' bytes and throw them away */
        throwaway = starto;
    }

    /* The size needs to fit in an int later */
    curlx_dyn_init(&dyn, MAX_FILE2MEMORY);
    do {
      char buffer[4096];
      size_t n_add;
      char *ptr_add;
      nread = fread(buffer, 1, sizeof(buffer), file);
      if(ferror(file)) {
        curlx_dyn_free(&dyn);
        *size = 0;
        *bufp = NULL;
        return PARAM_READ_ERROR;
      }
      n_add = nread;
      ptr_add = buffer;
      if(nread) {
        if(throwaway) {
          if(throwaway >= (curl_off_t)nread) {
            throwaway -= nread;
            offset += nread;
            n_add = 0; /* nothing to add */
          }
          else {
            /* append the trailing piece */
            n_add = (size_t)(nread - throwaway);
            ptr_add = &buffer[throwaway];
            offset += throwaway;
            throwaway = 0;
          }
        }
        if(n_add) {
          if((curl_off_t)(n_add + offset) > endo)
            n_add = (size_t)(endo - offset + 1);

          if(curlx_dyn_addn(&dyn, ptr_add, n_add))
            return PARAM_NO_MEM;

          offset += n_add;
          if(offset > endo)
            break;
        }
      }
    } while(!feof(file));
    *size = curlx_dyn_len(&dyn);
    *bufp = curlx_dyn_ptr(&dyn);
  }
  else {
    *size = 0;
    *bufp = NULL;
  }
  return PARAM_OK;
}

ParameterError file2memory(char **bufp, size_t *size, FILE *file)
{
  return file2memory_range(bufp, size, file, 0, CURL_OFF_T_MAX);
}

/*
 * Parse the string and write the long in the given address. Return PARAM_OK
 * on success, otherwise a parameter specific error enum.
 *
 * Since this function gets called with the 'nextarg' pointer from within the
 * getparameter a lot, we must check it for NULL before accessing the str
 * data.
 */
static ParameterError getnum(long *val, const char *str, int base)
{
  DEBUGASSERT((base == 8) || (base == 10));
  if(str) {
    curl_off_t num;
    bool is_neg = FALSE;
    if(base == 10) {
      is_neg = (*str == '-');
      if(is_neg)
        str++;
      if(curlx_str_number(&str, &num, LONG_MAX))
        return PARAM_BAD_NUMERIC;
    }
    else { /* base == 8 */
      if(curlx_str_octal(&str, &num, LONG_MAX))
        return PARAM_BAD_NUMERIC;
    }
    if(!curlx_str_single(&str, '\0')) {
      *val = (long)num;
      if(is_neg)
        *val = -*val;
      return PARAM_OK;  /* Ok */
    }
  }
  return PARAM_BAD_NUMERIC; /* badness */
}

ParameterError str2num(long *val, const char *str)
{
  return getnum(val, str, 10);
}

ParameterError oct2nummax(long *val, const char *str, long max)
{
  ParameterError result = getnum(val, str, 8);
  if(result != PARAM_OK)
    return result;
  else if(*val > max)
    return PARAM_NUMBER_TOO_LARGE;
  else if(*val < 0)
    return PARAM_NEGATIVE_NUMERIC;

  return PARAM_OK;
}

/*
 * Parse the string and write the long in the given address. Return PARAM_OK
 * on success, otherwise a parameter error enum. ONLY ACCEPTS POSITIVE NUMBERS!
 *
 * Since this function gets called with the 'nextarg' pointer from within the
 * getparameter a lot, we must check it for NULL before accessing the str
 * data.
 */

ParameterError str2unum(long *val, const char *str)
{
  ParameterError result = getnum(val, str, 10);
  if(result != PARAM_OK)
    return result;
  if(*val < 0)
    return PARAM_NEGATIVE_NUMERIC;

  return PARAM_OK;
}

/*
 * Parse the string and write the long in the given address if it is below the
 * maximum allowed value. Return PARAM_OK on success, otherwise a parameter
 * error enum. ONLY ACCEPTS POSITIVE NUMBERS!
 *
 * Since this function gets called with the 'nextarg' pointer from within the
 * getparameter a lot, we must check it for NULL before accessing the str
 * data.
 */

ParameterError str2unummax(long *val, const char *str, long max)
{
  ParameterError result = str2unum(val, str);
  if(result != PARAM_OK)
    return result;
  if(*val > max)
    return PARAM_NUMBER_TOO_LARGE;

  return PARAM_OK;
}

/*
 * Parse the string as seconds with decimals, and write the number of
 * milliseconds that corresponds in the given address. Return PARAM_OK on
 * success, otherwise a parameter error enum. ONLY ACCEPTS POSITIVE NUMBERS!
 *
 * The 'max' argument is the maximum value allowed, as the numbers are often
 * multiplied when later used.
 *
 * Since this function gets called with the 'nextarg' pointer from within the
 * getparameter a lot, we must check it for NULL before accessing the str
 * data.
 */

ParameterError secs2ms(long *valp, const char *str)
{
  curl_off_t secs;
  long ms = 0;
  const unsigned int digs[] = { 1, 10, 100, 1000, 10000, 100000,
    1000000, 10000000, 100000000 };
  if(!str ||
     curlx_str_number(&str, &secs, LONG_MAX/1000 - 1))
    return PARAM_BAD_NUMERIC;
  if(!curlx_str_single(&str, '.')) {
    curl_off_t fracs;
    const char *s = str;
    size_t len;
    if(curlx_str_number(&str, &fracs, CURL_OFF_T_MAX))
      return PARAM_NUMBER_TOO_LARGE;
    /* how many milliseconds are in fracs ? */
    len = (str - s);
    while((len > CURL_ARRAYSIZE(digs) || (fracs > LONG_MAX/100))) {
      fracs /= 10;
      len--;
    }
    ms = ((long)fracs * 100) / digs[len - 1];
  }

  *valp = (long)secs * 1000 + ms;
  return PARAM_OK;
}

/*
 * Implement protocol sets in null-terminated array of protocol name pointers.
 */

/* Return index of prototype token in set, card(set) if not found.
   Can be called with proto == NULL to get card(set). */
static size_t protoset_index(const char * const *protoset, const char *proto)
{
  const char * const *p = protoset;

  DEBUGASSERT(proto == proto_token(proto));     /* Ensure it is tokenized. */

  for(; *p; p++)
    if(proto == *p)
      break;
  return p - protoset;
}

/* Include protocol token in set. */
static void protoset_set(const char **protoset, const char *proto)
{
  if(proto) {
    size_t n = protoset_index(protoset, proto);

    if(!protoset[n]) {
      DEBUGASSERT(n < proto_count);
      protoset[n] = proto;
      protoset[n + 1] = NULL;
    }
  }
}

/* Exclude protocol token from set. */
static void protoset_clear(const char **protoset, const char *proto)
{
  if(proto) {
    size_t n = protoset_index(protoset, proto);

    if(protoset[n]) {
      size_t m = protoset_index(protoset, NULL) - 1;

      protoset[n] = protoset[m];
      protoset[m] = NULL;
    }
  }
}

/*
 * Parse the string and provide an allocated libcurl compatible protocol
 * string output. Return non-zero on failure, zero on success.
 *
 * The string is a list of protocols
 *
 * Since this function gets called with the 'nextarg' pointer from within the
 * getparameter a lot, we must check it for NULL before accessing the str
 * data.
 */

#define MAX_PROTOSTRING (64*11) /* Enough room for 64 10-chars proto names. */

ParameterError proto2num(const char * const *val, char **ostr, const char *str)
{
  const char **protoset;
  struct dynbuf obuf;
  size_t proto;
  CURLcode result;

  curlx_dyn_init(&obuf, MAX_PROTOSTRING);

  protoset = malloc((proto_count + 1) * sizeof(*protoset));
  if(!protoset)
    return PARAM_NO_MEM;

  /* Preset protocol set with default values. */
  protoset[0] = NULL;
  for(; *val; val++) {
    const char *p = proto_token(*val);

    if(p)
      protoset_set(protoset, p);
  }

  while(*str) {
    const char *next = strchr(str, ',');
    size_t plen;
    enum e_action { allow, deny, set } action = allow;

    if(next) {
      if(str == next) {
        str++;
        continue;
      }
      plen = next - str - 1;
    }
    else
      plen = strlen(str) - 1;

    /* Process token modifiers */
    switch(*str++) {
    case '=':
      action = set;
      break;
    case '-':
      action = deny;
      break;
    case '+':
      action = allow;
      break;
    default:
      /* no modifier */
      str--;
      plen++;
      break;
    }

    if((plen == 3) && curl_strnequal(str, "all", 3)) {
      switch(action) {
      case deny:
        protoset[0] = NULL;
        break;
      case allow:
      case set:
        memcpy((char *) protoset,
               built_in_protos, (proto_count + 1) * sizeof(*protoset));
        break;
      }
    }
    else {
      char buffer[32];
      const char *p;
      msnprintf(buffer, sizeof(buffer), "%.*s", (int)plen, str);

      p = proto_token(buffer);

      if(p)
        switch(action) {
        case deny:
          protoset_clear(protoset, p);
          break;
        case set:
          protoset[0] = NULL;
          FALLTHROUGH();
        case allow:
          protoset_set(protoset, p);
          break;
        }
      else { /* unknown protocol */
        /* If they have specified only this protocol, we say treat it as
           if no protocols are allowed */
        if(action == set)
          protoset[0] = NULL;
        warnf("unrecognized protocol '%s'", buffer);
      }
    }
    if(next)
      str = next + 1;
    else
      break;
  }

  /* We need the protocols in alphabetic order for CI tests requirements. */
  qsort((char *) protoset, protoset_index(protoset, NULL), sizeof(*protoset),
        struplocompare4sort);

  result = curlx_dyn_addn(&obuf, "", 0);
  for(proto = 0; protoset[proto] && !result; proto++)
    result = curlx_dyn_addf(&obuf, "%s,", protoset[proto]);
  free((char *) protoset);
  curlx_dyn_setlen(&obuf, curlx_dyn_len(&obuf) - 1);
  free(*ostr);
  *ostr = curlx_dyn_ptr(&obuf);

  return *ostr ? PARAM_OK : PARAM_NO_MEM;
}

/**
 * Check if the given string is a protocol supported by libcurl
 *
 * @param str  the protocol name
 * @return PARAM_OK  protocol supported
 * @return PARAM_LIBCURL_UNSUPPORTED_PROTOCOL  protocol not supported
 * @return PARAM_REQUIRES_PARAMETER   missing parameter
 */
ParameterError check_protocol(const char *str)
{
  if(!str)
    return PARAM_REQUIRES_PARAMETER;

  if(proto_token(str))
    return PARAM_OK;
  return PARAM_LIBCURL_UNSUPPORTED_PROTOCOL;
}

/**
 * Parses the given string looking for an offset (which may be a
 * larger-than-integer value). The offset CANNOT be negative!
 *
 * @param val  the offset to populate
 * @param str  the buffer containing the offset
 * @return PARAM_OK if successful, a parameter specific error enum if failure.
 */
ParameterError str2offset(curl_off_t *val, const char *str)
{
  if(curlx_str_number(&str, val, CURL_OFF_T_MAX) ||
     curlx_str_single(&str, '\0'))
    return PARAM_BAD_NUMERIC;
  return PARAM_OK;
}

#define MAX_USERPWDLENGTH (100*1024)
static CURLcode checkpasswd(const char *kind, /* for what purpose */
                            const size_t i,   /* operation index */
                            const bool last,  /* TRUE if last operation */
                            char **userpwd)   /* pointer to allocated string */
{
  char *psep;
  char *osep;

  if(!*userpwd)
    return CURLE_OK;

  /* Attempt to find the password separator */
  psep = strchr(*userpwd, ':');

  /* Attempt to find the options separator */
  osep = strchr(*userpwd, ';');

  if(!psep && **userpwd != ';') {
    /* no password present, prompt for one */
    char passwd[2048] = "";
    char prompt[256];
    struct dynbuf dyn;

    curlx_dyn_init(&dyn, MAX_USERPWDLENGTH);
    if(osep)
      *osep = '\0';

    /* build a nice-looking prompt */
    if(!i && last)
      msnprintf(prompt, sizeof(prompt),
                "Enter %s password for user '%s':",
                kind, *userpwd);
    else
      msnprintf(prompt, sizeof(prompt),
                "Enter %s password for user '%s' on URL #%zu:",
                kind, *userpwd, i + 1);

    /* get password */
    getpass_r(prompt, passwd, sizeof(passwd));
    if(osep)
      *osep = ';';

    if(curlx_dyn_addf(&dyn, "%s:%s", *userpwd, passwd))
      return CURLE_OUT_OF_MEMORY;

    /* return the new string */
    free(*userpwd);
    *userpwd = curlx_dyn_ptr(&dyn);
  }

  return CURLE_OK;
}

ParameterError add2list(struct curl_slist **list, const char *ptr)
{
  struct curl_slist *newlist = curl_slist_append(*list, ptr);
  if(newlist)
    *list = newlist;
  else
    return PARAM_NO_MEM;

  return PARAM_OK;
}

long ftpfilemethod(const char *str)
{
  if(curl_strequal("singlecwd", str))
    return CURLFTPMETHOD_SINGLECWD;
  if(curl_strequal("nocwd", str))
    return CURLFTPMETHOD_NOCWD;
  if(curl_strequal("multicwd", str))
    return CURLFTPMETHOD_MULTICWD;

  warnf("unrecognized ftp file method '%s', using default", str);

  return CURLFTPMETHOD_MULTICWD;
}

long ftpcccmethod(const char *str)
{
  if(curl_strequal("passive", str))
    return CURLFTPSSL_CCC_PASSIVE;
  if(curl_strequal("active", str))
    return CURLFTPSSL_CCC_ACTIVE;

  warnf("unrecognized ftp CCC method '%s', using default", str);

  return CURLFTPSSL_CCC_PASSIVE;
}

long delegation(const char *str)
{
  if(curl_strequal("none", str))
    return CURLGSSAPI_DELEGATION_NONE;
  if(curl_strequal("policy", str))
    return CURLGSSAPI_DELEGATION_POLICY_FLAG;
  if(curl_strequal("always", str))
    return CURLGSSAPI_DELEGATION_FLAG;

  warnf("unrecognized delegation method '%s', using none", str);

  return CURLGSSAPI_DELEGATION_NONE;
}

/*
 * my_useragent: returns allocated string with default user agent
 */
static char *my_useragent(void)
{
  return strdup(CURL_NAME "/" CURL_VERSION);
}

#define isheadersep(x) ((((x)==':') || ((x)==';')))

/*
 * inlist() returns true if the given 'checkfor' header is present in the
 * header list.
 */
static bool inlist(const struct curl_slist *head,
                   const char *checkfor)
{
  size_t thislen = strlen(checkfor);
  DEBUGASSERT(thislen);
  DEBUGASSERT(checkfor[thislen-1] != ':');

  for(; head; head = head->next) {
    if(curl_strnequal(head->data, checkfor, thislen) &&
       isheadersep(head->data[thislen]) )
      return TRUE;
  }

  return FALSE;
}

CURLcode get_args(struct OperationConfig *config, const size_t i)
{
  CURLcode result = CURLE_OK;
  bool last = (config->next ? FALSE : TRUE);

  if(config->jsoned) {
    ParameterError err = PARAM_OK;
    /* --json also implies json Content-Type: and Accept: headers - if
       they are not set with -H */
    if(!inlist(config->headers, "Content-Type"))
      err = add2list(&config->headers, "Content-Type: application/json");
    if(!err && !inlist(config->headers, "Accept"))
      err = add2list(&config->headers, "Accept: application/json");
    if(err)
      return CURLE_OUT_OF_MEMORY;
  }

  /* Check if we have a password for the given host user */
  if(config->userpwd && !config->oauth_bearer)
    result = checkpasswd("host", i, last, &config->userpwd);

  /* Check if we have a password for the given proxy user */
  if(!result && config->proxyuserpwd)
    result = checkpasswd("proxy", i, last, &config->proxyuserpwd);

  /* Check if we have a user agent */
  if(!result && !config->useragent) {
    config->useragent = my_useragent();
    if(!config->useragent) {
      errorf("out of memory");
      result = CURLE_OUT_OF_MEMORY;
    }
  }

  return result;
}

/*
 * Parse the string and modify ssl_version in the val argument. Return PARAM_OK
 * on success, otherwise a parameter error enum. ONLY ACCEPTS POSITIVE NUMBERS!
 *
 * Since this function gets called with the 'nextarg' pointer from within the
 * getparameter a lot, we must check it for NULL before accessing the str
 * data.
 */

ParameterError str2tls_max(unsigned char *val, const char *str)
{
  static struct s_tls_max {
    const char *tls_max_str;
    unsigned char tls_max;
  } const tls_max_array[] = {
    { "default", 0 }, /* lets the library decide */
    { "1.0",     1 },
    { "1.1",     2 },
    { "1.2",     3 },
    { "1.3",     4 }
  };
  size_t i = 0;
  if(!str)
    return PARAM_REQUIRES_PARAMETER;
  for(i = 0; i < CURL_ARRAYSIZE(tls_max_array); i++) {
    if(!strcmp(str, tls_max_array[i].tls_max_str)) {
      *val = tls_max_array[i].tls_max;
      return PARAM_OK;
    }
  }
  return PARAM_BAD_USE;
}
