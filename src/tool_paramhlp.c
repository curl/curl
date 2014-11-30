/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2014, Daniel Stenberg, <daniel@haxx.se>, et al.
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

#include "rawstr.h"

#define ENABLE_CURLX_PRINTF
/* use our own printf() functions */
#include "curlx.h"

#include "tool_cfgable.h"
#include "tool_getparam.h"
#include "tool_getpass.h"
#include "tool_homedir.h"
#include "tool_msgs.h"
#include "tool_paramhlp.h"
#include "tool_version.h"

#include "memdebug.h" /* keep this as LAST include */

struct getout *new_getout(struct OperationConfig *config)
{
  struct getout *node = calloc(1, sizeof(struct getout));
  struct getout *last = config->url_last;
  if(node) {
    /* append this new node last in the list */
    if(last)
      last->next = node;
    else
      config->url_list = node; /* first node */

    /* move the last pointer */
    config->url_last = node;

    node->flags = config->default_node_flags;
  }
  return node;
}

ParameterError file2string(char **bufp, FILE *file)
{
  char buffer[256];
  char *ptr;
  char *string = NULL;
  size_t stringlen = 0;
  size_t buflen;

  if(file) {
    while(fgets(buffer, sizeof(buffer), file)) {
      if((ptr = strchr(buffer, '\r')) != NULL)
        *ptr = '\0';
      if((ptr = strchr(buffer, '\n')) != NULL)
        *ptr = '\0';
      buflen = strlen(buffer);
      if((ptr = realloc(string, stringlen+buflen+1)) == NULL) {
        Curl_safefree(string);
        return PARAM_NO_MEM;
      }
      string = ptr;
      strcpy(string+stringlen, buffer);
      stringlen += buflen;
    }
  }
  *bufp = string;
  return PARAM_OK;
}

ParameterError file2memory(char **bufp, size_t *size, FILE *file)
{
  char *newbuf;
  char *buffer = NULL;
  size_t alloc = 512;
  size_t nused = 0;
  size_t nread;

  if(file) {
    do {
      if(!buffer || (alloc == nused)) {
        /* size_t overflow detection for huge files */
        if(alloc+1 > ((size_t)-1)/2) {
          Curl_safefree(buffer);
          return PARAM_NO_MEM;
        }
        alloc *= 2;
        /* allocate an extra char, reserved space, for null termination */
        if((newbuf = realloc(buffer, alloc+1)) == NULL) {
          Curl_safefree(buffer);
          return PARAM_NO_MEM;
        }
        buffer = newbuf;
      }
      nread = fread(buffer+nused, 1, alloc-nused, file);
      nused += nread;
    } while(nread);
    /* null terminate the buffer in case it's used as a string later */
    buffer[nused] = '\0';
    /* free trailing slack space, if possible */
    if(alloc != nused) {
      if((newbuf = realloc(buffer, nused+1)) == NULL) {
        Curl_safefree(buffer);
        return PARAM_NO_MEM;
      }
      buffer = newbuf;
    }
    /* discard buffer if nothing was read */
    if(!nused) {
      Curl_safefree(buffer); /* no string */
    }
  }
  *size = nused;
  *bufp = buffer;
  return PARAM_OK;
}

void cleanarg(char *str)
{
#ifdef HAVE_WRITABLE_ARGV
  /* now that GetStr has copied the contents of nextarg, wipe the next
   * argument out so that the username:password isn't displayed in the
   * system process list */
  if(str) {
    size_t len = strlen(str);
    memset(str, ' ', len);
  }
#else
  (void)str;
#endif
}

/*
 * Parse the string and write the long in the given address. Return PARAM_OK
 * on success, otherwise a parameter specific error enum.
 *
 * Since this function gets called with the 'nextarg' pointer from within the
 * getparameter a lot, we must check it for NULL before accessing the str
 * data.
 */

ParameterError str2num(long *val, const char *str)
{
  if(str) {
    char *endptr;
    long num = strtol(str, &endptr, 10);
    if((endptr != str) && (endptr == str + strlen(str))) {
      *val = num;
      return PARAM_OK;  /* Ok */
    }
  }
  return PARAM_BAD_NUMERIC; /* badness */
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
  ParameterError result = str2num(val, str);
  if(result != PARAM_OK)
    return result;
  if(*val < 0)
    return PARAM_NEGATIVE_NUMERIC;

  return PARAM_OK;
}

/*
 * Parse the string and write the double in the given address. Return PARAM_OK
 * on success, otherwise a parameter specific error enum.
 *
 * Since this function gets called with the 'nextarg' pointer from within the
 * getparameter a lot, we must check it for NULL before accessing the str
 * data.
 */

ParameterError str2double(double *val, const char *str)
{
  if(str) {
    char *endptr;
    double num = strtod(str, &endptr);
    if((endptr != str) && (endptr == str + strlen(str))) {
      *val = num;
      return PARAM_OK;  /* Ok */
    }
  }
  return PARAM_BAD_NUMERIC; /* badness */
}

/*
 * Parse the string and write the double in the given address. Return PARAM_OK
 * on success, otherwise a parameter error enum. ONLY ACCEPTS POSITIVE NUMBERS!
 *
 * Since this function gets called with the 'nextarg' pointer from within the
 * getparameter a lot, we must check it for NULL before accessing the str
 * data.
 */

ParameterError str2udouble(double *val, const char *str)
{
  ParameterError result = str2double(val, str);
  if(result != PARAM_OK)
    return result;
  if(*val < 0)
    return PARAM_NEGATIVE_NUMERIC;

  return PARAM_OK;
}

/*
 * Parse the string and modify the long in the given address. Return
 * non-zero on failure, zero on success.
 *
 * The string is a list of protocols
 *
 * Since this function gets called with the 'nextarg' pointer from within the
 * getparameter a lot, we must check it for NULL before accessing the str
 * data.
 */

long proto2num(struct OperationConfig *config, long *val, const char *str)
{
  char *buffer;
  const char *sep = ",";
  char *token;

  static struct sprotos {
    const char *name;
    long bit;
  } const protos[] = {
    { "all", CURLPROTO_ALL },
    { "http", CURLPROTO_HTTP },
    { "https", CURLPROTO_HTTPS },
    { "ftp", CURLPROTO_FTP },
    { "ftps", CURLPROTO_FTPS },
    { "scp", CURLPROTO_SCP },
    { "sftp", CURLPROTO_SFTP },
    { "telnet", CURLPROTO_TELNET },
    { "ldap", CURLPROTO_LDAP },
    { "ldaps", CURLPROTO_LDAPS },
    { "dict", CURLPROTO_DICT },
    { "file", CURLPROTO_FILE },
    { "tftp", CURLPROTO_TFTP },
    { "imap", CURLPROTO_IMAP },
    { "imaps", CURLPROTO_IMAPS },
    { "pop3", CURLPROTO_POP3 },
    { "pop3s", CURLPROTO_POP3S },
    { "smtp", CURLPROTO_SMTP },
    { "smtps", CURLPROTO_SMTPS },
    { "rtsp", CURLPROTO_RTSP },
    { "gopher", CURLPROTO_GOPHER },
    { "smb", CURLPROTO_SMB },
    { "smbs", CURLPROTO_SMBS },
    { NULL, 0 }
  };

  if(!str)
    return 1;

  buffer = strdup(str); /* because strtok corrupts it */
  if(!buffer)
    return 1;

  for(token = strtok(buffer, sep);
      token;
      token = strtok(NULL, sep)) {
    enum e_action { allow, deny, set } action = allow;

    struct sprotos const *pp;

    /* Process token modifiers */
    while(!ISALNUM(*token)) { /* may be NULL if token is all modifiers */
      switch (*token++) {
      case '=':
        action = set;
        break;
      case '-':
        action = deny;
        break;
      case '+':
        action = allow;
        break;
      default: /* Includes case of terminating NULL */
        Curl_safefree(buffer);
        return 1;
      }
    }

    for(pp=protos; pp->name; pp++) {
      if(curlx_raw_equal(token, pp->name)) {
        switch (action) {
        case deny:
          *val &= ~(pp->bit);
          break;
        case allow:
          *val |= pp->bit;
          break;
        case set:
          *val = pp->bit;
          break;
        }
        break;
      }
    }

    if(!(pp->name)) { /* unknown protocol */
      /* If they have specified only this protocol, we say treat it as
         if no protocols are allowed */
      if(action == set)
        *val = 0;
      warnf(config, "unrecognized protocol '%s'\n", token);
    }
  }
  Curl_safefree(buffer);
  return 0;
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
  char *endptr;
  if(str[0] == '-')
    /* offsets aren't negative, this indicates weird input */
    return PARAM_NEGATIVE_NUMERIC;

#if(CURL_SIZEOF_CURL_OFF_T > CURL_SIZEOF_LONG)
  *val = curlx_strtoofft(str, &endptr, 0);
  if((*val == CURL_OFF_T_MAX || *val == CURL_OFF_T_MIN) && (ERRNO == ERANGE))
    return PARAM_BAD_NUMERIC;
#else
  *val = strtol(str, &endptr, 0);
  if((*val == LONG_MIN || *val == LONG_MAX) && ERRNO == ERANGE)
    return PARAM_BAD_NUMERIC;
#endif
  if((endptr != str) && (endptr == str + strlen(str)))
    return PARAM_OK;

  return PARAM_BAD_NUMERIC;
}

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
    char passwd[256] = "";
    char prompt[256];
    size_t passwdlen;
    size_t userlen = strlen(*userpwd);
    char *passptr;

    if(osep)
      *osep = '\0';

    /* build a nice-looking prompt */
    if(!i && last)
      curlx_msnprintf(prompt, sizeof(prompt),
                      "Enter %s password for user '%s':",
                      kind, *userpwd);
    else
      curlx_msnprintf(prompt, sizeof(prompt),
                      "Enter %s password for user '%s' on URL #%"
                      CURL_FORMAT_CURL_OFF_TU ":",
                      kind, *userpwd, i + 1);

    /* get password */
    getpass_r(prompt, passwd, sizeof(passwd));
    passwdlen = strlen(passwd);

    if(osep)
      *osep = ';';

    /* extend the allocated memory area to fit the password too */
    passptr = realloc(*userpwd,
                      passwdlen + 1 + /* an extra for the colon */
                      userlen + 1);   /* an extra for the zero */
    if(!passptr)
      return CURLE_OUT_OF_MEMORY;

    /* append the password separated with a colon */
    passptr[userlen] = ':';
    memcpy(&passptr[userlen+1], passwd, passwdlen+1);
    *userpwd = passptr;
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

int ftpfilemethod(struct OperationConfig *config, const char *str)
{
  if(curlx_raw_equal("singlecwd", str))
    return CURLFTPMETHOD_SINGLECWD;
  if(curlx_raw_equal("nocwd", str))
    return CURLFTPMETHOD_NOCWD;
  if(curlx_raw_equal("multicwd", str))
    return CURLFTPMETHOD_MULTICWD;
  warnf(config, "unrecognized ftp file method '%s', using default\n", str);
  return CURLFTPMETHOD_MULTICWD;
}

int ftpcccmethod(struct OperationConfig *config, const char *str)
{
  if(curlx_raw_equal("passive", str))
    return CURLFTPSSL_CCC_PASSIVE;
  if(curlx_raw_equal("active", str))
    return CURLFTPSSL_CCC_ACTIVE;
  warnf(config, "unrecognized ftp CCC method '%s', using default\n", str);
  return CURLFTPSSL_CCC_PASSIVE;
}

long delegation(struct OperationConfig *config, char *str)
{
  if(curlx_raw_equal("none", str))
    return CURLGSSAPI_DELEGATION_NONE;
  if(curlx_raw_equal("policy", str))
    return CURLGSSAPI_DELEGATION_POLICY_FLAG;
  if(curlx_raw_equal("always", str))
    return CURLGSSAPI_DELEGATION_FLAG;
  warnf(config, "unrecognized delegation method '%s', using none\n", str);
  return CURLGSSAPI_DELEGATION_NONE;
}

/*
 * my_useragent: returns allocated string with default user agent
 */
static char *my_useragent(void)
{
  return strdup(CURL_NAME "/" CURL_VERSION);
}

CURLcode get_args(struct OperationConfig *config, const size_t i)
{
  CURLcode result = CURLE_OK;
  bool last = (config->next ? FALSE : TRUE);

  /* Check we have a password for the given host user */
  if(config->userpwd && !config->xoauth2_bearer) {
    result = checkpasswd("host", i, last, &config->userpwd);
    if(result)
      return result;
  }

  /* Check we have a password for the given proxy user */
  if(config->proxyuserpwd) {
    result = checkpasswd("proxy", i, last, &config->proxyuserpwd);
    if(result)
      return result;
  }

  /* Check we have a user agent */
  if(!config->useragent) {
    config->useragent = my_useragent();
    if(!config->useragent) {
      helpf(config->global->errors, "out of memory\n");
      result = CURLE_OUT_OF_MEMORY;
    }
  }

  return result;
}
