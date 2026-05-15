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

#ifndef CURL_DISABLE_NETRC

#ifdef HAVE_PWD_H
#ifdef __AMIGA__
#undef __NO_NET_API /* required for AmigaOS to declare getpwuid() */
#endif
#include <pwd.h>
#ifdef __AMIGA__
#define __NO_NET_API
#endif
#endif

#include "netrc.h"
#include "urldata.h"
#include "creds.h"
#include "curl_trc.h"
#include "strcase.h"
#include "curl_get_line.h"
#include "curlx/fopen.h"
#include "curlx/strparse.h"


/* .netrc is not really a standard. The GNU definition can be found here:
 * https://www.gnu.org/software/inetutils/manual/\
 *            html_node/The-_002enetrc-file.html
 * This gives grammar like:
 *
 * LITERAL := \S+ | QUOTED
 * QUOTED  := "(\\[rnt\]|[^"])*"
 * ANYTHING := .
 * EMPTY_LINE := \r*\n\r*\n
 * MACHINE := machine         # case-insensitive
 * LOGIN   := login           # case-insensitive
 * PASSWD  := password        # case-insensitive
 * ACCOUNT := account         # case-insensitive
 * MACDEF  := macdef          # case-insensitive
 * DEFAULT := default         # case-insensitive
 *
 * MACRO   := MACDEF ANYTHING* EMPTY_LINE
 * JUNK    := LITERAL
 * LKEY     := ( LOGIN | PASSWD | ACCOUNT ) LITERAL
 * MENTRY   := MACHINE LITERAL LKEY*
 * DENTRY   := DEFAULT LKEY*
 * NETRC   := (MENTRY | DENTRY | MACRO | JUNK )* EOF
 *
 * Tokens are separated by whitespace or newlines. which have otherwise
 * no special meaning, apart from the empty line ending a MACRO.
 *
 * Parsing is not strict, unmatched LITERALs are ignored
 */

#define MAX_NETRC_LINE  16384
#define MAX_NETRC_FILE  (128 * 1024)
#define MAX_NETRC_TOKEN 4096

#define NETRC_DEBUG   0

/* convert a dynbuf call CURLcode error to a NETRCcode error */
#define curl2netrc(r)                     \
  ((!(r)) ? NETRC_OK : (((r) == CURLE_OUT_OF_MEMORY) ?         \
   NETRC_OUT_OF_MEMORY : NETRC_SYNTAX_ERROR))

typedef enum {
  NETRC_TOK_EOF,
  NETRC_TOK_LITERAL,
  NETRC_TOK_MACHINE,
  NETRC_TOK_DEFAULT,
  NETRC_TOK_ACCOUNT,
  NETRC_TOK_LOGIN,
  NETRC_TOK_PASSWD,
  NETRC_TOK_MACDEF,
  NETRC_TOK_JUNK
} curl_netrc_token;

struct netrc_lexer {
  struct Curl_easy *data;
  const char *content;
  const char *pos;
  struct dynbuf literal;
  curl_netrc_token token;
  bool pushed;
};

#if NETRC_DEBUG
static const char *netrc_tokenstr(curl_netrc_token token)
{
  switch(token) {
  case NETRC_TOK_EOF:
    return "[EOF]";
  case NETRC_TOK_LITERAL:
    return "[LITERAL]";
  case NETRC_TOK_MACHINE:
    return "[MACHINE]";
  case NETRC_TOK_DEFAULT:
    return "[DEFAULT]";
  case NETRC_TOK_ACCOUNT:
    return "[ACCOUNT]";
  case NETRC_TOK_LOGIN:
    return "[LOGIN]";
  case NETRC_TOK_PASSWD:
    return "[PASSWORD]";
  case NETRC_TOK_MACDEF:
    return "[MACDEF]";
  case NETRC_TOK_JUNK:
    return "[JUNK]";
  default:
    return "[???]";
  }
}

#endif

static void netrc_lexer_init(struct netrc_lexer *lexer,
                             struct Curl_easy *data,
                             const char *content)
{
  curlx_dyn_init(&lexer->literal, MAX_NETRC_TOKEN);
  lexer->data = data;
  lexer->content = lexer->pos = content;
}

static void netrc_lexer_cleanup(struct netrc_lexer *lexer)
{
  lexer->content = lexer->pos = NULL;
  lexer->data = NULL;
  curlx_dyn_free(&lexer->literal);
}

static void netrc_skip_blanks(struct netrc_lexer *lexer)
{
  const char *s = lexer->pos;
  while(*s) {
    curlx_str_passblanks(&s);
    while(*s == '\r')
      ++s;
    if(*s == '\n') {
      ++s;
    }
    else
      break;
  }
  lexer->pos = s;
}

static void netrc_skip_to_empty_line(struct netrc_lexer *lexer)
{
  const char *s = lexer->pos;
  while(*s) {
    if(*s == '\r')
      ++s;
    else if(*s == '\n') {
      ++s;
      while(*s == '\r')
        ++s;
      if(*s == '\n')
        goto out;
    }
    else
      ++s;
  }
out:
  lexer->pos = s;
}

/*
 * Parse a quoted token starting after the opening '"'. Handles \n, \r, \t
 * escape sequences. Advances *tok_endp past the closing '"'.
 *
 * Returns NETRC_OK or error.
 */
static NETRCcode netrc_lexer_quoted(struct netrc_lexer *lexer)
{
  NETRCcode rc = NETRC_SYNTAX_ERROR;
  const char *s = lexer->pos;
  bool escape = FALSE;
  CURLcode result;

  DEBUGASSERT(*s == '\"');
  ++s; /* pass the leading quote */
  while(*s) {
    char c = *s;
    if(escape) {
      escape = FALSE;
      switch(c) {
      case 'n':
        c = '\n';
        break;
      case 'r':
        c = '\r';
        break;
      case 't':
        c = '\t';
        break;
      }
    }
    else if(c == '\\') {
      escape = TRUE;
      ++s;
      continue;
    }
    else if(c == '\"') {
      ++s; /* pass the ending quote */
      rc = NETRC_OK;
      goto out;
    }
    result = curlx_dyn_addn(&lexer->literal, &c, 1);
    if(result) {
      rc = curl2netrc(result);
      goto out;
    }
    ++s;
  }
out:
  lexer->pos = s;
  return rc;
}

static void netrc_lexer_push(struct netrc_lexer *lexer)
{
  lexer->pushed = TRUE;
}

static NETRCcode netrc_lexer_next(struct netrc_lexer *lexer,
                                  bool want_literal)
{
  const char *s = lexer->pos, *start;
  NETRCcode rc = NETRC_OK;
  size_t slen;
  CURLcode result;

  if(lexer->pushed) {
    lexer->pushed = FALSE;
    goto out;
  }

  curlx_dyn_reset(&lexer->literal);
  netrc_skip_blanks(lexer);
  s = lexer->pos;

  switch(*s) {
  case 0:
    lexer->token = NETRC_TOK_EOF;
    break;
  case '\"':
    rc = netrc_lexer_quoted(lexer);
    lexer->token = NETRC_TOK_LITERAL;
    s = lexer->pos;
    break;
  default:
    /* unquoted token */
    start = s;
    while(*s && !ISBLANK(*s) && !ISNEWLINE(*s))
      ++s;
    slen = s - start;
    if(!slen) {
      rc = NETRC_SYNTAX_ERROR;
    }
    if(want_literal) {
      lexer->token = NETRC_TOK_LITERAL;
      result = curlx_dyn_addn(&lexer->literal, start, slen);
      rc = curl2netrc(result);
    }
    else if((slen == 7) && curl_strnequal(start, "machine", slen)) {
      lexer->token = NETRC_TOK_MACHINE;
    }
    else if((slen == 7) && curl_strnequal(start, "default", slen)) {
      lexer->token = NETRC_TOK_DEFAULT;
    }
    else if((slen == 7) && curl_strnequal(start, "account", slen)) {
      lexer->token = NETRC_TOK_ACCOUNT;
    }
    else if((slen == 5) && curl_strnequal(start, "login", slen)) {
      lexer->token = NETRC_TOK_LOGIN;
    }
    else if((slen == 8) && curl_strnequal(start, "password", slen)) {
      lexer->token = NETRC_TOK_PASSWD;
    }
    else if((slen == 6) && curl_strnequal(start, "macdef", slen)) {
      lexer->token = NETRC_TOK_MACDEF;
    }
    else {
      lexer->token = NETRC_TOK_JUNK;
    }
    break;
  }

out:
#if NETRC_DEBUG
  CURL_TRC_M(lexer->data, "[NETRC] token %s '%s', rc=%d",
             netrc_tokenstr(lexer->token),
             curlx_dyn_ptr(&lexer->literal), rc);
#endif
  lexer->pos = s;
  return rc;
}

struct netrc_scanner {
  struct netrc_lexer lexer;
  const char *hostname; /* non-NULL, machine to scan for */
  const char *user; /* maybe NULL, login to scan for */
  char *login;
  char *passwd;
  struct Curl_creds *creds;
  bool matches_host;
  bool found;
};

static void netrc_scan_reset(struct netrc_scanner *sc)
{
  curlx_safefree(sc->login);
  curlx_safefree(sc->passwd);
  sc->matches_host = FALSE;
}

static void netrc_scan_init(struct netrc_scanner *sc,
                            struct Curl_easy *data,
                            const char *content,
                            const char *hostname,
                            const char *user)
{
  memset(sc, 0, sizeof(*sc));
  netrc_lexer_init(&sc->lexer, data, content);
  sc->hostname = hostname;
  sc->user = (user && user[0]) ? user : NULL;
  netrc_scan_reset(sc);
}

static void netrc_scan_cleanup(struct netrc_scanner *sc)
{
  netrc_scan_reset(sc);
  sc->hostname = NULL;
  sc->user = NULL;
  Curl_creds_unlink(&sc->creds);
  netrc_lexer_cleanup(&sc->lexer);
}

static NETRCcode netrc_scan_literal(struct netrc_scanner *sc,
                                    char **pdest)
{
  NETRCcode rc = netrc_lexer_next(&sc->lexer, TRUE);
  if(!rc) {
    if(sc->lexer.token == NETRC_TOK_LITERAL) {
      if(pdest && sc->matches_host) {
        curlx_free(*pdest);
        *pdest = curlx_strdup(curlx_dyn_ptr(&sc->lexer.literal));
        if(!*pdest)
          rc = NETRC_OUT_OF_MEMORY;
      }
    }
    else
      netrc_lexer_push(&sc->lexer);
  }
  return rc;
}

static NETRCcode netrc_scan_end_entry(struct netrc_scanner *sc)
{
  NETRCcode rc = NETRC_OK;
#if NETRC_DEBUG
  CURL_TRC_M(sc->lexer.data,
             "[NETRC] entry matches_host=%d, login='%s', passwd='%s'",
             sc->matches_host, sc->login, sc->passwd);
#endif
  if(sc->matches_host) {
    if(sc->login) {
      if(sc->user) {
        if(Curl_timestrcmp(sc->user, sc->login))
          goto out;
        /* We look for a specific user,
         * entry is only interesting with password */
        sc->found = !!sc->passwd;
      }
      else {
        sc->found = TRUE;
      }
    }
    else if(sc->passwd) {
      /* found a passwd that applies to any user */
      sc->found = TRUE;
    }
    else {
      /* entry has nothing interesting */
    }
    if(sc->found) {
#if NETRC_DEBUG
      CURL_TRC_M(sc->lexer.data, "[NETRC] entry match found");
#endif
      if(Curl_creds_create(sc->user ? sc->user : sc->login, sc->passwd,
                           NULL, NULL, NULL, CREDS_NETRC, &sc->creds))
        rc = NETRC_OUT_OF_MEMORY;
    }
  }
out:
  netrc_scan_reset(sc);
  return rc;
}

static NETRCcode netrc_scan(struct Curl_easy *data,
                            const char *content,
                            const char *hostname,
                            const char *user,
                            struct Curl_creds **pcreds)
{
  struct netrc_scanner sc;
  NETRCcode rc = NETRC_OK;

  Curl_creds_unlink(pcreds);
  netrc_scan_init(&sc, data, content, hostname, user);

  while(!rc && !sc.found) {
    rc = netrc_lexer_next(&sc.lexer, FALSE);
    if(!rc) {
      /* Does this token end any previous entry? */
      switch(sc.lexer.token) {
      case NETRC_TOK_EOF:
      case NETRC_TOK_MACHINE:
      case NETRC_TOK_DEFAULT:
      case NETRC_TOK_MACDEF:
        rc = netrc_scan_end_entry(&sc);
        if(rc || sc.found)
          goto out;
        break;
      default:
        break;
      }

      switch(sc.lexer.token) {
      case NETRC_TOK_EOF:
        goto out;
      case NETRC_TOK_MACHINE:
        rc = netrc_lexer_next(&sc.lexer, TRUE);
        if(!rc) {
          if(sc.lexer.token == NETRC_TOK_LITERAL) {
            sc.matches_host = curl_strequal(
              sc.hostname, curlx_dyn_ptr(&sc.lexer.literal));
          }
          else {
            sc.matches_host = FALSE;
            netrc_lexer_push(&sc.lexer);
          }
        }
        break;
      case NETRC_TOK_DEFAULT:
        sc.matches_host = TRUE;
        break;
      case NETRC_TOK_ACCOUNT:
        rc = netrc_scan_literal(&sc, NULL); /* ignore, not used */
        break;
      case NETRC_TOK_LOGIN:
        rc = netrc_scan_literal(&sc, &sc.login);
        break;
      case NETRC_TOK_PASSWD:
        rc = netrc_scan_literal(&sc, &sc.passwd);
        break;
      case NETRC_TOK_MACDEF:
        netrc_skip_to_empty_line(&sc.lexer);
        break;
      case NETRC_TOK_LITERAL:
      case NETRC_TOK_JUNK:
      default:
        /* skip this */
        break;
      }
    }
  }

out:
  if(!rc) {
    if(sc.creds)
      Curl_creds_link(pcreds, sc.creds);
    else
      rc = NETRC_NO_MATCH;
  }
  netrc_scan_cleanup(&sc);
  return rc;
}

static NETRCcode file2memory(const char *filename, struct dynbuf *filebuf)
{
  NETRCcode ret = NETRC_FILE_MISSING; /* if it cannot open the file */
  FILE *file = curlx_fopen(filename, FOPEN_READTEXT);

  if(file) {
    curlx_struct_stat stat;
    if((curlx_fstat(fileno(file), &stat) == -1) || !S_ISDIR(stat.st_mode)) {
      CURLcode result = CURLE_OK;
      bool eof;
      struct dynbuf linebuf;
      curlx_dyn_init(&linebuf, MAX_NETRC_LINE);
      ret = NETRC_OK;
      do {
        const char *line;
        /* Curl_get_line always returns lines ending with a newline */
        result = Curl_get_line(&linebuf, file, &eof);
        if(!result) {
          line = curlx_dyn_ptr(&linebuf);
          /* skip comments on load */
          curlx_str_passblanks(&line);
          if(*line == '#')
            continue;
          result = curlx_dyn_add(filebuf, line);
        }
        if(result) {
          curlx_dyn_free(filebuf);
          ret = curl2netrc(result);
          break;
        }
      } while(!eof);
      curlx_dyn_free(&linebuf);
    }
    curlx_fclose(file);
  }
  return ret;
}

static NETRCcode netrc_scan_file(struct Curl_easy *data,
                                 struct store_netrc *store,
                                 const char *hostname,
                                 const char *user,
                                 const char *netrcfile,
                                 struct Curl_creds **pcreds)
{
  struct dynbuf *filebuf = &store->filebuf;

  if(!store->loaded) {
    NETRCcode ret = file2memory(netrcfile, filebuf);
    if(ret) {
      CURL_TRC_M(data, "[NETRC] could not load '%s'", netrcfile);
      return ret;
    }
    store->loaded = TRUE;
  }

  return netrc_scan(data, curlx_dyn_ptr(filebuf), hostname, user, pcreds);
}

/*
 * @unittest: 1304
 *
 * *loginp and *passwordp MUST be allocated if they are not NULL when passed
 * in.
 */
NETRCcode Curl_netrc_scan(struct Curl_easy *data,
                          struct store_netrc *store,
                          const char *hostname,
                          const char *user,
                          const char *netrcfile,
                          struct Curl_creds **pcreds)
{
  NETRCcode retcode = NETRC_OK;
  char *filealloc = NULL;

  CURL_TRC_M(data, "[NETRC] scanning '%s' for host '%s' user '%s'",
             netrcfile, hostname, user);
  Curl_creds_unlink(pcreds);
  if(!netrcfile) {
    char *home = NULL;
    char *homea = NULL;
#if defined(HAVE_GETPWUID_R) && defined(HAVE_GETEUID)
    char pwbuf[1024];
#endif
    filealloc = curl_getenv("NETRC");
    if(!filealloc) {
      homea = curl_getenv("HOME"); /* portable environment reader */
      if(homea) {
        home = homea;
#if defined(HAVE_GETPWUID_R) && defined(HAVE_GETEUID)
      }
      else {
        struct passwd pw, *pw_res;
        if(!getpwuid_r(geteuid(), &pw, pwbuf, sizeof(pwbuf), &pw_res) &&
           pw_res) {
          home = pw.pw_dir;
        }
#elif defined(HAVE_GETPWUID) && defined(HAVE_GETEUID)
      }
      else {
        struct passwd *pw;
        pw = getpwuid(geteuid());
        if(pw) {
          home = pw->pw_dir;
        }
#elif defined(_WIN32)
      }
      else {
        homea = curl_getenv("USERPROFILE");
        if(homea) {
          home = homea;
        }
#endif
      }

      if(!home)
        return NETRC_FILE_MISSING; /* no home directory found (or possibly out
                                      of memory) */

      filealloc = curl_maprintf("%s%s.netrc", home, DIR_CHAR);
      if(!filealloc) {
        curlx_free(homea);
        retcode = NETRC_OUT_OF_MEMORY;
        goto out;
      }
    }
    retcode = netrc_scan_file(
      data, store, hostname, user, filealloc, pcreds);
    curlx_free(filealloc);
#ifdef _WIN32
    if(retcode == NETRC_FILE_MISSING) {
      /* fallback to the old-style "_netrc" file */
      filealloc = curl_maprintf("%s%s_netrc", home, DIR_CHAR);
      if(!filealloc) {
        curlx_free(homea);
        return NETRC_OUT_OF_MEMORY;
      }
      retcode = netrc_scan_file(
        data, store, hostname, user, filealloc, pcreds);
      curlx_free(filealloc);
    }
#endif
    curlx_free(homea);
  }
  else
    retcode = netrc_scan_file(
      data, store, hostname, user, netrcfile, pcreds);

out:
  if(retcode)
    Curl_creds_unlink(pcreds);
  return retcode;
}

void Curl_netrc_init(struct store_netrc *store)
{
  curlx_dyn_init(&store->filebuf, MAX_NETRC_FILE);
  store->loaded = FALSE;
}
void Curl_netrc_cleanup(struct store_netrc *store)
{
  curlx_dyn_free(&store->filebuf);
  store->loaded = FALSE;
}

const char *Curl_netrc_strerror(NETRCcode ret)
{
  switch(ret) {
  default:
    return ""; /* not a legit error */
  case NETRC_FILE_MISSING:
    return "no such file";
  case NETRC_NO_MATCH:
    return "no matching entry";
  case NETRC_OUT_OF_MEMORY:
    return "out of memory";
  case NETRC_SYNTAX_ERROR:
    return "syntax error";
  }
  /* never reached */
}

#endif /* !CURL_DISABLE_NETRC */
