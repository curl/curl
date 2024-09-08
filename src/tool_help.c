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

#include "curlx.h"

#include "tool_help.h"
#include "tool_libinfo.h"
#include "tool_util.h"
#include "tool_version.h"
#include "tool_cb_prg.h"
#include "tool_hugehelp.h"
#include "tool_getparam.h"
#include "terminal.h"

#include "memdebug.h" /* keep this as LAST include */

#ifdef MSDOS
#  define USE_WATT32
#endif

#ifndef ARRAYSIZE
#define ARRAYSIZE(A) (sizeof(A)/sizeof((A)[0]))
#endif

struct category_descriptors {
  const char *opt;
  const char *desc;
  unsigned int category;
};

static const struct category_descriptors categories[] = {
  /* important is left out because it is the default help page */
  {"auth", "Authentication methods", CURLHELP_AUTH},
  {"connection", "Manage connections", CURLHELP_CONNECTION},
  {"curl", "The command line tool itself", CURLHELP_CURL},
  {"deprecated", "Legacy", CURLHELP_DEPRECATED},
  {"dns", "Names and resolving", CURLHELP_DNS},
  {"file", "FILE protocol", CURLHELP_FILE},
  {"ftp", "FTP protocol", CURLHELP_FTP},
  {"global", "Global options", CURLHELP_GLOBAL},
  {"http", "HTTP and HTTPS protocol", CURLHELP_HTTP},
  {"imap", "IMAP protocol", CURLHELP_IMAP},
  {"ldap", "LDAP protocol", CURLHELP_LDAP},
  {"output", "Filesystem output", CURLHELP_OUTPUT},
  {"pop3", "POP3 protocol", CURLHELP_POP3},
  {"post", "HTTP POST specific", CURLHELP_POST},
  {"proxy", "Options for proxies", CURLHELP_PROXY},
  {"scp", "SCP protocol", CURLHELP_SCP},
  {"sftp", "SFTP protocol", CURLHELP_SFTP},
  {"smtp", "SMTP protocol", CURLHELP_SMTP},
  {"ssh", "SSH protocol", CURLHELP_SSH},
  {"telnet", "TELNET protocol", CURLHELP_TELNET},
  {"tftp", "TFTP protocol", CURLHELP_TFTP},
  {"timeout", "Timeouts and delays", CURLHELP_TIMEOUT},
  {"tls", "TLS/SSL related", CURLHELP_TLS},
  {"upload", "Upload, sending data", CURLHELP_UPLOAD},
  {"verbose", "Tracing, logging etc", CURLHELP_VERBOSE}
};

static void print_category(unsigned int category, unsigned int cols)
{
  unsigned int i;
  size_t longopt = 5;
  size_t longdesc = 5;

  for(i = 0; helptext[i].opt; ++i) {
    size_t len;
    if(!(helptext[i].categories & category))
      continue;
    len = strlen(helptext[i].opt);
    if(len > longopt)
      longopt = len;
    len = strlen(helptext[i].desc);
    if(len > longdesc)
      longdesc = len;
  }
  if(longopt + longdesc > cols)
    longopt = cols - longdesc;

  for(i = 0; helptext[i].opt; ++i)
    if(helptext[i].categories & category) {
      size_t opt = longopt;
      size_t desclen = strlen(helptext[i].desc);
      if(opt + desclen >= (cols - 2)) {
        if(desclen < (cols - 2))
          opt = (cols - 3) - desclen;
        else
          opt = 0;
      }
      printf(" %-*s  %s\n", (int)opt, helptext[i].opt, helptext[i].desc);
    }
}

/* Prints category if found. If not, it returns 1 */
static int get_category_content(const char *category, unsigned int cols)
{
  unsigned int i;
  for(i = 0; i < ARRAYSIZE(categories); ++i)
    if(curl_strequal(categories[i].opt, category)) {
      printf("%s: %s\n", categories[i].opt, categories[i].desc);
      print_category(categories[i].category, cols);
      return 0;
    }
  return 1;
}

/* Prints all categories and their description */
static void get_categories(void)
{
  unsigned int i;
  for(i = 0; i < ARRAYSIZE(categories); ++i)
    printf(" %-11s %s\n", categories[i].opt, categories[i].desc);
}

/* Prints all categories as a comma-separated list of given width */
static void get_categories_list(unsigned int width)
{
  unsigned int i;
  size_t col = 0;
  for(i = 0; i < ARRAYSIZE(categories); ++i) {
    size_t len = strlen(categories[i].opt);
    if(i == ARRAYSIZE(categories) - 1) {
      /* final category */
      if(col + len + 1 < width)
        printf("%s.\n", categories[i].opt);
      else
        /* start a new line first */
        printf("\n%s.\n", categories[i].opt);
    }
    else if(col + len + 2 < width) {
      printf("%s, ", categories[i].opt);
      col += len + 2;
    }
    else {
      /* start a new line first */
      printf("\n%s, ", categories[i].opt);
      col = len + 2;
    }
  }
}

#ifdef USE_MANUAL

void inithelpscan(struct scan_ctx *ctx,
                  const char *trigger,
                  const char *arg,
                  const char *endarg)
{
  ctx->trigger = trigger;
  ctx->tlen = strlen(trigger);
  ctx->arg = arg;
  ctx->flen = strlen(arg);
  ctx->endarg = endarg;
  ctx->elen = strlen(endarg);
  DEBUGASSERT((ctx->elen < sizeof(ctx->rbuf)) ||
              (ctx->flen < sizeof(ctx->rbuf)));
  ctx->show = 0;
  ctx->olen = 0;
  memset(ctx->rbuf, 0, sizeof(ctx->rbuf));
}

bool helpscan(unsigned char *buf, size_t len, struct scan_ctx *ctx)
{
  size_t i;
  for(i = 0; i < len; i++) {
    if(!ctx->show) {
      /* wait for the trigger */
      memmove(&ctx->rbuf[0], &ctx->rbuf[1], ctx->tlen - 1);
      ctx->rbuf[ctx->tlen - 1] = buf[i];
      if(!memcmp(ctx->rbuf, ctx->trigger, ctx->tlen))
        ctx->show++;
      continue;
    }
    /* past the trigger */
    if(ctx->show == 1) {
      memmove(&ctx->rbuf[0], &ctx->rbuf[1], ctx->flen - 1);
      ctx->rbuf[ctx->flen - 1] = buf[i];
      if(!memcmp(ctx->rbuf, ctx->arg, ctx->flen)) {
        /* match, now output until endarg */
        fputs(&ctx->arg[1], stdout);
        ctx->show++;
      }
      continue;
    }
    /* show until the end */
    memmove(&ctx->rbuf[0], &ctx->rbuf[1], ctx->elen - 1);
    ctx->rbuf[ctx->elen - 1] = buf[i];
    if(!memcmp(ctx->rbuf, ctx->endarg, ctx->elen))
      return FALSE;

    if(buf[i] == '\n') {
      DEBUGASSERT(ctx->olen < sizeof(ctx->obuf));
      if(ctx->olen == sizeof(ctx->obuf))
        return FALSE; /* bail out */
      ctx->obuf[ctx->olen++] = 0;
      ctx->olen = 0;
      puts(ctx->obuf);
    }
    else {
      DEBUGASSERT(ctx->olen < sizeof(ctx->obuf));
      if(ctx->olen == sizeof(ctx->obuf))
        return FALSE; /* bail out */
      ctx->obuf[ctx->olen++] = buf[i];
    }
  }
  return TRUE;
}

#endif

void tool_help(char *category)
{
  unsigned int cols = get_terminal_columns();
  /* If no category was provided */
  if(!category) {
    const char *category_note = "\nThis is not the full help; this "
      "menu is split into categories.\nUse \"--help category\" to get "
      "an overview of all categories, which are:";
    const char *category_note2 =
      "Use \"--help all\" to list all options"
#ifdef USE_MANUAL
      "\nUse \"--help [option]\" to view documentation for a given option"
#endif
      ;
    puts("Usage: curl [options...] <url>");
    print_category(CURLHELP_IMPORTANT, cols);
    puts(category_note);
    get_categories_list(cols);
    puts(category_note2);
  }
  /* Lets print everything if "all" was provided */
  else if(curl_strequal(category, "all"))
    /* Print everything */
    print_category(CURLHELP_ALL, cols);
  /* Lets handle the string "category" differently to not print an errormsg */
  else if(curl_strequal(category, "category"))
    get_categories();
  else if(category[0] == '-') {
#ifdef USE_MANUAL
    /* command line option help */
    const struct LongShort *a = NULL;
    if(category[1] == '-') {
      char *lookup = &category[2];
      bool noflagged = FALSE;
      if(!strncmp(lookup, "no-", 3)) {
        lookup += 3;
        noflagged = TRUE;
      }
      a = findlongopt(lookup);
      if(a && noflagged && (ARGTYPE(a->desc) != ARG_BOOL))
        /* a --no- prefix for a non-boolean is not specifying a proper
           option */
        a = NULL;
    }
    else if(!category[2])
      a = findshortopt(category[1]);
    if(!a) {
      fprintf(tool_stderr, "Incorrect option name to show help for,"
              " see curl -h\n");
    }
    else {
      char cmdbuf[80];
      if(a->letter != ' ')
        msnprintf(cmdbuf, sizeof(cmdbuf), "\n    -%c, --", a->letter);
      else if(a->desc & ARG_NO)
        msnprintf(cmdbuf, sizeof(cmdbuf), "\n    --no-%s", a->lname);
      else
        msnprintf(cmdbuf, sizeof(cmdbuf), "\n    %s", category);
      if(a->cmd == C_XATTR)
        /* this is the last option, which then ends when FILES starts */
        showhelp("\nALL OPTIONS\n", cmdbuf, "\nFILES");
      else
        showhelp("\nALL OPTIONS\n", cmdbuf, "\n    -");
    }
#else
    fprintf(tool_stderr, "Cannot comply. "
            "This curl was built without built-in manual\n");
#endif
  }
  /* Otherwise print category and handle the case if the cat was not found */
  else if(get_category_content(category, cols)) {
    puts("Unknown category provided, here is a list of all categories:\n");
    get_categories();
  }
  free(category);
}

static bool is_debug(void)
{
  const char *const *builtin;
  for(builtin = feature_names; *builtin; ++builtin)
    if(curl_strequal("debug", *builtin))
      return TRUE;
  return FALSE;
}

void tool_version_info(void)
{
  const char *const *builtin;
  if(is_debug())
    fprintf(tool_stderr, "WARNING: this libcurl is Debug-enabled, "
            "do not use in production\n\n");

  printf(CURL_ID "%s\n", curl_version());
#ifdef CURL_PATCHSTAMP
  printf("Release-Date: %s, security patched: %s\n",
         LIBCURL_TIMESTAMP, CURL_PATCHSTAMP);
#else
  printf("Release-Date: %s\n", LIBCURL_TIMESTAMP);
#endif
  if(built_in_protos[0]) {
#ifndef CURL_DISABLE_IPFS
    const char *insert = NULL;
    /* we have ipfs and ipns support if libcurl has http support */
    for(builtin = built_in_protos; *builtin; ++builtin) {
      if(insert) {
        /* update insertion so ipfs will be printed in alphabetical order */
        if(strcmp(*builtin, "ipfs") < 0)
          insert = *builtin;
        else
          break;
      }
      else if(!strcmp(*builtin, "http")) {
        insert = *builtin;
      }
    }
#endif /* !CURL_DISABLE_IPFS */
    printf("Protocols:");
    for(builtin = built_in_protos; *builtin; ++builtin) {
      /* Special case: do not list rtmp?* protocols.
         They may only appear together with "rtmp" */
      if(!curl_strnequal(*builtin, "rtmp", 4) || !builtin[0][4])
        printf(" %s", *builtin);
#ifndef CURL_DISABLE_IPFS
      if(insert && insert == *builtin) {
        printf(" ipfs ipns");
        insert = NULL;
      }
#endif /* !CURL_DISABLE_IPFS */
    }
    puts(""); /* newline */
  }
  if(feature_names[0]) {
    const char **feat_ext;
    size_t feat_ext_count = feature_count;
#ifdef CURL_CA_EMBED
    ++feat_ext_count;
#endif
    feat_ext = malloc(sizeof(*feature_names) * (feat_ext_count + 1));
    if(feat_ext) {
      memcpy((void *)feat_ext, feature_names,
             sizeof(*feature_names) * feature_count);
      feat_ext_count = feature_count;
#ifdef CURL_CA_EMBED
      feat_ext[feat_ext_count++] = "CAcert";
#endif
      feat_ext[feat_ext_count] = NULL;
      qsort((void *)feat_ext, feat_ext_count, sizeof(*feat_ext),
            struplocompare4sort);
      printf("Features:");
      for(builtin = feat_ext; *builtin; ++builtin)
        printf(" %s", *builtin);
      puts(""); /* newline */
      free((void *)feat_ext);
    }
  }
  if(strcmp(CURL_VERSION, curlinfo->version)) {
    printf("WARNING: curl and libcurl versions do not match. "
           "Functionality may be affected.\n");
  }
}

void tool_list_engines(void)
{
  CURL *curl = curl_easy_init();
  struct curl_slist *engines = NULL;

  /* Get the list of engines */
  curl_easy_getinfo(curl, CURLINFO_SSL_ENGINES, &engines);

  puts("Build-time engines:");
  if(engines) {
    for(; engines; engines = engines->next)
      printf("  %s\n", engines->data);
  }
  else {
    puts("  <none>");
  }

  /* Cleanup the list of engines */
  curl_slist_free_all(engines);
  curl_easy_cleanup(curl);
}
