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

#include "tool_help.h"
#include "tool_libinfo.h"
#include "tool_util.h"
#include "tool_version.h"
#include "tool_cb_prg.h"
#include "tool_hugehelp.h"
#include "tool_getparam.h"
#include "tool_cfgable.h"
#include "terminal.h"

struct category_descriptors {
  const char *opt;
  const char *desc;
  unsigned int category;
};

static const struct category_descriptors categories[] = {
  /* important is left out because it is the default help page */
  {"auth", "Authentication methods", CURLHELP_AUTH},
  {"common", "Common options", CURLHELP_COMMON},
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
  {"output", "File system output", CURLHELP_OUTPUT},
  {"pop3", "POP3 protocol", CURLHELP_POP3},
  {"post", "HTTP POST specific", CURLHELP_POST},
  {"proxy", "Options for proxies", CURLHELP_PROXY},
  {"scp", "SCP protocol", CURLHELP_SCP},
  {"sftp", "SFTP protocol", CURLHELP_SFTP},
  {"smtp", "SMTP protocol", CURLHELP_SMTP},
  {"ssh", "SSH protocol", CURLHELP_SSH},
  {"table", "Table format category (use table:<category>)", 0},
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

  if(longdesc > cols)
    longopt = 0; /* avoid wrap-around */
  else if(longopt + longdesc > cols)
    longopt = cols - longdesc;

  for(i = 0; helptext[i].opt; ++i)
    if(helptext[i].categories & category) {
      size_t opt = longopt;
      size_t desclen = strlen(helptext[i].desc);
      /* avoid wrap-around */
      if(cols >= 2 && opt + desclen >= (cols - 2)) {
        if(desclen < (cols - 2))
          opt = (cols - 3) - desclen;
        else
          opt = 0;
      }
      curl_mprintf(" %-*s  %s\n", (int)opt, helptext[i].opt, helptext[i].desc);
    }
}

/* Prints category if found. If not, it returns 1 */
static int get_category_content(const char *category, unsigned int cols)
{
  unsigned int i;

  /* Checking for table. */
  bool table_flag = FALSE;

  /* Check and handle table:<category> syntax. */
  if(curl_strnequal(category, "table", 5)) {
    const char *table_category = category + 5;
    table_flag = TRUE; /* Use tool_table(). */

    /* Set category, defaulting to common. */
    category = (!*table_category) ? "common" : table_category + 1;
  }

  for(i = 0; i < CURL_ARRAYSIZE(categories); ++i)
    if(curl_strequal(categories[i].opt, category)) {
      curl_mprintf("%s: %s\n", categories[i].opt, categories[i].desc);
      if(table_flag)
        tool_table(categories[i].category, cols);
      else
        print_category(categories[i].category, cols);
      return 0;
    }
  return 1;
}

/* Prints all categories and their description */
static void get_categories(void)
{
  unsigned int i;
  for(i = 0; i < CURL_ARRAYSIZE(categories); ++i)
    curl_mprintf(" %-11s %s\n", categories[i].opt, categories[i].desc);
}

/* Prints all categories as a comma-separated list of given width */
static void get_categories_list(unsigned int width)
{
  unsigned int i;
  size_t col = 0;
  for(i = 0; i < CURL_ARRAYSIZE(categories); ++i) {
    size_t len = strlen(categories[i].opt);
    if(i == CURL_ARRAYSIZE(categories) - 1) {
      /* final category */
      if(col + len + 1 < width)
        curl_mprintf("%s.\n", categories[i].opt);
      else
        /* start a new line first */
        curl_mprintf("\n%s.\n", categories[i].opt);
    }
    else if(col + len + 2 < width) {
      curl_mprintf("%s, ", categories[i].opt);
      col += len + 2;
    }
    else {
      /* start a new line first */
      curl_mprintf("\n%s, ", categories[i].opt);
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

bool helpscan(const unsigned char *buf, size_t len, struct scan_ctx *ctx)
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

void tool_help(const char *category)
{
  unsigned int cols = get_terminal_columns();
  /* If no category was provided */
  if(!category) {
    const char *category_note =
      "\nThis is not the full help; this "
      "menu is split into categories.\nUse \"--help category\" to get "
      "an overview of all categories, which are:";
    const char *category_note2 =
      "Use \"--help all\" to list all options"
#ifdef USE_MANUAL
      "\nUse \"--help [option]\" to view documentation for a given option"
      "\nUse \"--help table:<category>\" to table format category overview"
#endif
      ;
    puts("Usage: curl [options...] <url>");
    print_category(CURLHELP_IMPORTANT, cols);
    puts(category_note);
    get_categories_list(cols);
    puts(category_note2);
  }
  /* Lets print everything if "all" was provided */
  else if(curl_strequal(category, "all") ||
          curl_strequal(category, "table:all"))
    /* Print everything */
    if(curl_strequal(category, "all"))
      print_category(CURLHELP_ALL, cols);
    else
      tool_table(CURLHELP_ALL, cols);
  /* Lets handle the string "category" differently to not print an errormsg */
  else if(curl_strequal(category, "category"))
    get_categories();
  else if(category[0] == '-') {
#ifdef USE_MANUAL
    /* command line option help */
    const struct LongShort *a = NULL;
    if(category[1] == '-') {
      const char *lookup = &category[2];
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
      curl_mfprintf(tool_stderr, "Incorrect option name to show help for,"
                    " see curl -h\n");
    }
    else {
      char cmdbuf[80];
      if(a->letter != ' ')
        curl_msnprintf(cmdbuf, sizeof(cmdbuf), "\n    -%c, --", a->letter);
      else if(a->desc & ARG_NO)
        curl_msnprintf(cmdbuf, sizeof(cmdbuf), "\n    --no-%s", a->lname);
      else
        curl_msnprintf(cmdbuf, sizeof(cmdbuf), "\n    %s", category);
#ifdef USE_MANUAL
      if(a->cmd == C_XATTR)
        /* this is the last option, which then ends when FILES starts */
        showhelp("\nALL OPTIONS\n", cmdbuf, "\nFILES");
      else
        showhelp("\nALL OPTIONS\n", cmdbuf, "\n    -");
#endif
    }
#else
    curl_mfprintf(tool_stderr, "Cannot comply. "
                  "This curl was built without built-in manual\n");
#endif
  }
  /* Otherwise print category and handle the case if the cat was not found */
  else if(get_category_content(category, cols)) {
    puts("Unknown category provided, here is a list of all categories:\n");
    get_categories();
  }
}

static bool is_debug(void)
{
  const char * const *builtin;
  for(builtin = feature_names; *builtin; ++builtin)
    if(curl_strequal("debug", *builtin))
      return TRUE;
  return FALSE;
}

void tool_version_info(void)
{
  const char * const *builtin;
  if(is_debug())
    curl_mfprintf(tool_stderr, "WARNING: this libcurl is Debug-enabled, "
                  "do not use in production\n\n");

  curl_mprintf(CURL_ID "%s\n", curl_version());
#ifdef CURL_PATCHSTAMP
  curl_mprintf("Release-Date: %s, security patched: %s\n",
               LIBCURL_TIMESTAMP, CURL_PATCHSTAMP);
#else
  curl_mprintf("Release-Date: %s\n", LIBCURL_TIMESTAMP);
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
    curl_mprintf("Protocols:");
    for(builtin = built_in_protos; *builtin; ++builtin) {
      /* Special case: do not list rtmp?* protocols.
         They may only appear together with "rtmp" */
      if(!curl_strnequal(*builtin, "rtmp", 4) || !builtin[0][4])
        curl_mprintf(" %s", *builtin);
#ifndef CURL_DISABLE_IPFS
      if(insert && insert == *builtin) {
        curl_mprintf(" ipfs ipns");
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
    feat_ext = curlx_malloc(sizeof(*feature_names) * (feat_ext_count + 1));
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
      curl_mprintf("Features:");
      for(builtin = feat_ext; *builtin; ++builtin)
        curl_mprintf(" %s", *builtin);
      puts(""); /* newline */
      curlx_free((void *)feat_ext);
    }
  }
  if(strcmp(CURL_VERSION, curlinfo->version)) {
    curl_mprintf("WARNING: curl and libcurl versions do not match. "
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
      curl_mprintf("  %s\n", engines->data);
  }
  else {
    puts("  <none>");
  }

  /* Cleanup the list of engines */
  curl_slist_free_all(engines);
  curl_easy_cleanup(curl);
}

/* Output table from category. */
void tool_table(unsigned int category, unsigned int cols)
{
  size_t i, c, j, found, opt_idx, current, lng_spc, count = 0;
  size_t max_len = 0;
  const char *e_sp;

  /* Count options in category. */
  for(i = 0; helptext[i].opt; ++i) {
    if(!(helptext[i].categories & category))
      continue;

    if(helptext[i].categories & category) {
      /* Use length of longest description or option to set col width. */
      if(max_len < strlen(helptext[i].desc) ||
         max_len < strlen(helptext[i].opt)) {
        max_len = (strlen(helptext[i].desc) > strlen(helptext[i].opt)) ?
          strlen(helptext[i].desc) : strlen(helptext[i].opt);
      }
      count++;
    }
  }

  /* Set j based on longest description or option length. */
  j = cols/(max_len + 1);
  if(j > 8)
    j = 8;
  else if(j == 0)
    j = 1;

  /* Print option and description in table format. */
  current = 0;
  for(i = 0; helptext[i].opt; ++i) {
    if(!(helptext[i].categories & category))
      continue;

    if(current % j == 0) {
      /* Empty line to distinguish table head and data. */
      if(current > 0)
        puts("");

      /* Option row. */
      for(c = 0; c < j && (current + c) < count; c++) {
        /* Print option as table head. */
        found = 0;
        for(opt_idx = 0; helptext[opt_idx].opt; ++opt_idx)
          if(helptext[opt_idx].categories & category) {
            if(found == current + c) {
              /* Equate option space to left align. */
              e_sp = helptext[opt_idx].opt +
                strspn(helptext[opt_idx].opt, " ");
              /* Use space before long or short option to align. */
              lng_spc = (int)(e_sp - helptext[opt_idx].opt);
              /* Output, left aligning option name. */
              curl_mprintf("%-*s ", (int)(max_len),
                     helptext[opt_idx].opt + lng_spc);
              break;
            }
            found++;
          }
      }
      puts("");

      /* Print separator. */
      for(c = 0; c < j && (current + c) < count; c++) {
        for(opt_idx = 0; opt_idx < max_len; opt_idx++)
          putchar('-');
        putchar(' ');
      }
      puts("");

      /* Description row. */
      for(c = 0; c < j && (current + c) < count; c++) {
        /* Print description as table data. */
        found = 0;
        for(opt_idx = 0; helptext[opt_idx].opt; ++opt_idx)
          if(helptext[opt_idx].categories & category) {
            if(found == current + c) {
              /* Output description. */
              curl_mprintf("%-*s ", (int)(max_len), helptext[opt_idx].desc);
              break;
            }
            found++;
          }
      }
      puts("");
    }
    current++;
  }
}
