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
#define ENABLE_CURLX_PRINTF
/* use our own printf() functions */
#include "curlx.h"

#include "tool_help.h"
#include "tool_libinfo.h"
#include "tool_util.h"
#include "tool_version.h"

#include "memdebug.h" /* keep this as LAST include */

#ifdef MSDOS
#  define USE_WATT32
#endif

struct category_descriptors {
  const char *opt;
  const char *desc;
  curlhelp_t category;
};

static const struct category_descriptors categories[] = {
  {"auth", "Different types of authentication methods", CURLHELP_AUTH},
  {"connection", "Low level networking operations",
   CURLHELP_CONNECTION},
  {"curl", "The command line tool itself", CURLHELP_CURL},
  {"dns", "General DNS options", CURLHELP_DNS},
  {"file", "FILE protocol options", CURLHELP_FILE},
  {"ftp", "FTP protocol options", CURLHELP_FTP},
  {"http", "HTTP and HTTPS protocol options", CURLHELP_HTTP},
  {"imap", "IMAP protocol options", CURLHELP_IMAP},
  /* important is left out because it is the default help page */
  {"misc", "Options that don't fit into any other category", CURLHELP_MISC},
  {"output", "Filesystem output", CURLHELP_OUTPUT},
  {"pop3", "POP3 protocol options", CURLHELP_POP3},
  {"post", "HTTP Post specific options", CURLHELP_POST},
  {"proxy", "All options related to proxies", CURLHELP_PROXY},
  {"scp", "SCP protocol options", CURLHELP_SCP},
  {"sftp", "SFTP protocol options", CURLHELP_SFTP},
  {"smtp", "SMTP protocol options", CURLHELP_SMTP},
  {"ssh", "SSH protocol options", CURLHELP_SSH},
  {"telnet", "TELNET protocol options", CURLHELP_TELNET},
  {"tftp", "TFTP protocol options", CURLHELP_TFTP},
  {"tls", "All TLS/SSL related options", CURLHELP_TLS},
  {"upload", "All options for uploads",
   CURLHELP_UPLOAD},
  {"verbose", "Options related to any kind of command line output of curl",
   CURLHELP_VERBOSE},
  {NULL, NULL, CURLHELP_HIDDEN}
};

extern const struct helptxt helptext[];


static void print_category(curlhelp_t category)
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
  if(longopt + longdesc > 80)
    longopt = 80 - longdesc;

  for(i = 0; helptext[i].opt; ++i)
    if(helptext[i].categories & category) {
      printf(" %-*s %s\n", (int)longopt, helptext[i].opt, helptext[i].desc);
    }
}

/* Prints category if found. If not, it returns 1 */
static int get_category_content(const char *category)
{
  unsigned int i;
  for(i = 0; categories[i].opt; ++i)
    if(curl_strequal(categories[i].opt, category)) {
      printf("%s: %s\n", categories[i].opt, categories[i].desc);
      print_category(categories[i].category);
      return 0;
    }
  return 1;
}

/* Prints all categories and their description */
static void get_categories(void)
{
  unsigned int i;
  for(i = 0; categories[i].opt; ++i)
    printf(" %-11s %s\n", categories[i].opt, categories[i].desc);
}


void tool_help(char *category)
{
  puts("Usage: curl [options...] <url>");
  /* If no category was provided */
  if(!category) {
    const char *category_note = "\nThis is not the full help, this "
      "menu is stripped into categories.\nUse \"--help category\" to get "
      "an overview of all categories.\nFor all options use the manual"
      " or \"--help all\".";
    print_category(CURLHELP_IMPORTANT);
    puts(category_note);
  }
  /* Lets print everything if "all" was provided */
  else if(curl_strequal(category, "all"))
    /* Print everything except hidden */
    print_category(~(CURLHELP_HIDDEN));
  /* Lets handle the string "category" differently to not print an errormsg */
  else if(curl_strequal(category, "category"))
    get_categories();
  /* Otherwise print category and handle the case if the cat was not found */
  else if(get_category_content(category)) {
    puts("Invalid category provided, here is a list of all categories:\n");
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
    printf("Protocols:");
    for(builtin = built_in_protos; *builtin; ++builtin) {
      /* Special case: do not list rtmp?* protocols.
         They may only appear together with "rtmp" */
      if(!curl_strnequal(*builtin, "rtmp", 4) || !builtin[0][4])
        printf(" %s", *builtin);
    }
    puts(""); /* newline */
  }
  if(feature_names[0]) {
    printf("Features:");
    for(builtin = feature_names; *builtin; ++builtin)
      printf(" %s", *builtin);
    puts(""); /* newline */
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
