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

#include "tool_cfgable.h"
#include "tool_getparam.h"
#include "tool_helpers.h"
#include "tool_findfile.h"
#include "tool_msgs.h"
#include "tool_parsecfg.h"
#include "tool_util.h"
#include "dynbuf.h"

#include "memdebug.h" /* keep this as LAST include */

/* only acknowledge colon or equals as separators if the option was not
   specified with an initial dash! */
#define ISSEP(x,dash) (!dash && (((x) == '=') || ((x) == ':')))

static const char *unslashquote(const char *line, char *param);

#define MAX_CONFIG_LINE_LENGTH (10*1024*1024)
static bool my_get_line(FILE *fp, struct curlx_dynbuf *, bool *error);


/* return 0 on everything-is-fine, and non-zero otherwise */
int parseconfig(const char *filename, struct GlobalConfig *global)
{
  FILE *file = NULL;
  bool usedarg = FALSE;
  int rc = 0;
  struct OperationConfig *operation = global->last;
  char *pathalloc = NULL;

  if(!filename) {
    /* NULL means load .curlrc from homedir! */
    char *curlrc = findfile(".curlrc", CURLRC_DOTSCORE);
    if(curlrc) {
      file = fopen(curlrc, FOPEN_READTEXT);
      if(!file) {
        free(curlrc);
        return 1;
      }
      filename = pathalloc = curlrc;
    }
#ifdef _WIN32 /* Windows */
    else {
      char *fullp;
      /* check for .curlrc then _curlrc in the dir of the executable */
      file = Curl_execpath(".curlrc", &fullp);
      if(!file)
        file = Curl_execpath("_curlrc", &fullp);
      if(file)
        /* this is the filename we read from */
        filename = fullp;
    }
#endif
  }
  else {
    if(strcmp(filename, "-"))
      file = fopen(filename, FOPEN_READTEXT);
    else
      file = stdin;
  }

  if(file) {
    char *line;
    char *option;
    char *param;
    int lineno = 0;
    bool dashed_option;
    struct curlx_dynbuf buf;
    bool fileerror = FALSE;
    curlx_dyn_init(&buf, MAX_CONFIG_LINE_LENGTH);
    DEBUGASSERT(filename);

    while(!rc && my_get_line(file, &buf, &fileerror)) {
      ParameterError res;
      bool alloced_param = FALSE;
      lineno++;
      line = curlx_dyn_ptr(&buf);
      if(!line) {
        rc = 1; /* out of memory */
        break;
      }

      /* line with # in the first non-blank column is a comment! */
      while(*line && ISSPACE(*line))
        line++;

      switch(*line) {
      case '#':
      case '/':
      case '\r':
      case '\n':
      case '*':
      case '\0':
        curlx_dyn_reset(&buf);
        continue;
      }

      /* the option keywords starts here */
      option = line;

      /* the option starts with a dash? */
      dashed_option = (option[0] == '-');

      while(*line && !ISSPACE(*line) && !ISSEP(*line, dashed_option))
        line++;
      /* ... and has ended here */

      if(*line)
        *line++ = '\0'; /* null-terminate, we have a local copy of the data */

#ifdef DEBUG_CONFIG
      fprintf(tool_stderr, "GOT: %s\n", option);
#endif

      /* pass spaces and separator(s) */
      while(*line && (ISSPACE(*line) || ISSEP(*line, dashed_option)))
        line++;

      /* the parameter starts here (unless quoted) */
      if(*line == '\"') {
        /* quoted parameter, do the quote dance */
        line++;
        param = malloc(strlen(line) + 1); /* parameter */
        if(!param) {
          /* out of memory */
          rc = 1;
          break;
        }
        alloced_param = TRUE;
        (void)unslashquote(line, param);
      }
      else {
        param = line; /* parameter starts here */
        while(*line && !ISSPACE(*line))
          line++;

        if(*line) {
          *line = '\0'; /* null-terminate */

          /* to detect mistakes better, see if there is data following */
          line++;
          /* pass all spaces */
          while(*line && ISSPACE(*line))
            line++;

          switch(*line) {
          case '\0':
          case '\r':
          case '\n':
          case '#': /* comment */
            break;
          default:
            warnf(operation->global, "%s:%d: warning: '%s' uses unquoted "
                  "whitespace", filename, lineno, option);
            warnf(operation->global, "This may cause side-effects. "
                  "Consider using double quotes?");
          }
        }
        if(!*param)
          /* do this so getparameter can check for required parameters.
             Otherwise it always thinks there is a parameter. */
          param = NULL;
      }

#ifdef DEBUG_CONFIG
      fprintf(tool_stderr, "PARAM: \"%s\"\n",(param ? param : "(null)"));
#endif
      res = getparameter(option, param, NULL, &usedarg, global, operation);
      operation = global->last;

      if(!res && param && *param && !usedarg)
        /* we passed in a parameter that was not used! */
        res = PARAM_GOT_EXTRA_PARAMETER;

      if(res == PARAM_NEXT_OPERATION) {
        if(operation->url_list && operation->url_list->url) {
          /* Allocate the next config */
          operation->next = malloc(sizeof(struct OperationConfig));
          if(operation->next) {
            /* Initialise the newly created config */
            config_init(operation->next);

            /* Set the global config pointer */
            operation->next->global = global;

            /* Update the last operation pointer */
            global->last = operation->next;

            /* Move onto the new config */
            operation->next->prev = operation;
            operation = operation->next;
          }
          else
            res = PARAM_NO_MEM;
        }
      }

      if(res != PARAM_OK && res != PARAM_NEXT_OPERATION) {
        /* the help request is not really an error */
        if(!strcmp(filename, "-")) {
          filename = "<stdin>";
        }
        if(res != PARAM_HELP_REQUESTED &&
           res != PARAM_MANUAL_REQUESTED &&
           res != PARAM_VERSION_INFO_REQUESTED &&
           res != PARAM_ENGINES_REQUESTED &&
           res != PARAM_CA_EMBED_REQUESTED) {
          const char *reason = param2text(res);
          errorf(operation->global, "%s:%d: '%s' %s",
                 filename, lineno, option, reason);
          rc = (int)res;
        }
      }

      if(alloced_param)
        Curl_safefree(param);

      curlx_dyn_reset(&buf);
    }
    curlx_dyn_free(&buf);
    if(file != stdin)
      fclose(file);
    if(fileerror)
      rc = 1;
  }
  else
    rc = 1; /* could not open the file */

  free(pathalloc);
  return rc;
}

/*
 * Copies the string from line to the buffer at param, unquoting
 * backslash-quoted characters and NUL-terminating the output string.
 * Stops at the first non-backslash-quoted double quote character or the
 * end of the input string. param must be at least as long as the input
 * string. Returns the pointer after the last handled input character.
 */
static const char *unslashquote(const char *line, char *param)
{
  while(*line && (*line != '\"')) {
    if(*line == '\\') {
      char out;
      line++;

      /* default is to output the letter after the backslash */
      switch(out = *line) {
      case '\0':
        continue; /* this'll break out of the loop */
      case 't':
        out = '\t';
        break;
      case 'n':
        out = '\n';
        break;
      case 'r':
        out = '\r';
        break;
      case 'v':
        out = '\v';
        break;
      }
      *param++ = out;
      line++;
    }
    else
      *param++ = *line++;
  }
  *param = '\0'; /* always null-terminate */
  return line;
}

/*
 * Reads a line from the given file, ensuring is NUL terminated.
 */
static bool my_get_line(FILE *fp, struct curlx_dynbuf *db,
                        bool *error)
{
  char buf[4096];
  *error = FALSE;
  do {
    /* fgets() returns s on success, and NULL on error or when end of file
       occurs while no characters have been read. */
    if(!fgets(buf, sizeof(buf), fp))
      /* only if there is data in the line, return TRUE */
      return curlx_dyn_len(db);
    if(curlx_dyn_add(db, buf)) {
      *error = TRUE; /* error */
      return FALSE; /* stop reading */
    }
  } while(!strchr(buf, '\n'));

  return TRUE; /* continue */
}
