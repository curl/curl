/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2019, Daniel Stenberg, <daniel@haxx.se>, et al.
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
#include "tool_setup.h"

#define ENABLE_CURLX_PRINTF
/* use our own printf() functions */
#include "curlx.h"

#include "tool_cfgable.h"
#include "tool_getparam.h"
#include "tool_helpers.h"
#include "tool_homedir.h"
#include "tool_msgs.h"
#include "tool_parsecfg.h"

#include "memdebug.h" /* keep this as LAST include */

/* only acknowledge colon or equals as separators if the option was not
   specified with an initial dash! */
#define ISSEP(x,dash) (!dash && (((x) == '=') || ((x) == ':')))

static const char *unslashquote(const char *line, char *param);
static char *my_get_line(FILE *fp);

#ifdef WIN32
static FILE *execpath(const char *filename)
{
  char filebuffer[512];
  /* Get the filename of our executable. GetModuleFileName is already declared
   * via inclusions done in setup header file.  We assume that we are using
   * the ASCII version here.
   */
  unsigned long len = GetModuleFileNameA(0, filebuffer, sizeof(filebuffer));
  if(len > 0 && len < sizeof(filebuffer)) {
    /* We got a valid filename - get the directory part */
    char *lastdirchar = strrchr(filebuffer, '\\');
    if(lastdirchar) {
      size_t remaining;
      *lastdirchar = 0;
      /* If we have enough space, build the RC filename */
      remaining = sizeof(filebuffer) - strlen(filebuffer);
      if(strlen(filename) < remaining - 1) {
        msnprintf(lastdirchar, remaining, "%s%s", DIR_CHAR, filename);
        return fopen(filebuffer, FOPEN_READTEXT);
      }
    }
  }

  return NULL;
}
#endif


/* return 0 on everything-is-fine, and non-zero otherwise */
int parseconfig(const char *filename, struct GlobalConfig *global)
{
  FILE *file = NULL;
  bool usedarg = FALSE;
  int rc = 0;
  struct OperationConfig *operation = global->first;
  char *pathalloc = NULL;

  if(!filename || !*filename) {
    /* NULL or no file name attempts to load .curlrc from the homedir! */

    char *home = homedir();    /* portable homedir finder */
#ifndef WIN32
    if(home) {
      pathalloc = curl_maprintf("%s%s.curlrc", home, DIR_CHAR);
      if(!pathalloc) {
        free(home);
        return 1; /* out of memory */
      }
      filename = pathalloc;
    }
#else /* Windows */
    if(home) {
      int i = 0;
      char prefix = '.';
      do {
        /* check for .curlrc then _curlrc in the home dir */
        pathalloc = curl_maprintf("%s%s%ccurlrc", home, DIR_CHAR, prefix);
        if(!pathalloc) {
          free(home);
          return 1; /* out of memory */
        }

        /* Check if the file exists - if not, try _curlrc */
        file = fopen(pathalloc, FOPEN_READTEXT);
        if(file) {
          filename = pathalloc;
          break;
        }
        prefix = '_';
      } while(++i < 2);
    }
    if(!filename) {
      /* check for .curlrc then _curlrc in the dir of the executable */
      file = execpath(".curlrc");
      if(!file)
        file = execpath("_curlrc");
    }
#endif

    Curl_safefree(home); /* we've used it, now free it */
  }

  if(!file && filename) { /* no need to fopen() again */
    if(strcmp(filename, "-"))
      file = fopen(filename, FOPEN_READTEXT);
    else
      file = stdin;
  }

  if(file) {
    char *line;
    char *aline;
    char *option;
    char *param;
    int lineno = 0;
    bool dashed_option;

    while(NULL != (aline = my_get_line(file))) {
      int res;
      bool alloced_param = FALSE;
      lineno++;
      line = aline;

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
        Curl_safefree(aline);
        continue;
      }

      /* the option keywords starts here */
      option = line;

      /* the option starts with a dash? */
      dashed_option = option[0]=='-'?TRUE:FALSE;

      while(*line && !ISSPACE(*line) && !ISSEP(*line, dashed_option))
        line++;
      /* ... and has ended here */

      if(*line)
        *line++ = '\0'; /* zero terminate, we have a local copy of the data */

#ifdef DEBUG_CONFIG
      fprintf(stderr, "GOT: %s\n", option);
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
          Curl_safefree(aline);
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
          *line = '\0'; /* zero terminate */

          /* to detect mistakes better, see if there's data following */
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
                  "white space in the line that may cause side-effects!\n",
                  filename, lineno, option);
          }
        }
        if(!*param)
          /* do this so getparameter can check for required parameters.
             Otherwise it always thinks there's a parameter. */
          param = NULL;
      }

#ifdef DEBUG_CONFIG
      fprintf(stderr, "PARAM: \"%s\"\n",(param ? param : "(null)"));
#endif
      res = getparameter(option, param, &usedarg, global, operation);

      if(!res && param && *param && !usedarg)
        /* we passed in a parameter that wasn't used! */
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
        /* the help request isn't really an error */
        if(!strcmp(filename, "-")) {
          filename = "<stdin>";
        }
        if(res != PARAM_HELP_REQUESTED &&
           res != PARAM_MANUAL_REQUESTED &&
           res != PARAM_VERSION_INFO_REQUESTED &&
           res != PARAM_ENGINES_REQUESTED) {
          const char *reason = param2text(res);
          warnf(operation->global, "%s:%d: warning: '%s' %s\n",
                filename, lineno, option, reason);
        }
      }

      if(alloced_param)
        Curl_safefree(param);

      Curl_safefree(aline);
    }
    if(file != stdin)
      fclose(file);
  }
  else
    rc = 1; /* couldn't open the file */

  free(pathalloc);
  return rc;
}

/*
 * Copies the string from line to the buffer at param, unquoting
 * backslash-quoted characters and NUL-terminating the output string.
 * Stops at the first non-backslash-quoted double quote character or the
 * end of the input string. param must be at least as long as the input
 * string.  Returns the pointer after the last handled input character.
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
  *param = '\0'; /* always zero terminate */
  return line;
}

/*
 * Reads a line from the given file, ensuring is NUL terminated.
 * The pointer must be freed by the caller.
 * NULL is returned on an out of memory condition.
 */
static char *my_get_line(FILE *fp)
{
  char buf[4096];
  char *nl = NULL;
  char *line = NULL;

  do {
    if(NULL == fgets(buf, sizeof(buf), fp))
      break;
    if(!line) {
      line = strdup(buf);
      if(!line)
        return NULL;
    }
    else {
      char *ptr;
      size_t linelen = strlen(line);
      ptr = realloc(line, linelen + strlen(buf) + 1);
      if(!ptr) {
        Curl_safefree(line);
        return NULL;
      }
      line = ptr;
      strcpy(&line[linelen], buf);
    }
    nl = strchr(line, '\n');
  } while(!nl);

  if(nl)
    *nl = '\0';

  return line;
}
