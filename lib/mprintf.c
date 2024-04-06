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
 */

#include "curl_setup.h"
#include "dynbuf.h"
#include "curl_printf.h"
#include <curl/mprintf.h>

#include "curl_memory.h"
/* The last #include file should be: */
#include "memdebug.h"

/*
 * If SIZEOF_SIZE_T has not been defined, default to the size of long.
 */

#ifdef HAVE_LONGLONG
#  define LONG_LONG_TYPE long long
#  define HAVE_LONG_LONG_TYPE
#else
#  if defined(_MSC_VER) && (_MSC_VER >= 900) && (_INTEGRAL_MAX_BITS >= 64)
#    define LONG_LONG_TYPE __int64
#    define HAVE_LONG_LONG_TYPE
#  else
#    undef LONG_LONG_TYPE
#    undef HAVE_LONG_LONG_TYPE
#  endif
#endif

/*
 * Max integer data types that mprintf.c is capable
 */

#ifdef HAVE_LONG_LONG_TYPE
#  define mp_intmax_t LONG_LONG_TYPE
#  define mp_uintmax_t unsigned LONG_LONG_TYPE
#else
#  define mp_intmax_t long
#  define mp_uintmax_t unsigned long
#endif

#define BUFFSIZE 326 /* buffer for long-to-str and float-to-str calcs, should
                        fit negative DBL_MAX (317 letters) */
#define MAX_PARAMETERS 128 /* number of input arguments */
#define MAX_SEGMENTS   128 /* number of output segments */

#ifdef __AMIGA__
# undef FORMAT_INT
#endif

/* Lower-case digits.  */
static const char lower_digits[] = "0123456789abcdefghijklmnopqrstuvwxyz";

/* Upper-case digits.  */
static const char upper_digits[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";

#define OUTCHAR(x)                                      \
  do {                                                  \
    if(!stream(x, userp))                               \
      done++;                                           \
    else                                                \
      return done; /* return on failure */              \
  } while(0)

/* Data type to read from the arglist */
typedef enum {
  FORMAT_STRING,
  FORMAT_PTR,
  FORMAT_INTPTR,
  FORMAT_INT,
  FORMAT_LONG,
  FORMAT_LONGLONG,
  FORMAT_INTU,
  FORMAT_LONGU,
  FORMAT_LONGLONGU,
  FORMAT_DOUBLE,
  FORMAT_LONGDOUBLE,
  FORMAT_WIDTH,
  FORMAT_PRECISION
} FormatType;

/* conversion and display flags */
enum {
  FLAGS_SPACE      = 1<<0,
  FLAGS_SHOWSIGN   = 1<<1,
  FLAGS_LEFT       = 1<<2,
  FLAGS_ALT        = 1<<3,
  FLAGS_SHORT      = 1<<4,
  FLAGS_LONG       = 1<<5,
  FLAGS_LONGLONG   = 1<<6,
  FLAGS_LONGDOUBLE = 1<<7,
  FLAGS_PAD_NIL    = 1<<8,
  FLAGS_UNSIGNED   = 1<<9,
  FLAGS_OCTAL      = 1<<10,
  FLAGS_HEX        = 1<<11,
  FLAGS_UPPER      = 1<<12,
  FLAGS_WIDTH      = 1<<13, /* '*' or '*<num>$' used */
  FLAGS_WIDTHPARAM = 1<<14, /* width PARAMETER was specified */
  FLAGS_PREC       = 1<<15, /* precision was specified */
  FLAGS_PRECPARAM  = 1<<16, /* precision PARAMETER was specified */
  FLAGS_CHAR       = 1<<17, /* %c story */
  FLAGS_FLOATE     = 1<<18, /* %e or %E */
  FLAGS_FLOATG     = 1<<19, /* %g or %G */
  FLAGS_SUBSTR     = 1<<20  /* no input, only substring */
};

enum {
  DOLLAR_UNKNOWN,
  DOLLAR_NOPE,
  DOLLAR_USE
};

/*
 * Describes an input va_arg type and hold its value.
 */
struct va_input {
  FormatType type; /* FormatType */
  union {
    char *str;
    void *ptr;
    mp_intmax_t nums; /* signed */
    mp_uintmax_t numu; /* unsigned */
    double dnum;
  } val;
};

/*
 * Describes an output segment.
 */
struct outsegment {
  int width;     /* width OR width parameter number */
  int precision; /* precision OR precision parameter number */
  unsigned int flags;
  unsigned int input; /* input argument array index */
  char *start;      /* format string start to output */
  size_t outlen;     /* number of bytes from the format string to output */
};

struct nsprintf {
  char *buffer;
  size_t length;
  size_t max;
};

struct asprintf {
  struct dynbuf *b;
  char merr;
};

/* the provided input number is 1-based but this returns the number 0-based.

   returns -1 if no valid number was provided.
*/
static int dollarstring(char *input, char **end)
{
  if(ISDIGIT(*input)) {
    int number = 0;
    do {
      if(number < MAX_PARAMETERS) {
        number *= 10;
        number += *input - '0';
      }
      input++;
    } while(ISDIGIT(*input));

    if(number && (number <= MAX_PARAMETERS) && ('$' == *input)) {
      *end = ++input;
      return number - 1;
    }
  }
  return -1;
}

/*
 * Parse the format string.
 *
 * Create two arrays. One describes the inputs, one describes the outputs.
 *
 * Returns zero on success.
 */

#define PFMT_OK          0
#define PFMT_DOLLAR      1 /* bad dollar for main param */
#define PFMT_DOLLARWIDTH 2 /* bad dollar use for width */
#define PFMT_DOLLARPREC  3 /* bad dollar use for precision */
#define PFMT_MANYARGS    4 /* too many input arguments used */
#define PFMT_PREC        5 /* precision overflow */
#define PFMT_PRECMIX     6 /* bad mix of precision specifiers */
#define PFMT_WIDTH       7 /* width overflow */
#define PFMT_INPUTGAP    8 /* gap in arguments */
#define PFMT_WIDTHARG    9 /* attempted to use same arg twice, for width */
#define PFMT_PRECARG    10 /* attempted to use same arg twice, for prec */
#define PFMT_MANYSEGS   11 /* maxed out output segments */

static int parsefmt(const char *format,
                    struct outsegment *out,
                    struct va_input *in,
                    int *opieces,
                    int *ipieces, va_list arglist)
{
  char *fmt = (char *)format;
  int param_num = 0;
  int param;
  int width;
  int precision;
  unsigned int flags;
  FormatType type;
  int max_param = -1;
  int i;
  int ocount = 0;
  unsigned char usedinput[MAX_PARAMETERS/8];
  size_t outlen = 0;
  struct outsegment *optr;
  int use_dollar = DOLLAR_UNKNOWN;
  char *start = fmt;

  /* clear, set a bit for each used input */
  memset(usedinput, 0, sizeof(usedinput));

  while(*fmt) {
    if(*fmt == '%') {
      struct va_input *iptr;
      bool loopit = TRUE;
      fmt++;
      outlen = fmt - start - 1;
      if(*fmt == '%') {
        /* this means a %% that should be output only as %. Create an output
           segment. */
        if(outlen) {
          optr = &out[ocount++];
          if(ocount > MAX_SEGMENTS)
            return PFMT_MANYSEGS;
          optr->input = 0;
          optr->flags = FLAGS_SUBSTR;
          optr->start = start;
          optr->outlen = outlen;
        }
        start = fmt;
        fmt++;
        continue; /* while */
      }

      flags = width = precision = 0;

      if(use_dollar != DOLLAR_NOPE) {
        param = dollarstring(fmt, &fmt);
        if(param < 0) {
          if(use_dollar == DOLLAR_USE)
            /* illegal combo */
            return PFMT_DOLLAR;

          /* we got no positional, just get the next arg */
          param = -1;
          use_dollar = DOLLAR_NOPE;
        }
        else
          use_dollar = DOLLAR_USE;
      }
      else
        param = -1;

      /* Handle the flags */
      while(loopit) {
        switch(*fmt++) {
        case ' ':
          flags |= FLAGS_SPACE;
          break;
        case '+':
          flags |= FLAGS_SHOWSIGN;
          break;
        case '-':
          flags |= FLAGS_LEFT;
          flags &= ~FLAGS_PAD_NIL;
          break;
        case '#':
          flags |= FLAGS_ALT;
          break;
        case '.':
          if('*' == *fmt) {
            /* The precision is picked from a specified parameter */
            flags |= FLAGS_PRECPARAM;
            fmt++;

            if(use_dollar == DOLLAR_USE) {
              precision = dollarstring(fmt, &fmt);
              if(precision < 0)
                /* illegal combo */
                return PFMT_DOLLARPREC;
            }
            else
              /* get it from the next argument */
              precision = -1;
          }
          else {
            bool is_neg = FALSE;
            flags |= FLAGS_PREC;
            precision = 0;
            if('-' == *fmt) {
              is_neg = TRUE;
              fmt++;
            }
            while(ISDIGIT(*fmt)) {
              if(precision > INT_MAX/10)
                return PFMT_PREC;
              precision *= 10;
              precision += *fmt - '0';
              fmt++;
            }
            if(is_neg)
              precision = -precision;
          }
          if((flags & (FLAGS_PREC | FLAGS_PRECPARAM)) ==
             (FLAGS_PREC | FLAGS_PRECPARAM))
            /* it is not permitted to use both kinds of precision for the same
               argument */
            return PFMT_PRECMIX;
          break;
        case 'h':
          flags |= FLAGS_SHORT;
          break;
#if defined(_WIN32) || defined(_WIN32_WCE)
        case 'I':
          /* Non-ANSI integer extensions I32 I64 */
          if((fmt[0] == '3') && (fmt[1] == '2')) {
            flags |= FLAGS_LONG;
            fmt += 2;
          }
          else if((fmt[0] == '6') && (fmt[1] == '4')) {
            flags |= FLAGS_LONGLONG;
            fmt += 2;
          }
          else {
#if (SIZEOF_CURL_OFF_T > SIZEOF_LONG)
            flags |= FLAGS_LONGLONG;
#else
            flags |= FLAGS_LONG;
#endif
          }
          break;
#endif /* _WIN32 || _WIN32_WCE */
        case 'l':
          if(flags & FLAGS_LONG)
            flags |= FLAGS_LONGLONG;
          else
            flags |= FLAGS_LONG;
          break;
        case 'L':
          flags |= FLAGS_LONGDOUBLE;
          break;
        case 'q':
          flags |= FLAGS_LONGLONG;
          break;
        case 'z':
          /* the code below generates a warning if -Wunreachable-code is
             used */
#if (SIZEOF_SIZE_T > SIZEOF_LONG)
          flags |= FLAGS_LONGLONG;
#else
          flags |= FLAGS_LONG;
#endif
          break;
        case 'O':
#if (SIZEOF_CURL_OFF_T > SIZEOF_LONG)
          flags |= FLAGS_LONGLONG;
#else
          flags |= FLAGS_LONG;
#endif
          break;
        case '0':
          if(!(flags & FLAGS_LEFT))
            flags |= FLAGS_PAD_NIL;
          FALLTHROUGH();
        case '1': case '2': case '3': case '4':
        case '5': case '6': case '7': case '8': case '9':
          flags |= FLAGS_WIDTH;
          width = 0;
          fmt--;
          do {
            if(width > INT_MAX/10)
              return PFMT_WIDTH;
            width *= 10;
            width += *fmt - '0';
            fmt++;
          } while(ISDIGIT(*fmt));
          break;
        case '*':  /* read width from argument list */
          flags |= FLAGS_WIDTHPARAM;
          if(use_dollar == DOLLAR_USE) {
            width = dollarstring(fmt, &fmt);
            if(width < 0)
              /* illegal combo */
              return PFMT_DOLLARWIDTH;
          }
          else
            /* pick from the next argument */
            width = -1;
          break;
        default:
          loopit = FALSE;
          fmt--;
          break;
        } /* switch */
      } /* while */

      switch(*fmt) {
      case 'S':
        flags |= FLAGS_ALT;
        FALLTHROUGH();
      case 's':
        type = FORMAT_STRING;
        break;
      case 'n':
        type = FORMAT_INTPTR;
        break;
      case 'p':
        type = FORMAT_PTR;
        break;
      case 'd':
      case 'i':
        if(flags & FLAGS_LONGLONG)
          type = FORMAT_LONGLONG;
        else if(flags & FLAGS_LONG)
          type = FORMAT_LONG;
        else
          type = FORMAT_INT;
        break;
      case 'u':
        if(flags & FLAGS_LONGLONG)
          type = FORMAT_LONGLONGU;
        else if(flags & FLAGS_LONG)
          type = FORMAT_LONGU;
        else
          type = FORMAT_INTU;
        flags |= FLAGS_UNSIGNED;
        break;
      case 'o':
        type = FORMAT_INT;
        flags |= FLAGS_OCTAL;
        break;
      case 'x':
        type = FORMAT_INTU;
        flags |= FLAGS_HEX|FLAGS_UNSIGNED;
        break;
      case 'X':
        type = FORMAT_INTU;
        flags |= FLAGS_HEX|FLAGS_UPPER|FLAGS_UNSIGNED;
        break;
      case 'c':
        type = FORMAT_INT;
        flags |= FLAGS_CHAR;
        break;
      case 'f':
        type = FORMAT_DOUBLE;
        break;
      case 'e':
        type = FORMAT_DOUBLE;
        flags |= FLAGS_FLOATE;
        break;
      case 'E':
        type = FORMAT_DOUBLE;
        flags |= FLAGS_FLOATE|FLAGS_UPPER;
        break;
      case 'g':
        type = FORMAT_DOUBLE;
        flags |= FLAGS_FLOATG;
        break;
      case 'G':
        type = FORMAT_DOUBLE;
        flags |= FLAGS_FLOATG|FLAGS_UPPER;
        break;
      default:
        /* invalid instruction, disregard and continue */
        continue;
      } /* switch */

      if(flags & FLAGS_WIDTHPARAM) {
        if(width < 0)
          width = param_num++;
        else {
          /* if this identifies a parameter already used, this
             is illegal */
          if(usedinput[width/8] & (1 << (width&7)))
            return PFMT_WIDTHARG;
        }
        if(width >= MAX_PARAMETERS)
          return PFMT_MANYARGS;
        if(width >= max_param)
          max_param = width;

        in[width].type = FORMAT_WIDTH;
        /* mark as used */
        usedinput[width/8] |= (unsigned char)(1 << (width&7));
      }

      if(flags & FLAGS_PRECPARAM) {
        if(precision < 0)
          precision = param_num++;
        else {
          /* if this identifies a parameter already used, this
             is illegal */
          if(usedinput[precision/8] & (1 << (precision&7)))
            return PFMT_PRECARG;
        }
        if(precision >= MAX_PARAMETERS)
          return PFMT_MANYARGS;
        if(precision >= max_param)
          max_param = precision;

        in[precision].type = FORMAT_PRECISION;
        usedinput[precision/8] |= (unsigned char)(1 << (precision&7));
      }

      /* Handle the specifier */
      if(param < 0)
        param = param_num++;
      if(param >= MAX_PARAMETERS)
        return PFMT_MANYARGS;
      if(param >= max_param)
        max_param = param;

      iptr = &in[param];
      iptr->type = type;

      /* mark this input as used */
      usedinput[param/8] |= (unsigned char)(1 << (param&7));

      fmt++;
      optr = &out[ocount++];
      if(ocount > MAX_SEGMENTS)
        return PFMT_MANYSEGS;
      optr->input = param;
      optr->flags = flags;
      optr->width = width;
      optr->precision = precision;
      optr->start = start;
      optr->outlen = outlen;
      start = fmt;
    }
    else
      fmt++;
  }

  /* is there a trailing piece */
  outlen = fmt - start;
  if(outlen) {
    optr = &out[ocount++];
    if(ocount > MAX_SEGMENTS)
      return PFMT_MANYSEGS;
    optr->input = 0;
    optr->flags = FLAGS_SUBSTR;
    optr->start = start;
    optr->outlen = outlen;
  }

  /* Read the arg list parameters into our data list */
  for(i = 0; i < max_param + 1; i++) {
    struct va_input *iptr = &in[i];
    if(!(usedinput[i/8] & (1 << (i&7))))
      /* bad input */
      return PFMT_INPUTGAP;

    /* based on the type, read the correct argument */
    switch(iptr->type) {
    case FORMAT_STRING:
      iptr->val.str = va_arg(arglist, char *);
      break;

    case FORMAT_INTPTR:
    case FORMAT_PTR:
      iptr->val.ptr = va_arg(arglist, void *);
      break;

    case FORMAT_LONGLONGU:
      iptr->val.numu = (mp_uintmax_t)va_arg(arglist, mp_uintmax_t);
      break;

    case FORMAT_LONGLONG:
      iptr->val.nums = (mp_intmax_t)va_arg(arglist, mp_intmax_t);
      break;

    case FORMAT_LONGU:
      iptr->val.numu = (mp_uintmax_t)va_arg(arglist, unsigned long);
      break;

    case FORMAT_LONG:
      iptr->val.nums = (mp_intmax_t)va_arg(arglist, long);
      break;

    case FORMAT_INTU:
      iptr->val.numu = (mp_uintmax_t)va_arg(arglist, unsigned int);
      break;

    case FORMAT_INT:
    case FORMAT_WIDTH:
    case FORMAT_PRECISION:
      iptr->val.nums = (mp_intmax_t)va_arg(arglist, int);
      break;

    case FORMAT_DOUBLE:
      iptr->val.dnum = va_arg(arglist, double);
      break;

    default:
      DEBUGASSERT(NULL); /* unexpected */
      break;
    }
  }
  *ipieces = max_param + 1;
  *opieces = ocount;

  return PFMT_OK;
}

/*
 * formatf() - the general printf function.
 *
 * It calls parsefmt() to parse the format string. It populates two arrays;
 * one that describes the input arguments and one that describes a number of
 * output segments.
 *
 * On success, the input array describes the type of all arguments and their
 * values.
 *
 * The function then iterates over the output segments and outputs them one
 * by one until done. Using the appropriate input arguments (if any).
 *
 * All output is sent to the 'stream()' callback, one byte at a time.
 */

static int formatf(
  void *userp, /* untouched by format(), just sent to the stream() function in
                  the second argument */
  /* function pointer called for each output character */
  int (*stream)(unsigned char, void *),
  const char *format,    /* %-formatted string */
  va_list ap_save) /* list of parameters */
{
  static const char nilstr[] = "(nil)";
  const char *digits = lower_digits;   /* Base-36 digits for numbers.  */
  int done = 0;   /* number of characters written  */
  int i;
  int ocount = 0; /* number of output segments */
  int icount = 0; /* number of input arguments */

  struct outsegment output[MAX_SEGMENTS];
  struct va_input input[MAX_PARAMETERS];
  char work[BUFFSIZE];

  /* 'workend' points to the final buffer byte position, but with an extra
     byte as margin to avoid the (false?) warning Coverity gives us
     otherwise */
  char *workend = &work[sizeof(work) - 2];

  /* Parse the format string */
  if(parsefmt(format, output, input, &ocount, &icount, ap_save))
    return 0;

  for(i = 0; i < ocount; i++) {
    struct outsegment *optr = &output[i];
    struct va_input *iptr;
    bool is_alt;            /* Format spec modifiers.  */
    int width;              /* Width of a field.  */
    int prec;               /* Precision of a field.  */
    bool is_neg;            /* Decimal integer is negative.  */
    unsigned long base;     /* Base of a number to be written.  */
    mp_uintmax_t num;       /* Integral values to be written.  */
    mp_intmax_t signed_num; /* Used to convert negative in positive.  */
    char *w;
    size_t outlen = optr->outlen;
    int flags = optr->flags;

    if(outlen) {
      char *str = optr->start;
      for(; outlen && *str; outlen--)
        OUTCHAR(*str++);
      if(optr->flags & FLAGS_SUBSTR)
        /* this is just a substring */
        continue;
    }

    /* pick up the specified width */
    if(flags & FLAGS_WIDTHPARAM) {
      width = (int)input[optr->width].val.nums;
      if(width < 0) {
        /* "A negative field width is taken as a '-' flag followed by a
           positive field width." */
        if(width == INT_MIN)
          width = INT_MAX;
        else
          width = -width;
        flags |= FLAGS_LEFT;
        flags &= ~FLAGS_PAD_NIL;
      }
    }
    else
      width = optr->width;

    /* pick up the specified precision */
    if(flags & FLAGS_PRECPARAM) {
      prec = (int)input[optr->precision].val.nums;
      if(prec < 0)
        /* "A negative precision is taken as if the precision were
           omitted." */
        prec = -1;
    }
    else if(flags & FLAGS_PREC)
      prec = optr->precision;
    else
      prec = -1;

    is_alt = (flags & FLAGS_ALT) ? 1 : 0;
    iptr = &input[optr->input];

    switch(iptr->type) {
    case FORMAT_INTU:
    case FORMAT_LONGU:
    case FORMAT_LONGLONGU:
      flags |= FLAGS_UNSIGNED;
      FALLTHROUGH();
    case FORMAT_INT:
    case FORMAT_LONG:
    case FORMAT_LONGLONG:
      num = iptr->val.numu;
      if(flags & FLAGS_CHAR) {
        /* Character.  */
        if(!(flags & FLAGS_LEFT))
          while(--width > 0)
            OUTCHAR(' ');
        OUTCHAR((char) num);
        if(flags & FLAGS_LEFT)
          while(--width > 0)
            OUTCHAR(' ');
        break;
      }
      if(flags & FLAGS_OCTAL) {
        /* Octal unsigned integer */
        base = 8;
        is_neg = FALSE;
      }
      else if(flags & FLAGS_HEX) {
        /* Hexadecimal unsigned integer */
        digits = (flags & FLAGS_UPPER)? upper_digits : lower_digits;
        base = 16;
        is_neg = FALSE;
      }
      else if(flags & FLAGS_UNSIGNED) {
        /* Decimal unsigned integer */
        base = 10;
        is_neg = FALSE;
      }
      else {
        /* Decimal integer.  */
        base = 10;

        is_neg = (iptr->val.nums < (mp_intmax_t)0);
        if(is_neg) {
          /* signed_num might fail to hold absolute negative minimum by 1 */
          signed_num = iptr->val.nums + (mp_intmax_t)1;
          signed_num = -signed_num;
          num = (mp_uintmax_t)signed_num;
          num += (mp_uintmax_t)1;
        }
      }
number:
      /* Supply a default precision if none was given.  */
      if(prec == -1)
        prec = 1;

      /* Put the number in WORK.  */
      w = workend;
      switch(base) {
      case 10:
        while(num > 0) {
          *w-- = (char)('0' + (num % 10));
          num /= 10;
        }
        break;
      default:
        while(num > 0) {
          *w-- = digits[num % base];
          num /= base;
        }
        break;
      }
      width -= (int)(workend - w);
      prec -= (int)(workend - w);

      if(is_alt && base == 8 && prec <= 0) {
        *w-- = '0';
        --width;
      }

      if(prec > 0) {
        width -= prec;
        while(prec-- > 0 && w >= work)
          *w-- = '0';
      }

      if(is_alt && base == 16)
        width -= 2;

      if(is_neg || (flags & FLAGS_SHOWSIGN) || (flags & FLAGS_SPACE))
        --width;

      if(!(flags & FLAGS_LEFT) && !(flags & FLAGS_PAD_NIL))
        while(width-- > 0)
          OUTCHAR(' ');

      if(is_neg)
        OUTCHAR('-');
      else if(flags & FLAGS_SHOWSIGN)
        OUTCHAR('+');
      else if(flags & FLAGS_SPACE)
        OUTCHAR(' ');

      if(is_alt && base == 16) {
        OUTCHAR('0');
        if(flags & FLAGS_UPPER)
          OUTCHAR('X');
        else
          OUTCHAR('x');
      }

      if(!(flags & FLAGS_LEFT) && (flags & FLAGS_PAD_NIL))
        while(width-- > 0)
          OUTCHAR('0');

      /* Write the number.  */
      while(++w <= workend) {
        OUTCHAR(*w);
      }

      if(flags & FLAGS_LEFT)
        while(width-- > 0)
          OUTCHAR(' ');
      break;

    case FORMAT_STRING: {
      const char *str;
      size_t len;

      str = (char *)iptr->val.str;
      if(!str) {
        /* Write null string if there's space.  */
        if(prec == -1 || prec >= (int) sizeof(nilstr) - 1) {
          str = nilstr;
          len = sizeof(nilstr) - 1;
          /* Disable quotes around (nil) */
          flags &= (~FLAGS_ALT);
        }
        else {
          str = "";
          len = 0;
        }
      }
      else if(prec != -1)
        len = (size_t)prec;
      else if(*str == '\0')
        len = 0;
      else
        len = strlen(str);

      width -= (len > INT_MAX) ? INT_MAX : (int)len;

      if(flags & FLAGS_ALT)
        OUTCHAR('"');

      if(!(flags&FLAGS_LEFT))
        while(width-- > 0)
          OUTCHAR(' ');

      for(; len && *str; len--)
        OUTCHAR(*str++);
      if(flags&FLAGS_LEFT)
        while(width-- > 0)
          OUTCHAR(' ');

      if(flags & FLAGS_ALT)
        OUTCHAR('"');
      break;
    }

    case FORMAT_PTR:
      /* Generic pointer.  */
      if(iptr->val.ptr) {
        /* If the pointer is not NULL, write it as a %#x spec.  */
        base = 16;
        digits = (flags & FLAGS_UPPER)? upper_digits : lower_digits;
        is_alt = TRUE;
        num = (size_t) iptr->val.ptr;
        is_neg = FALSE;
        goto number;
      }
      else {
        /* Write "(nil)" for a nil pointer.  */
        const char *point;

        width -= (int)(sizeof(nilstr) - 1);
        if(flags & FLAGS_LEFT)
          while(width-- > 0)
            OUTCHAR(' ');
        for(point = nilstr; *point != '\0'; ++point)
          OUTCHAR(*point);
        if(!(flags & FLAGS_LEFT))
          while(width-- > 0)
            OUTCHAR(' ');
      }
      break;

    case FORMAT_DOUBLE: {
      char formatbuf[32]="%";
      char *fptr = &formatbuf[1];
      size_t left = sizeof(formatbuf)-strlen(formatbuf);
      int len;

      if(flags & FLAGS_WIDTH)
        width = optr->width;

      if(flags & FLAGS_PREC)
        prec = optr->precision;

      if(flags & FLAGS_LEFT)
        *fptr++ = '-';
      if(flags & FLAGS_SHOWSIGN)
        *fptr++ = '+';
      if(flags & FLAGS_SPACE)
        *fptr++ = ' ';
      if(flags & FLAGS_ALT)
        *fptr++ = '#';

      *fptr = 0;

      if(width >= 0) {
        if(width >= (int)sizeof(work))
          width = sizeof(work)-1;
        /* RECURSIVE USAGE */
        len = curl_msnprintf(fptr, left, "%d", width);
        fptr += len;
        left -= len;
      }
      if(prec >= 0) {
        /* for each digit in the integer part, we can have one less
           precision */
        size_t maxprec = sizeof(work) - 2;
        double val = iptr->val.dnum;
        if(width > 0 && prec <= width)
          maxprec -= width;
        while(val >= 10.0) {
          val /= 10;
          maxprec--;
        }

        if(prec > (int)maxprec)
          prec = (int)maxprec-1;
        if(prec < 0)
          prec = 0;
        /* RECURSIVE USAGE */
        len = curl_msnprintf(fptr, left, ".%d", prec);
        fptr += len;
      }
      if(flags & FLAGS_LONG)
        *fptr++ = 'l';

      if(flags & FLAGS_FLOATE)
        *fptr++ = (char)((flags & FLAGS_UPPER) ? 'E':'e');
      else if(flags & FLAGS_FLOATG)
        *fptr++ = (char)((flags & FLAGS_UPPER) ? 'G' : 'g');
      else
        *fptr++ = 'f';

      *fptr = 0; /* and a final null-termination */

#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wformat-nonliteral"
#endif
      /* NOTE NOTE NOTE!! Not all sprintf implementations return number of
         output characters */
#ifdef HAVE_SNPRINTF
      (snprintf)(work, sizeof(work), formatbuf, iptr->val.dnum);
#else
      (sprintf)(work, formatbuf, iptr->val.dnum);
#endif
#ifdef __clang__
#pragma clang diagnostic pop
#endif
      DEBUGASSERT(strlen(work) <= sizeof(work));
      for(fptr = work; *fptr; fptr++)
        OUTCHAR(*fptr);
      break;
    }

    case FORMAT_INTPTR:
      /* Answer the count of characters written.  */
#ifdef HAVE_LONG_LONG_TYPE
      if(flags & FLAGS_LONGLONG)
        *(LONG_LONG_TYPE *) iptr->val.ptr = (LONG_LONG_TYPE)done;
      else
#endif
        if(flags & FLAGS_LONG)
          *(long *) iptr->val.ptr = (long)done;
      else if(!(flags & FLAGS_SHORT))
        *(int *) iptr->val.ptr = (int)done;
      else
        *(short *) iptr->val.ptr = (short)done;
      break;

    default:
      break;
    }
  }
  return done;
}

/* fputc() look-alike */
static int addbyter(unsigned char outc, void *f)
{
  struct nsprintf *infop = f;
  if(infop->length < infop->max) {
    /* only do this if we haven't reached max length yet */
    *infop->buffer++ = outc; /* store */
    infop->length++; /* we are now one byte larger */
    return 0;     /* fputc() returns like this on success */
  }
  return 1;
}

int curl_mvsnprintf(char *buffer, size_t maxlength, const char *format,
                    va_list ap_save)
{
  int retcode;
  struct nsprintf info;

  info.buffer = buffer;
  info.length = 0;
  info.max = maxlength;

  retcode = formatf(&info, addbyter, format, ap_save);
  if(info.max) {
    /* we terminate this with a zero byte */
    if(info.max == info.length) {
      /* we're at maximum, scrap the last letter */
      info.buffer[-1] = 0;
      DEBUGASSERT(retcode);
      retcode--; /* don't count the nul byte */
    }
    else
      info.buffer[0] = 0;
  }
  return retcode;
}

int curl_msnprintf(char *buffer, size_t maxlength, const char *format, ...)
{
  int retcode;
  va_list ap_save; /* argument pointer */
  va_start(ap_save, format);
  retcode = curl_mvsnprintf(buffer, maxlength, format, ap_save);
  va_end(ap_save);
  return retcode;
}

/* fputc() look-alike */
static int alloc_addbyter(unsigned char outc, void *f)
{
  struct asprintf *infop = f;
  CURLcode result = Curl_dyn_addn(infop->b, &outc, 1);
  if(result) {
    infop->merr = result == CURLE_TOO_LARGE ? MERR_TOO_LARGE : MERR_MEM;
    return 1 ; /* fail */
  }
  return 0;
}

/* appends the formatted string, returns MERR error code */
int Curl_dyn_vprintf(struct dynbuf *dyn, const char *format, va_list ap_save)
{
  struct asprintf info;
  info.b = dyn;
  info.merr = MERR_OK;

  (void)formatf(&info, alloc_addbyter, format, ap_save);
  if(info.merr) {
    Curl_dyn_free(info.b);
    return info.merr;
  }
  return 0;
}

char *curl_mvaprintf(const char *format, va_list ap_save)
{
  struct asprintf info;
  struct dynbuf dyn;
  info.b = &dyn;
  Curl_dyn_init(info.b, DYN_APRINTF);
  info.merr = MERR_OK;

  (void)formatf(&info, alloc_addbyter, format, ap_save);
  if(info.merr) {
    Curl_dyn_free(info.b);
    return NULL;
  }
  if(Curl_dyn_len(info.b))
    return Curl_dyn_ptr(info.b);
  return strdup("");
}

char *curl_maprintf(const char *format, ...)
{
  va_list ap_save;
  char *s;
  va_start(ap_save, format);
  s = curl_mvaprintf(format, ap_save);
  va_end(ap_save);
  return s;
}

static int storebuffer(unsigned char outc, void *f)
{
  char **buffer = f;
  **buffer = outc;
  (*buffer)++;
  return 0;
}

int curl_msprintf(char *buffer, const char *format, ...)
{
  va_list ap_save; /* argument pointer */
  int retcode;
  va_start(ap_save, format);
  retcode = formatf(&buffer, storebuffer, format, ap_save);
  va_end(ap_save);
  *buffer = 0; /* we terminate this with a zero byte */
  return retcode;
}

static int fputc_wrapper(unsigned char outc, void *f)
{
  int out = outc;
  FILE *s = f;
  int rc = fputc(out, s);
  if(rc == out)
    return 0;
  return 1;
}

int curl_mprintf(const char *format, ...)
{
  int retcode;
  va_list ap_save; /* argument pointer */
  va_start(ap_save, format);

  retcode = formatf(stdout, fputc_wrapper, format, ap_save);
  va_end(ap_save);
  return retcode;
}

int curl_mfprintf(FILE *whereto, const char *format, ...)
{
  int retcode;
  va_list ap_save; /* argument pointer */
  va_start(ap_save, format);
  retcode = formatf(whereto, fputc_wrapper, format, ap_save);
  va_end(ap_save);
  return retcode;
}

int curl_mvsprintf(char *buffer, const char *format, va_list ap_save)
{
  int retcode = formatf(&buffer, storebuffer, format, ap_save);
  *buffer = 0; /* we terminate this with a zero byte */
  return retcode;
}

int curl_mvprintf(const char *format, va_list ap_save)
{
  return formatf(stdout, fputc_wrapper, format, ap_save);
}

int curl_mvfprintf(FILE *whereto, const char *format, va_list ap_save)
{
  return formatf(whereto, fputc_wrapper, format, ap_save);
}
