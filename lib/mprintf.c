/****************************************************************************
 *
 * $Id$
 *
 *************************************************************************
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
 * MERCHANTIBILITY AND FITNESS FOR A PARTICULAR PURPOSE. THE AUTHORS AND
 * CONTRIBUTORS ACCEPT NO RESPONSIBILITY IN ANY CONCEIVABLE MANNER.
 *
 * Purpose:
 *  A merge of Bjorn Reese's format() function and Daniel's dsprintf()
 *  1.0. A full blooded printf() clone with full support for <num>$
 *  everywhere (parameters, widths and precisions) including variabled
 *  sized parameters (like doubles, long longs, long doubles and even
 *  void * in 64-bit architectures).
 *
 * Current restrictions:
 * - Max 128 parameters
 * - No 'long double' support.
 *
 * If you ever want truly portable and good *printf() clones, the project that
 * took on from here is named 'Trio' and you find more details on the trio web
 * page at http://daniel.haxx.se/trio/
 */


#include "setup.h"
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <ctype.h>
#include <string.h>

#ifndef SIZEOF_LONG_LONG
/* prevents warnings on picky compilers */
#define SIZEOF_LONG_LONG 0
#endif
#ifndef SIZEOF_LONG_DOUBLE
#define SIZEOF_LONG_DOUBLE 0
#endif


/* The last #include file should be: */
#ifdef MALLOCDEBUG
#include "memdebug.h"
#endif

#define BUFFSIZE 256 /* buffer for long-to-str and float-to-str calcs */
#define MAX_PARAMETERS 128 /* lame static limit */

#undef TRUE
#undef FALSE
#undef BOOL
#ifdef __cplusplus
# define TRUE true
# define FALSE false
# define BOOL bool
#else
# define TRUE  ((char)(1 == 1))
# define FALSE ((char)(0 == 1))
# define BOOL char
#endif


/* Lower-case digits.  */
static const char lower_digits[] = "0123456789abcdefghijklmnopqrstuvwxyz";

/* Upper-case digits.  */
static const char upper_digits[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";

#define	OUTCHAR(x) done+=(stream(x, (FILE *)data)==-1?0:1)

/* Data type to read from the arglist */
typedef enum  {
  FORMAT_UNKNOWN = 0,
  FORMAT_STRING,
  FORMAT_PTR,
  FORMAT_INT,
  FORMAT_INTPTR,
  FORMAT_LONG,
  FORMAT_LONGLONG,
  FORMAT_DOUBLE,
  FORMAT_LONGDOUBLE,
  FORMAT_WIDTH /* For internal use */
} FormatType;

/* convertion and display flags */
enum {
  FLAGS_NEW        = 0,
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
  FLAGS_FLOATG     = 1<<19  /* %g or %G */
};

typedef struct {
  FormatType type;
  int flags;
  int width;     /* width OR width parameter number */
  int precision; /* precision OR precision parameter number */
  union {
    char *str;
    void *ptr;
    long num;
#if SIZEOF_LONG_LONG /* if this is non-zero */
    long long lnum;
#endif
    double dnum;
#if SIZEOF_LONG_DOUBLE
    long double ldnum;
#endif
  } data;
} va_stack_t;

struct nsprintf {
  char *buffer;
  size_t length;
  size_t max;
};

struct asprintf {
  char *buffer; /* allocated buffer */
  size_t len;   /* length of string */
  size_t alloc; /* length of alloc */
};

int curl_msprintf(char *buffer, const char *format, ...);

static int dprintf_DollarString(char *input, char **end)
{
  int number=0;
  while(isdigit((int)*input)) {
    number *= 10;
    number += *input-'0';
    input++;
  }
  if(number && ('$'==*input++)) {
    *end = input;
    return number;
  }
  return 0;
}

static BOOL dprintf_IsQualifierNoDollar(char c)
{
  switch (c) {
  case '-': case '+': case ' ': case '#': case '.':
  case '0': case '1': case '2': case '3': case '4':
  case '5': case '6': case '7': case '8': case '9':
  case 'h': case 'l': case 'L': case 'Z': case 'q':
    return TRUE;
  default:
    return FALSE;
  }
}

#ifdef DPRINTF_DEBUG2
int dprintf_Pass1Report(va_stack_t *vto, int max)
{
  int i;
  char buffer[128];
  int bit;
  int flags;

  for(i=0; i<max; i++) {
    char *type;
    switch(vto[i].type) {
    case FORMAT_UNKNOWN:
      type = "unknown";
      break;
    case FORMAT_STRING:
      type ="string";
      break;
    case FORMAT_PTR:
      type ="pointer";
      break;
    case FORMAT_INT:
      type = "int";
      break;
    case FORMAT_LONG:
      type = "long";
      break;
    case FORMAT_LONGLONG:
      type = "long long";
      break;
    case FORMAT_DOUBLE:
      type = "double";
      break;
    case FORMAT_LONGDOUBLE:
      type = "long double";
      break;      
    }


    buffer[0]=0;

    for(bit=0; bit<31; bit++) {
      flags = vto[i].flags & (1<<bit);

      if(flags & FLAGS_SPACE)
	strcat(buffer, "space ");
      else if(flags & FLAGS_SHOWSIGN)
	strcat(buffer, "plus ");
      else if(flags & FLAGS_LEFT)
	strcat(buffer, "left ");
      else if(flags & FLAGS_ALT)
	strcat(buffer, "alt ");
      else if(flags & FLAGS_SHORT)
	strcat(buffer, "short ");
      else if(flags & FLAGS_LONG)
	strcat(buffer, "long ");
      else if(flags & FLAGS_LONGLONG)
	strcat(buffer, "longlong ");
      else if(flags & FLAGS_LONGDOUBLE)
	strcat(buffer, "longdouble ");
      else if(flags & FLAGS_PAD_NIL)
	strcat(buffer, "padnil ");
      else if(flags & FLAGS_UNSIGNED)
	strcat(buffer, "unsigned ");
      else if(flags & FLAGS_OCTAL)
	strcat(buffer, "octal ");
      else if(flags & FLAGS_HEX)
	strcat(buffer, "hex ");
      else if(flags & FLAGS_UPPER)
	strcat(buffer, "upper ");
      else if(flags & FLAGS_WIDTH)
	strcat(buffer, "width ");
      else if(flags & FLAGS_WIDTHPARAM)
	strcat(buffer, "widthparam ");
      else if(flags & FLAGS_PREC)
	strcat(buffer, "precision ");
      else if(flags & FLAGS_PRECPARAM)
	strcat(buffer, "precparam ");
      else if(flags & FLAGS_CHAR)
	strcat(buffer, "char ");
      else if(flags & FLAGS_FLOATE)
	strcat(buffer, "floate ");
      else if(flags & FLAGS_FLOATG)
	strcat(buffer, "floatg ");
    }
    printf("REPORT: %d. %s [%s]\n", i, type, buffer);

  }


}
#endif

/******************************************************************
 *
 * Pass 1:
 * Create an index with the type of each parameter entry and its
 * value (may vary in size)
 *
 ******************************************************************/

static int dprintf_Pass1(char *format, va_stack_t *vto, char **endpos, va_list arglist)
{
  char *fmt = format;
  int param_num = 0;
  int this_param;
  int width;
  int precision;
  int flags;
  int max_param=0;
  int i;

  while (*fmt) {
    if (*fmt++ == '%') {
      if (*fmt == '%') {
	fmt++;
	continue; /* while */
      }

      flags = FLAGS_NEW;

      /* Handle the positional case (N$) */

      param_num++;
      
      this_param = dprintf_DollarString(fmt, &fmt);
      if (0 == this_param)
	/* we got no positional, get the next counter */
	this_param = param_num;

      if (this_param > max_param)
	max_param = this_param;

      /*
       * The parameter with number 'i' should be used. Next, we need
       * to get SIZE and TYPE of the parameter. Add the information
       * to our array.
       */

      width = 0;
      precision = 0;

      /* Handle the flags */

      while (dprintf_IsQualifierNoDollar(*fmt)) {
	switch (*fmt++) {
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
	  flags |= FLAGS_PREC;
	  if ('*' == *fmt) {
	    /* The precision is picked from a specified parameter */

	    flags |= FLAGS_PRECPARAM;
	    fmt++;
	    param_num++;

	    i = dprintf_DollarString(fmt, &fmt);
	    if (i)
	      precision = i;
	    else
	      precision = param_num;

	    if (precision > max_param)
	      max_param = precision;
       	  }
	  else {
	    flags |= FLAGS_PREC;
	    precision = strtol(fmt, &fmt, 10);
	  }
	  break;
	case 'h':
	  flags |= FLAGS_SHORT;
	  break;
	case 'l':
	  if (flags & FLAGS_LONG)
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
	case 'Z':
	  if (sizeof(size_t) > sizeof(unsigned long int))
	    flags |= FLAGS_LONGLONG;
	  if (sizeof(size_t) > sizeof(unsigned int))
	    flags |= FLAGS_LONG;
	  break;
	case '0':
	  if (!(flags & FLAGS_LEFT))
	    flags |= FLAGS_PAD_NIL;
	  /* FALLTHROUGH */
	case '1': case '2': case '3': case '4':
	case '5': case '6': case '7': case '8': case '9':
	  flags |= FLAGS_WIDTH;
	  width = strtol(fmt-1, &fmt, 10);
	  break;
	case '*':  /* Special case */
	  flags |= FLAGS_WIDTHPARAM;
	  param_num++;
	  
	  i = dprintf_DollarString(fmt, &fmt);
	  if(i)
	    width = i;
	  else
	    width = param_num;
	  if(width > max_param)
	    max_param=width;
	  break;
	default:
	  break;
	}
      } /* switch */

      /* Handle the specifier */

      i = this_param - 1;

      switch (*fmt) {
      case 'S':
	flags |= FLAGS_ALT;
	/* FALLTHROUGH */
      case 's':
	vto[i].type = FORMAT_STRING;
	break;
      case 'n':
	vto[i].type = FORMAT_INTPTR;
	break;
      case 'p':
	vto[i].type = FORMAT_PTR;
	break;
      case 'd': case 'i':
	vto[i].type = FORMAT_INT;
	break;
      case 'u':
	vto[i].type = FORMAT_INT;
	flags |= FLAGS_UNSIGNED;
	break;
      case 'o':
	vto[i].type = FORMAT_INT;
	flags |= FLAGS_OCTAL;
	break;
      case 'x':
	vto[i].type = FORMAT_INT;
	flags |= FLAGS_HEX;
	break;
      case 'X':
	vto[i].type = FORMAT_INT;
	flags |= FLAGS_HEX|FLAGS_UPPER;
	break;
      case 'c':
	vto[i].type = FORMAT_INT;
	flags |= FLAGS_CHAR;
	break;	
      case 'f':
	vto[i].type = FORMAT_DOUBLE;
	break;
      case 'e': case 'E':
	vto[i].type = FORMAT_DOUBLE;
	flags |= FLAGS_FLOATE| (('E' == *fmt)?FLAGS_UPPER:0);
	break;
      case 'g': case 'G':
	vto[i].type = FORMAT_DOUBLE;
	flags |= FLAGS_FLOATG| (('G' == *fmt)?FLAGS_UPPER:0);
	break;	
      default:
	vto[i].type = FORMAT_UNKNOWN;
	break;
      } /* switch */

      vto[i].flags = flags;
      vto[i].width = width;
      vto[i].precision = precision;
      
      if (flags & FLAGS_WIDTHPARAM) {
	/* we have the width specified from a parameter, so we make that
	   parameter's info setup properly */
	vto[i].width = width - 1;
	i = width - 1;
	vto[i].type = FORMAT_WIDTH;
	vto[i].flags = FLAGS_NEW;
	vto[i].precision = vto[i].width = 0; /* can't use width or precision
						of width! */	
      }
      if (flags & FLAGS_PRECPARAM) {
	/* we have the precision specified from a parameter, so we make that
	   parameter's info setup properly */
	vto[i].precision = precision - 1;
	i = precision - 1;
	vto[i].type = FORMAT_WIDTH;
	vto[i].flags = FLAGS_NEW;
	vto[i].precision = vto[i].width = 0; /* can't use width or precision
						of width! */
      }
      *endpos++ = fmt + 1; /* end of this sequence */
    }
  }

#ifdef DPRINTF_DEBUG2
  dprintf_Pass1Report(vto, max_param);
#endif

  /* Read the arg list parameters into our data list */
  for (i=0; i<max_param; i++) {
    if ((i + 1 < max_param) && (vto[i + 1].type == FORMAT_WIDTH))
      {
	/* Width/precision arguments must be read before the main argument
	 * they are attached to
	 */
	vto[i + 1].data.num = va_arg(arglist, int);
      }

    switch (vto[i].type)
      {
      case FORMAT_STRING:
	vto[i].data.str = va_arg(arglist, char *);
	break;
	
      case FORMAT_INTPTR:
      case FORMAT_UNKNOWN:
      case FORMAT_PTR:
	vto[i].data.ptr = va_arg(arglist, void *);
	break;
	
      case FORMAT_INT:
#if SIZEOF_LONG_LONG
	if(vto[i].flags & FLAGS_LONGLONG)
	  vto[i].data.lnum = va_arg(arglist, long long);
	else
#endif
	  if(vto[i].flags & FLAGS_LONG)
	    vto[i].data.num = va_arg(arglist, long);
	else
	  vto[i].data.num = va_arg(arglist, int);
	break;
	
      case FORMAT_DOUBLE:
#if SIZEOF_LONG_DOUBLE
	if(vto[i].flags & FLAGS_LONG)
	  vto[i].data.ldnum = va_arg(arglist, long double);
	else
#endif
	  vto[i].data.dnum = va_arg(arglist, double);
	break;
	
      case FORMAT_WIDTH:
	/* Argument has been read. Silently convert it into an integer
	 * for later use
	 */
	vto[i].type = FORMAT_INT;
	break;
	
      default:
	break;
      }
  }

  return max_param;

}

static int dprintf_formatf(
             void *data, /* untouched by format(), just sent to the
                            stream() function in the first argument */
	     int (*stream)(int, FILE *), /* function pointer called for each
					    output character */
	     const char *format,    /* %-formatted string */
	     va_list ap_save) /* list of parameters */
{
  /* Base-36 digits for numbers.  */
  const char *digits = lower_digits;

  /* Pointer into the format string.  */
  char *f;

  /* Number of characters written.  */
  register size_t done = 0;

  long param; /* current parameter to read */
  long param_num=0; /* parameter counter */

  va_stack_t vto[MAX_PARAMETERS];
  char *endpos[MAX_PARAMETERS];
  char **end;

  char work[BUFFSIZE];

  va_stack_t *p;

  /* Do the actual %-code parsing */
  dprintf_Pass1((char *)format, vto, endpos, ap_save);

  end = &endpos[0]; /* the initial end-position from the list dprintf_Pass1()
                       created for us */
  
  f = (char *)format;
  while (*f != '\0') {
    /* Format spec modifiers.  */
    char alt;
    
    /* Width of a field.  */
    register long width;
    /* Precision of a field.  */
    long prec;
    
    /* Decimal integer is negative.  */
    char is_neg;
    
    /* Base of a number to be written.  */
    long base;

    /* Integral values to be written.  */
#if SIZEOF_LONG_LONG
    unsigned long long num;
#else
    unsigned long num;
#endif
    long signed_num;
    
    if (*f != '%') {
      /* This isn't a format spec, so write everything out until the next one
	 OR end of string is reached.  */
      do {
	OUTCHAR(*f);
      } while(*++f && ('%' != *f));
      continue;
    }
    
    ++f;
    
    /* Check for "%%".  Note that although the ANSI standard lists
       '%' as a conversion specifier, it says "The complete format
       specification shall be `%%'," so we can avoid all the width
       and precision processing.  */
    if (*f == '%') {
      ++f;
      OUTCHAR('%');
      continue;
    }

    /* If this is a positional parameter, the position must follow imediately
       after the %, thus create a %<num>$ sequence */
    param=dprintf_DollarString(f, &f);

    if(!param)
      param = param_num;
    else
      --param;
    
    param_num++; /* increase this always to allow "%2$s %1$s %s" and then the
		    third %s will pick the 3rd argument */

    p = &vto[param];

    /* pick up the specified width */
    if(p->flags & FLAGS_WIDTHPARAM)
      width = vto[p->width].data.num;
    else
      width = p->width;

    /* pick up the specified precision */
    if(p->flags & FLAGS_PRECPARAM)
      prec = vto[p->precision].data.num;
    else if(p->flags & FLAGS_PREC)
      prec = p->precision;
    else
      prec = -1;

    alt = p->flags & FLAGS_ALT;
    
    switch (p->type) {
    case FORMAT_INT:
      num = p->data.num;
      if(p->flags & FLAGS_CHAR) {
	/* Character.  */
	if (!(p->flags & FLAGS_LEFT))
	  while (--width > 0)
	    OUTCHAR(' ');
	OUTCHAR((char) num);
	if (p->flags & FLAGS_LEFT)
	  while (--width > 0)
	    OUTCHAR(' ');
	break;
      }
      if(p->flags & FLAGS_UNSIGNED) {
	/* Decimal unsigned integer.  */
	base = 10;
	goto unsigned_number;
      }
      if(p->flags & FLAGS_OCTAL) {
	/* Octal unsigned integer.  */
	base = 8;
	goto unsigned_number;
      }
      if(p->flags & FLAGS_HEX) {
	/* Hexadecimal unsigned integer.  */

	digits = (p->flags & FLAGS_UPPER)? upper_digits : lower_digits;
	base = 16;
	goto unsigned_number;
      }

      /* Decimal integer.  */
      base = 10;

#if SIZEOF_LONG_LONG
      if(p->flags & FLAGS_LONGLONG) {
	 /* long long */
	is_neg = p->data.lnum < 0;
	num = is_neg ? (- p->data.lnum) : p->data.lnum;
      }
      else
#endif
      {
	signed_num = (long) num;
      
	is_neg = signed_num < 0;
	num = is_neg ? (- signed_num) : signed_num;
      }
      goto number;
      
    unsigned_number:;
      /* Unsigned number of base BASE.  */
      is_neg = 0;
      
    number:;
      /* Number of base BASE.  */
      {
	char *workend = &work[sizeof(work) - 1];
	register char *w;
	
	/* Supply a default precision if none was given.  */
	if (prec == -1)
	  prec = 1;
	
	/* Put the number in WORK.  */
	w = workend;
	while (num > 0) {
	  *w-- = digits[num % base];
	  num /= base;
	}
	width -= workend - w;
	prec -= workend - w;
	
	if (alt && base == 8 && prec <= 0) {
	  *w-- = '0';
	  --width;
	}
	
	if (prec > 0) {
	  width -= prec;
	  while (prec-- > 0)
	    *w-- = '0';
	}
	
	if (alt && base == 16)
	  width -= 2;
	
	if (is_neg || (p->flags & FLAGS_SHOWSIGN) || (p->flags & FLAGS_SPACE))
	  --width;
	
	if (!(p->flags & FLAGS_LEFT) && !(p->flags & FLAGS_PAD_NIL))
	  while (width-- > 0)
	    OUTCHAR(' ');
	
	if (is_neg)
	  OUTCHAR('-');
	else if (p->flags & FLAGS_SHOWSIGN)
	  OUTCHAR('+');
	else if (p->flags & FLAGS_SPACE)
	  OUTCHAR(' ');
	
	if (alt && base == 16) {
	  OUTCHAR('0');
	  if(p->flags & FLAGS_UPPER)
	    OUTCHAR('X');
	  else
	    OUTCHAR('x');
	}

	if (!(p->flags & FLAGS_LEFT) && (p->flags & FLAGS_PAD_NIL))
	  while (width-- > 0)
	    OUTCHAR('0');
	
	/* Write the number.  */
	while (++w <= workend) {
	  OUTCHAR(*w);
	}
	
	if (p->flags & FLAGS_LEFT)
	  while (width-- > 0)
	    OUTCHAR(' ');
      }
      break;
      
    case FORMAT_STRING:
	    /* String.  */
      {
	static char null[] = "(nil)";
	char *str;
	size_t len;
	
	str = (char *) p->data.str;
	if ( str == NULL) {
	  /* Write null[] if there's space.  */
	  if (prec == -1 || prec >= (long) sizeof(null) - 1) {
	    str = null;
	    len = sizeof(null) - 1;
	    /* Disable quotes around (nil) */
	    p->flags &= (~FLAGS_ALT);
	  }
	  else {
	    str = (char *)"";
	    len = 0;
	  }
	}
	else
	  len = strlen(str);
	
	if (prec != -1 && (size_t) prec < len)
	  len = prec;
	width -= len;

	if (p->flags & FLAGS_ALT)
	  OUTCHAR('"');

	if (!(p->flags&FLAGS_LEFT))
	  while (width-- > 0)
	    OUTCHAR(' ');
	
	while (len-- > 0)
	  OUTCHAR(*str++);
	if (p->flags&FLAGS_LEFT)
	  while (width-- > 0)
	    OUTCHAR(' ');

	if (p->flags & FLAGS_ALT)
	  OUTCHAR('"');
      }
      break;
      
    case FORMAT_PTR:
      /* Generic pointer.  */
      {
	void *ptr;
	ptr = (void *) p->data.ptr;
	if (ptr != NULL) {
	  /* If the pointer is not NULL, write it as a %#x spec.  */
	  base = 16;
	  digits = (p->flags & FLAGS_UPPER)? upper_digits : lower_digits;
	  alt = 1;
	  num = (unsigned long) ptr;
	  is_neg = 0;
	  goto number;
	}
	else {
	  /* Write "(nil)" for a nil pointer.  */
	  static char strnil[] = "(nil)";
	  register char *point;
	  
	  width -= sizeof(strnil) - 1;
	  if (p->flags & FLAGS_LEFT)
	    while (width-- > 0)
	      OUTCHAR(' ');
	  for (point = strnil; *point != '\0'; ++point)
	    OUTCHAR(*point);
	  if (! (p->flags & FLAGS_LEFT))
	    while (width-- > 0)
	      OUTCHAR(' ');
	}
      }
      break;

    case FORMAT_DOUBLE:
      {
	char formatbuf[32]="%";
	char *fptr;
	
	width = -1;
	if (p->flags & FLAGS_WIDTH)
	  width = p->width;
	else if (p->flags & FLAGS_WIDTHPARAM)
	  width = vto[p->width].data.num;

	prec = -1;
	if (p->flags & FLAGS_PREC)
	  prec = p->precision;
	else if (p->flags & FLAGS_PRECPARAM)
	  prec = vto[p->precision].data.num;

	if (p->flags & FLAGS_LEFT)
	  strcat(formatbuf, "-");
	if (p->flags & FLAGS_SHOWSIGN)
	  strcat(formatbuf, "+");
	if (p->flags & FLAGS_SPACE)
	  strcat(formatbuf, " ");
	if (p->flags & FLAGS_ALT)
	  strcat(formatbuf, "#");

	fptr=&formatbuf[strlen(formatbuf)];

	if(width >= 0) {
	  /* RECURSIVE USAGE */
	  fptr += curl_msprintf(fptr, "%d", width);
	}
	if(prec >= 0) {
	  /* RECURSIVE USAGE */
	  fptr += curl_msprintf(fptr, ".%d", prec);
	}
	if (p->flags & FLAGS_LONG)
	  strcat(fptr, "l");

	if (p->flags & FLAGS_FLOATE)
	  strcat(fptr, p->flags&FLAGS_UPPER?"E":"e");
	else if (p->flags & FLAGS_FLOATG)
	  strcat(fptr, (p->flags & FLAGS_UPPER) ? "G" : "g");
	else
	  strcat(fptr, "f");

	/* NOTE NOTE NOTE!! Not all sprintf() implementations returns number
	   of output characters */
#if SIZEOF_LONG_DOUBLE
	if (p->flags & FLAGS_LONG)
	  /* This is for support of the 'long double' type */
	  (sprintf)(work, formatbuf, p->data.ldnum);
	else
#endif
	  (sprintf)(work, formatbuf, p->data.dnum);

	for(fptr=work; *fptr; fptr++)
	  OUTCHAR(*fptr);
      }
      break;

    case FORMAT_INTPTR:
      /* Answer the count of characters written.  */
#if SIZEOF_LONG_LONG
      if (p->flags & FLAGS_LONGLONG)
	*(long long int *) p->data.ptr = done;
      else
#endif
	if (p->flags & FLAGS_LONG)
	  *(long int *) p->data.ptr = done;
      else if (!(p->flags & FLAGS_SHORT))
	*(int *) p->data.ptr = done;
      else
	*(short int *) p->data.ptr = done;
      break;

    default:
      break;
    }
    f = *end++; /* goto end of %-code */

  }
  return done;
}

/* fputc() look-alike */
static int addbyter(int output, FILE *data)
{
  struct nsprintf *infop=(struct nsprintf *)data;
 
  if(infop->length < infop->max) {
    /* only do this if we haven't reached max length yet */
    infop->buffer[0] = (char)output; /* store */
    infop->buffer++; /* increase pointer */
    infop->length++; /* we are now one byte larger */
    return output; /* fputc() returns like this on success */
  }
  return -1;
}

int curl_msnprintf(char *buffer, size_t maxlength, const char *format, ...)
{
  va_list ap_save; /* argument pointer */
  int retcode;
  struct nsprintf info;

  info.buffer = buffer;
  info.length = 0;
  info.max = maxlength;

  va_start(ap_save, format);
  retcode = dprintf_formatf(&info, addbyter, format, ap_save);
  va_end(ap_save);
  info.buffer[0] = 0; /* we terminate this with a zero byte */

  /* we could even return things like */
  
  return retcode;
}

int curl_mvsnprintf(char *buffer, size_t maxlength, const char *format, va_list ap_save)
{
  int retcode;
  struct nsprintf info;

  info.buffer = buffer;
  info.length = 0;
  info.max = maxlength;

  retcode = dprintf_formatf(&info, addbyter, format, ap_save);
  info.buffer[0] = 0; /* we terminate this with a zero byte */
  return retcode;
}


/* fputc() look-alike */
static int alloc_addbyter(int output, FILE *data)
{
  struct asprintf *infop=(struct asprintf *)data;
 
  if(!infop->buffer) {
    infop->buffer=(char *)malloc(32);
    if(!infop->buffer)
      return -1; /* fail */
    infop->alloc = 32;
    infop->len =0;
  }
  else if(infop->len+1 >= infop->alloc) {
    char *newptr;

    newptr = (char *)realloc(infop->buffer, infop->alloc*2);

    if(!newptr) {
      return -1;
    }
    infop->buffer = newptr;
    infop->alloc *= 2;
  }

  infop->buffer[ infop->len ] = output;

  infop->len++;

  return output; /* fputc() returns like this on success */
}

char *curl_maprintf(const char *format, ...)
{
  va_list ap_save; /* argument pointer */
  int retcode;
  struct asprintf info;

  info.buffer = NULL;
  info.len = 0;
  info.alloc = 0;

  va_start(ap_save, format);
  retcode = dprintf_formatf(&info, alloc_addbyter, format, ap_save);
  va_end(ap_save);
  if(-1 == retcode) {
    if(info.alloc)
      free(info.buffer);
    return NULL;
  }
  if(info.alloc) {
    info.buffer[info.len] = 0; /* we terminate this with a zero byte */
    return info.buffer;
  }
  else
    return strdup("");
}

char *curl_mvaprintf(const char *format, va_list ap_save)
{
  int retcode;
  struct asprintf info;

  info.buffer = NULL;
  info.len = 0;
  info.alloc = 0;

  retcode = dprintf_formatf(&info, alloc_addbyter, format, ap_save);
  if(-1 == retcode) {
    if(info.alloc)
      free(info.buffer);
    return NULL;
  }

  if(info.alloc) {
    info.buffer[info.len] = 0; /* we terminate this with a zero byte */
    return info.buffer;
  }
  else
    return strdup("");
}

static int storebuffer(int output, FILE *data)
{
  char **buffer = (char **)data;
  **buffer = (char)output;
  (*buffer)++;
  return output; /* act like fputc() ! */
}

int curl_msprintf(char *buffer, const char *format, ...)
{
  va_list ap_save; /* argument pointer */
  int retcode;
  va_start(ap_save, format);
  retcode = dprintf_formatf(&buffer, storebuffer, format, ap_save);
  va_end(ap_save);
  *buffer=0; /* we terminate this with a zero byte */
  return retcode;
}

#ifndef WIN32 /* not needed on win32 */
extern int fputc(int, FILE *);
#endif

int curl_mprintf(const char *format, ...)
{
  int retcode;
  va_list ap_save; /* argument pointer */
  va_start(ap_save, format);
  retcode = dprintf_formatf(stdout, fputc, format, ap_save);
  va_end(ap_save);
  return retcode;
}

int curl_mfprintf(FILE *whereto, const char *format, ...)
{
  int retcode;
  va_list ap_save; /* argument pointer */
  va_start(ap_save, format);
  retcode = dprintf_formatf(whereto, fputc, format, ap_save);
  va_end(ap_save);
  return retcode;
}

int curl_mvsprintf(char *buffer, const char *format, va_list ap_save)
{
  int retcode;
  retcode = dprintf_formatf(&buffer, storebuffer, format, ap_save);
  *buffer=0; /* we terminate this with a zero byte */
  return retcode;
}

int curl_mvprintf(const char *format, va_list ap_save)
{
  return dprintf_formatf(stdout, fputc, format, ap_save);
}

int curl_mvfprintf(FILE *whereto, const char *format, va_list ap_save)
{
  return dprintf_formatf(whereto, fputc, format, ap_save);
}

#ifdef DPRINTF_DEBUG
int main()
{
  char buffer[129];
  char *ptr;
#if SIZEOF_LONG_LONG>0
  long long hullo;
  dprintf("%3$12s %1$s %2$qd %4$d\n", "daniel", hullo, "stenberg", 65);
#endif

  mprintf("%3d %5d\n", 10, 1998);
  
  ptr=maprintf("test this then baby %s%s%s%s%s%s %d %d %d loser baby get a hit in yer face now!", "", "pretty long string pretty long string pretty long string pretty long string pretty long string", "/", "/", "/", "pretty long string", 1998, 1999, 2001);

  puts(ptr);

  memset(ptr, 55, strlen(ptr)+1);

  free(ptr);

#if 1
  mprintf(buffer, "%s %s %d", "daniel", "stenberg", 19988);
  puts(buffer);

  mfprintf(stderr, "%s %#08x\n", "dummy", 65);

  printf("%s %#08x\n", "dummy", 65);
  {
    double tryout = 3.14156592;
    mprintf(buffer, "%.2g %G %f %e %E", tryout, tryout, tryout, tryout, tryout);
    puts(buffer);
    printf("%.2g %G %f %e %E\n", tryout, tryout, tryout, tryout, tryout);
  }
#endif

  return 0;
}

#endif

/*
 * local variables:
 * eval: (load-file "../curl-mode.el")
 * end:
 * vim600: fdm=marker
 * vim: et sw=2 ts=2 sts=2 tw=78
 */
