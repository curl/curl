
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>

#define EAT_SPACE(ptr) while( ptr && *ptr && isspace(*ptr) ) ptr++
#define EAT_WORD(ptr) while( ptr && *ptr && !isspace(*ptr) && ('>' != *ptr)) ptr++

char *spitout(FILE *stream, char *main, char *sub, int *size)
{
  char buffer[8192]; /* big enough for anything */
  char cmain[128]=""; /* current main section */
  char csub[128]="";  /* current sub section */
  char *ptr;
  char *end;
  char display = 0;

  char *string;
  int stringlen=0;
  int stralloc=256;

  enum {
    STATE_OUTSIDE,
    STATE_INMAIN,
    STATE_INSUB,
    STATE_ILLEGAL
  } state = STATE_OUTSIDE;

  string = (char *)malloc(stralloc);
  
  while(fgets(buffer, sizeof(buffer), stream)) {

    ptr = buffer;

    /* pass white spaces */
    EAT_SPACE(ptr);

    if('<' != *ptr) {
      if(display) {
        int len;
        printf("=> %s", buffer);
        
        len = strlen(buffer);

        if((len + stringlen) > stralloc) {
          char *newptr= realloc(string, stralloc*2);
          if(newptr) {
            string = newptr;
            stralloc *= 2;
          }
          else
            return NULL;
        }
        strcpy(&string[stringlen], buffer);
        stringlen += len;
      }
      continue;
    }

    ptr++;
    EAT_SPACE(ptr);

    if('/' == *ptr) {
      /* end of a section */
      ptr++;
      EAT_SPACE(ptr);

      end = ptr;
      EAT_WORD(end);
      *end = 0;

      if((state == STATE_INSUB) &&
         !strcmp(csub, ptr)) {
        /* this is the end of the currently read sub section */
        state--;
        csub[0]=0; /* no sub anymore */
      }
      else if((state == STATE_INMAIN) &&
              !strcmp(cmain, ptr)) {
        /* this is the end of the currently read main section */
        state--;
        cmain[0]=0; /* no main anymore */
      }
    }
    else {
      /* this is the beginning of a section */
      end = ptr;
      EAT_WORD(end);
      
      *end = 0;
      switch(state) {
      case STATE_OUTSIDE:
        strcpy(cmain, ptr);
        state = STATE_INMAIN;
        break;
      case STATE_INMAIN:
        strcpy(csub, ptr);
        state = STATE_INSUB;
        break;
      }
    }

    if((STATE_INSUB == state) &&
       !strcmp(cmain, main) &&
       !strcmp(csub, sub)) {
      printf("* %s\n", buffer);
      display = 1; /* start displaying */
    }
    else {
      printf("%d (%s/%s): %s\n", state, cmain, csub, buffer);
      display = 0; /* no display */
    }
  }

  *size = stringlen;
  return string;
}

#ifdef TEST
int main(int argc, char **argv)
{
  if(argc< 3) {
    printf("./moo main sub\n");
  }
  else {
    int size;
    char *buffer = spitout(stdin, argv[1], argv[2], &size);
  }
  return 0;
}
#endif
