/* sws.c: simple (silly?) web server */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

char *spitout(FILE *stream, char *main, char *sub, int *size);

#define DEFAULT_PORT 8999

#ifndef DEFAULT_LOGFILE
#define DEFAULT_LOGFILE "log/sws.log"
#endif

#define DOCBUFSIZE 4
#define BUFFERSIZE (DOCBUFSIZE * 1024)

#define VERSION "cURL test suite HTTP server/0.1"

#define REQUEST_DUMP "log/http-request.dump"

#define TEST_DATA_PATH "data/test%d"

static char *docfriends = "HTTP/1.1 200 Mighty fine indeed\r\n\r\nWE ROOLZ\r\n";
static char *doc404 = "HTTP/1.1 404 Not Found\n"
    "Server: " VERSION "\n"
    "Connection: close\n"
    "Content-Type: text/html\n"
    "\n"
    "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\">\n"
    "<HTML><HEAD>\n"
    "<TITLE>404 Not Found</TITLE>\n"
    "</HEAD><BODY>\n"
    "<H1>Not Found</H1>\n"
    "The requested URL was not found on this server.\n"
    "<P><HR><ADDRESS>" VERSION "</ADDRESS>\n" "</BODY></HTML>\n";

static volatile int sigpipe, sigterm;
static FILE *logfp;


static void logmsg(const char *msg)
{
    time_t t = time(NULL);
    struct tm *curr_time = localtime(&t);
    char loctime[80];

    strcpy(loctime, asctime(curr_time));
    loctime[strlen(loctime) - 1] = '\0';
    fprintf(logfp, "%s: pid %d: %s\n", loctime, getpid(), msg);
#ifdef DEBUG
    fprintf(stderr, "%s: pid %d: %s\n", loctime, getpid(), msg);
#endif
    fflush(logfp);
}


static void sigpipe_handler(int sig)
{
    sigpipe = 1;
}


static void sigterm_handler(int sig)
{
    char logbuf[100];
    snprintf(logbuf, 100, "Got signal %d, terminating", sig);
    logmsg(logbuf);
    sigterm = 1;
}

int ProcessRequest(char *request)
{
  char *line=request;
  unsigned long contentlength=0;

#define END_OF_HEADERS "\r\n\r\n"

  char *end;
  end = strstr(request, END_OF_HEADERS);

  if(!end)
    /* we don't have a complete request yet! */
    return 0;

  /* **** Persistancy ****
   *
   * If the request is a HTTP/1.0 one, we close the connection unconditionally
   * when we're done.
   *
   * If the request is a HTTP/1.1 one, we MUST check for a "Connection:"
   * header that might say "close". If it does, we close a connection when
   * this request is processed. Otherwise, we keep the connection alive for X
   * seconds.
   */

  do {
    if(!strncasecmp("Content-Length:", line, 15))
      contentlength = strtol(line+15, &line, 10);

    line = strchr(line, '\n');
    if(line)
      line++;
  } while(line);

  if(contentlength > 0 ) {
    if(contentlength <= strlen(end+strlen(END_OF_HEADERS)))
      return 1; /* done */
    else
      return 0; /* not complete yet */
  }
  return 1; /* done */
}

/* store the entire request in a file */
void storerequest(char *reqbuf)
{
  FILE *dump;

  dump = fopen(REQUEST_DUMP, "ab"); /* b is for windows-preparing */
  if(dump) {
    fwrite(reqbuf, 1, strlen(reqbuf), dump);

    fclose(dump);
  }

}


#define REQBUFSIZ 50000
#define REQBUFSIZ_TXT "49999"

/* very-big-path support */
#define MAXDOCNAMELEN 40000
#define MAXDOCNAMELEN_TXT "39999"

#define REQUEST_KEYWORD_SIZE 256
static int get_request(int sock, int *part)
{
  static char reqbuf[REQBUFSIZ], doc[MAXDOCNAMELEN];
  static char request[REQUEST_KEYWORD_SIZE];
  unsigned int offset = 0;
  int prot_major, prot_minor;
  char logbuf[256];

  *part = 0; /* part zero equals none */

  while (offset < REQBUFSIZ) {
    int got = recv(sock, reqbuf + offset, REQBUFSIZ - offset, 0);
    if (got <= 0) {
      if (got < 0) {
        perror("recv");
        return -1;
      }
      logmsg("Connection closed by client");
      return -1;
    }
    offset += got;

    reqbuf[offset] = 0;

    if(ProcessRequest(reqbuf))
      break;
  }

  if (offset >= REQBUFSIZ) {
    logmsg("Request buffer overflow, closing connection");
    return -1;
  }
  reqbuf[offset]=0;
  
  logmsg("Received a request");

  /* dump the request to an external file */
  storerequest(reqbuf);

  if (sscanf(reqbuf, "%" REQBUFSIZ_TXT"s %" MAXDOCNAMELEN_TXT "s HTTP/%d.%d",
             request,
             doc,
             &prot_major,
             &prot_minor) == 4) {
    char *ptr;
    int test_no=0;

    /* find the last slash */
    ptr = strrchr(doc, '/');

    /* get the number after it */
    if(ptr) {

      if((strlen(doc) + strlen(request)) < 200)
        sprintf(logbuf, "Got request: %s %s HTTP/%d.%d",
                request, doc, prot_major, prot_minor);
      else
        sprintf(logbuf, "Got a *HUGE* request HTTP/%d.%d",
                prot_major, prot_minor);
      logmsg(logbuf);
      
      if(!strncmp("/verifiedserver", ptr, 15)) {
        logmsg("Are-we-friendly question received");
        return -2;
      }

      ptr++; /* skip the slash */

      test_no = strtol(ptr, &ptr, 10);

      if(test_no > 10000) {
        *part = test_no % 10000;
        test_no /= 10000;
      }

      sprintf(logbuf, "Found test number %d in path", test_no);
      logmsg(logbuf);
    }
    else {

      logmsg("Did not find test number in PATH");
    }

    return test_no;
  }
  
  logmsg("Got illegal request");
  fprintf(stderr, "Got illegal request\n");
  return -1;
}


static int send_doc(int sock, int doc, int part_no)
{
  int written;
  int count;
  char *buffer;
  char *ptr;
  FILE *stream;

  char filename[256];
  char partbuf[80]="data";

  if(doc < 0) {
    if(-2 == doc)
      /* we got a "friends?" question, reply back that we sure are */
      buffer = docfriends;
    else
      buffer = doc404;
    ptr = NULL;
    stream=NULL;

    count = strlen(buffer);
  }
  else {
    sprintf(filename, TEST_DATA_PATH, doc);

    stream=fopen(filename, "rb");
    if(!stream) {
      logmsg("Couldn't open test file");
      return 0;
    }

    if(0 != part_no) {
      sprintf(partbuf, "data%d", part_no);
    }

    ptr = buffer = spitout(stream, "reply", partbuf, &count);
  }

  do {
    written = send(sock, buffer, count, 0);
    if (written < 0) {
      if(stream)
        fclose(stream);
      return -1;
    }
    count -= written;
    buffer += written;
  } while(count>0);

  if(ptr)
    free(ptr);
  if(stream)
    fclose(stream);

  return 0;
}

int main(int argc, char *argv[])
{
  struct sockaddr_in me;
  int sock, msgsock, flag;
  unsigned short port = DEFAULT_PORT;
  char *logfile = DEFAULT_LOGFILE;
  int part_no;
  
  if(argc>1)
    port = atoi(argv[1]);

  /* FIX: write our pid to a file name */

  logfp = fopen(logfile, "a");
  if (!logfp) {
    perror(logfile);
    exit(1);
  }

  /* FIX: make a more portable signal handler */
  signal(SIGPIPE, sigpipe_handler);
  signal(SIGINT, sigterm_handler);
  signal(SIGTERM, sigterm_handler);

  siginterrupt(SIGPIPE, 1);
  siginterrupt(SIGINT, 1);
  siginterrupt(SIGTERM, 1);

  sock = socket(AF_INET, SOCK_STREAM, 0);
  if (sock < 0) {
    perror("opening stream socket");
    fprintf(logfp, "Error opening socket -- aborting\n");
    fclose(logfp);
    exit(1);
  }

  flag = 1;
  if (setsockopt
      (sock, SOL_SOCKET, SO_REUSEADDR, (const void *) &flag,
       sizeof(int)) < 0) {
    perror("setsockopt(SO_REUSEADDR)");
  }

  me.sin_family = AF_INET;
  me.sin_addr.s_addr = INADDR_ANY;
  me.sin_port = htons(port);
  if (bind(sock, (struct sockaddr *) &me, sizeof me) < 0) {
    perror("binding stream socket");
    fprintf(logfp, "Error binding socket -- aborting\n");
    fclose(logfp);
    exit(1);
  }

  /* start accepting connections */
  listen(sock, 5);

  printf("*** %s listening on port %u ***\n", VERSION, port);

  while (!sigterm) {
    int doc;

    msgsock = accept(sock, NULL, NULL);
    
    if (msgsock == -1) {
      if (sigterm) {
        break;
      }
      /* perror("accept"); */
      continue;
    }
    
    logmsg("New client connected");

    doc = get_request(msgsock, &part_no);
    send_doc(msgsock, doc, part_no);

    close(msgsock);
  }
  
  close(sock);
  fclose(logfp);
  
  return 0;
}

