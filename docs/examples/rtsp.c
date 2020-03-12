/*
 * Copyright (c) 2011 - 2019, Jim Hollinger
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *   * Neither the name of Jim Hollinger nor the names of its contributors
 *     may be used to endorse or promote products derived from this
 *     software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */
/* <DESC>
 * A basic RTSP transfer
 * </DESC>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined (WIN32)
#  include <conio.h>  /* _getch() */
#else
#  include <termios.h>
#  include <unistd.h>

static int _getch(void)
{
  struct termios oldt, newt;
  int ch;
  tcgetattr(STDIN_FILENO, &oldt);
  newt = oldt;
  newt.c_lflag &= ~( ICANON | ECHO);
  tcsetattr(STDIN_FILENO, TCSANOW, &newt);
  ch = getchar();
  tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
  return ch;
}
#endif

#include <curl/curl.h>

#define VERSION_STR  "V1.0"

/* error handling macros */
#define my_curl_easy_setopt(A, B, C)                             \
  res = curl_easy_setopt((A), (B), (C));                         \
  if(res != CURLE_OK)                                            \
    fprintf(stderr, "curl_easy_setopt(%s, %s, %s) failed: %d\n", \
            #A, #B, #C, res);

#define my_curl_easy_perform(A)                                     \
  res = curl_easy_perform(A);                                       \
  if(res != CURLE_OK)                                               \
    fprintf(stderr, "curl_easy_perform(%s) failed: %d\n", #A, res);

/*------------------------------------------------------------------------------
 *
 *
 *    Easy functions
 *
 *
 *----------------------------------------------------------------------------*/

/* send RTSP OPTIONS request */
static void rtsp_options(CURL *curl, const char *uri)
{
  CURLcode res = CURLE_OK;
  printf("\nRTSP: OPTIONS %s\n", uri);
  my_curl_easy_setopt(curl, CURLOPT_RTSP_STREAM_URI, uri);
  my_curl_easy_setopt(curl, CURLOPT_RTSP_REQUEST, (long)CURL_RTSPREQ_OPTIONS);
  my_curl_easy_perform(curl);
}


/* send RTSP DESCRIBE request and write sdp response to a file */
static void rtsp_describe(CURL *curl, const char *uri,
                          const char *sdp_filename)
{
  CURLcode res = CURLE_OK;
  FILE *sdp_fp = fopen(sdp_filename, "wb");
  printf("\nRTSP: DESCRIBE %s\n", uri);
  if(sdp_fp == NULL) {
    fprintf(stderr, "Could not open '%s' for writing\n", sdp_filename);
    sdp_fp = stdout;
  }
  else {
    printf("Writing SDP to '%s'\n", sdp_filename);
  }
  my_curl_easy_setopt(curl, CURLOPT_WRITEDATA, sdp_fp);
  my_curl_easy_setopt(curl, CURLOPT_RTSP_REQUEST, (long)CURL_RTSPREQ_DESCRIBE);
  my_curl_easy_perform(curl);
  my_curl_easy_setopt(curl, CURLOPT_WRITEDATA, stdout);
  if(sdp_fp != stdout) {
    fclose(sdp_fp);
  }
}

/* send RTSP SETUP request */
static void rtsp_setup(CURL *curl, const char *uri, const char *transport)
{
  CURLcode res = CURLE_OK;
  printf("\nRTSP: SETUP %s\n", uri);
  printf("      TRANSPORT %s\n", transport);
  my_curl_easy_setopt(curl, CURLOPT_RTSP_STREAM_URI, uri);
  my_curl_easy_setopt(curl, CURLOPT_RTSP_TRANSPORT, transport);
  my_curl_easy_setopt(curl, CURLOPT_RTSP_REQUEST, (long)CURL_RTSPREQ_SETUP);
  my_curl_easy_perform(curl);
}


/* send RTSP PLAY request */
static void rtsp_play(CURL *curl, const char *uri, const char *range)
{
  CURLcode res = CURLE_OK;
  printf("\nRTSP: PLAY %s\n", uri);
  my_curl_easy_setopt(curl, CURLOPT_RTSP_STREAM_URI, uri);
  // my_curl_easy_setopt(curl, CURLOPT_RANGE, range);
  my_curl_easy_setopt(curl, CURLOPT_RTSP_REQUEST, (long)CURL_RTSPREQ_PLAY);
  my_curl_easy_perform(curl);

  /* switch off using range again */
  my_curl_easy_setopt(curl, CURLOPT_RANGE, NULL);
}


/* send RTSP TEARDOWN request */
static void rtsp_teardown(CURL *curl, const char *uri)
{
  CURLcode res = CURLE_OK;
  printf("\nRTSP: TEARDOWN %s\n", uri);
  my_curl_easy_setopt(curl, CURLOPT_RTSP_REQUEST, (long)CURL_RTSPREQ_TEARDOWN);
  my_curl_easy_perform(curl);
}


/* convert url into an sdp filename */
static void get_sdp_filename(const char *url, char *sdp_filename,
                             size_t namelen)
{
  const char *s = strrchr(url, '/');
  strcpy(sdp_filename, "video.sdp");
  if(s != NULL) {
    s++;
    if(s[0] != '\0') {
      snprintf(sdp_filename, namelen, "%s.sdp", s);
    }
  }
}


/* scan sdp file for media control attribute */
static void get_media_control_attribute(const char *sdp_filename,
                                        char *control)
{
  char s[256];
  FILE *sdp_fp = fopen(sdp_filename, "rb");
  control[0] = '\0';
  if(sdp_fp != NULL) {
    while(fgets(s, sizeof(s)-2, sdp_fp) != NULL) {
      sscanf(s, " a = control:%s", control);
    }
    fclose(sdp_fp);
  }
}

/*------------------------------------------------------------------------------
 *
 *
 *    Multi functions
 *
 *
 *----------------------------------------------------------------------------*/

typedef enum
{
   RTSP_STATE_MIN = -1,
   RTSP_STATE_IDLE,
   RTSP_STATE_IN_OPTIONS,
   RTSP_STATE_IN_DESCRIBE
   RTSP_STATE_IN_SETUP,
   RTSP_STATE_IN_PLAY,
   RTSP_STATE_PLAYING,
   RTSP_STATE_IN_PAUSE,
   RTSP_STATE_PAUSED,
   RTSP_STATE_WAIT_FOR_TERMINATING,
   RTSP_STATE_TERMINATING,
   RTSP_STATE_TERMINATED,
   RTSP_STATE_KEEPALIVE,
   RTSP_STATE_MAX
}
RtspSessionState;

typedef struct
{
  RtspSessionState state;
  CURL*            handle;
  char*            url;
  char             uri[256];
  char*            credentials;
}
RtspSession;

void session_init(RtspSession* session) {
  session->url = NULL;
  session->credentials = NULL;
  session->uri[0] = '\0';
  session->state = RTSP_STATE_MIN;
}

void session_setup(RtspSession* session, CURL* handle) {
  session->handle = handle;
  session->state = RTSP_STATE_IDLE;
}

int session_check_error(RtspSession* session, CURLcode result_code)
{
  long server_response = 0L;
   if (result_code == CURLE_OK)
   {
      curl_easy_getinfo(session->handle, CURLINFO_RESPONSE_CODE, &last_server_response); 
      if ((last_server_response == 0) || 
          ((last_server_response >= 200) && (last_server_response < 300)))
      {
         return 0;
      }
      printf(
         "Session %s: server response %li\n", 
         session->url,
         last_server_response);
   }
   else
   {
      LOG(LOG_ERROR, "Session %s: curl code %li", session->url, result_code);
   }
   return 1;
}

session_next(RtspSession* session, CURLcode result_code) {
   int result = 0;
   CURLcode res = CURLE_OK;
   CURLMcode curlm_result = CURLM_OK;

   if (session->state != RTSP_STATE_PLAYING)
   {
      printf(
         "RtspRtpSession %s: rtsp state = %i\n", 
         session->uri, session->state);
   }

   bool retry_makes_sense = false;

   /*
    * This condition checks skips odd resultcodes (but successfull
    * communication) on the OPTIONS. This helps setting up RTSP sessions over
    * port 80 (Axis fw 5.60+ supports that). In that case the first option
    * response is a 503.
    */
   if ((session->state < RTSP_STATE_TERMINATING) && 
       !((session->state == RTSP_STATE_IN_OPTIONS)) && 
       session_check_error(result_code, retry_makes_sense))
   {
      LOG(LOG_ERROR, "Curl log: %s", m_error_buffer);
      if (retry_makes_sense)
      {
         setErrorAndRetry();
         result = RESULT_SIGNIFICANT_CHANGE;
      }
      else
      {
         LOG(LOG_ERROR,"Session %s: failed. Stop!", session->url);
         result = Teardown() ? RESULT_CAN_REMOVE_ME : RESULT_SIGNIFICANT_CHANGE;
      }
      return result;
   }

   my_curl_easy_setopt(session->handle, CURLOPT_POSTFIELDS, 0); 

   /*
    * Normal state handling. We know that there is no curl error or error
    * server response
    */

   switch (session->state)
   {
      case RTSP_STATE_IDLE:
         /*
          * If idle, do nothing. Need to call start() first
          */
         break;

      case RTSP_STATE_IN_OPTIONS:
         /*
          * Skip parsing OPTIONS. Prepare for DESCRIBE
          */
         // curl_multi_remove_handle(m_multi, session->handle);
         my_curl_easy_setopt(session->handle, CURLOPT_WRITEFUNCTION, (void*)rtsp_describe_callback_s);
         my_curl_easy_setopt(session->handle, CURLOPT_WRITEDATA, (void*)&m_sdp);
         my_curl_easy_setopt(session->handle, CURLOPT_RTSP_REQUEST, (long)CURL_RTSPREQ_DESCRIBE);
         LOG(LOG_INFO,"RTSP: DESCRIBE %s", m_uri.c_str());
         curlm_result = curl_multi_restart_handle(m_multi, session->handle);
         if (curlm_result == CURLM_OK)
         {
            session->state = RTSP_STATE_IN_DESCRIBE;
         }
         else
         {
            LOG(LOG_ERROR,"Session %s: Curl error %u!", session->url, curlm_result);
            Teardown();
         }
         break;

      case RTSP_STATE_IN_DESCRIBE:
         /*
          * DESCRIBE completed. Prepare for SETUP
          */
         // curl_multi_remove_handle(m_multi, session->handle);
         my_curl_easy_setopt(session->handle, CURLOPT_WRITEDATA, 0);
         my_curl_easy_setopt(session->handle, CURLOPT_WRITEFUNCTION, 0);
         if (m_sdp)
         {
            SDP::MediaDefinition* media = m_sdp->FindMedia(m_media_name.c_str());
            if (media != nullptr)
            {
               unsigned int payload_type = media->GetPayloadType();
               bool has_listener = m_listeners.HasSubscriber(payload_type);
               if (!has_listener && (m_create_parser_cb != 0))
               {
                  (*m_create_parser_cb)(m_media_name.c_str());  /* Parser will get the SDP from the session ('this') */
                  has_listener = m_listeners.HasSubscriber(payload_type);
               }

               if (has_listener)
               {
                  HeaderDict::iterator hi = m_rtsp_headers.find("Content-Base");
                  if (hi != m_rtsp_headers.end())
                  {
                     m_play_uri = hi->second;
                  }
                  else
                  {
                     m_play_uri = m_uri;
                  }
                  std::string setup_uri = m_sdp->MediaUrl(m_media_name.c_str());
                  if (setup_uri.compare(0, 5, "rtsp:") == 0)
                  {      
                     m_setup_uri = setup_uri;
                  }
                  else
                  {
                     if ((setup_uri[0] == '/') || (!m_play_uri.empty() && m_play_uri[m_play_uri.size()-1] == '/')) /* can´t use back() */
                     {
                        m_setup_uri = m_play_uri + setup_uri;
                     }
                     else
                     {
                        m_setup_uri = m_play_uri + "/" + setup_uri;
                     }
                  }
                  setupTransport();
                  LOG(LOG_INFO,"RTSP: SETUP %s", m_setup_uri.c_str());
                  LOG(LOG_INFO,"      TRANSPORT %s", m_transport_str.c_str());
                  my_curl_easy_setopt(session->handle, CURLOPT_RTSP_STREAM_URI, m_setup_uri.c_str());
                  my_curl_easy_setopt(session->handle, CURLOPT_RTSP_TRANSPORT, m_transport_str.c_str());
                  my_curl_easy_setopt(session->handle, CURLOPT_RTSP_REQUEST, (long)CURL_RTSPREQ_SETUP);
                  if ((m_transport == StreamSpecification::TRANSPORT_RTSP_TCP) || (m_transport == StreamSpecification::TRANSPORT_RTSP_OVER_HTTP))
                  {
                     my_curl_easy_setopt(session->handle, CURLOPT_HTTPHEADER, blocksize_header_s);
                  }
         m_error_buffer[0] = '\0';
                  curl_multi_restart_handle(m_multi, session->handle);
                  session->state = RTSP_STATE_IN_SETUP;
               }
               else
               {
               LOG(LOG_ERROR,"Session %s: Can't process payloadtype %u. Stop", session->url, payload_type);
               Teardown();
               }
            }
            else
            {
               LOG(LOG_ERROR,"Session %s: No media \"%s\" available. Stop", session->url, m_media_name.c_str());
               Teardown();
            }
         }
         else
         {
            LOG(LOG_ERROR,"Session %s: No SDP. Stop!", session->url);
            Teardown();
         }
         break;
      case RTSP_STATE_IN_SETUP:
         /*
          * SETUP completed. Prepare for PLAY
          * Alternatively if already streaming, simply repeat the play command
          */
         // curl_multi_remove_handle(m_multi, session->handle);
         my_curl_easy_setopt(session->handle, CURLOPT_WRITEDATA, 0);
         my_curl_easy_setopt(session->handle, CURLOPT_WRITEFUNCTION, 0);
         my_curl_easy_setopt(session->handle, CURLOPT_HTTPHEADER, 0);
         if ((m_session_state == STATE_STREAMING) || processTransportResponse())
         {

            LOG(LOG_INFO,"RTSP: PLAY %s", m_uri.c_str());
            my_curl_easy_setopt(session->handle, CURLOPT_RTSP_STREAM_URI, m_play_uri.c_str());
            //    my_curl_easy_setopt(session->handle, CURLOPT_RANGE, range);
            my_curl_easy_setopt(session->handle, CURLOPT_RTSP_REQUEST, (long)CURL_RTSPREQ_PLAY);
         m_error_buffer[0] = '\0';
            curl_multi_restart_handle(m_multi, session->handle);
            session->state = RTSP_STATE_IN_PLAY;
            result |= RESULT_SIGNIFICANT_CHANGE;
            /* Next call is known to succeed (we survived in describe before) */
            SDP::MediaDefinition* media = m_sdp->FindMedia(m_media_name.c_str());
            m_listeners.InitialiseSubscribers(media->GetPayloadType());
         }
         else
         {
            LOG(LOG_ERROR,"RtspRtpSession%s: SETUP was not succesfull!", session->url);
            Teardown();
         }
         break;
      case RTSP_STATE_IN_PLAY:
      case RTSP_STATE_PLAYING:
      case RTSP_STATE_TERMINATING:
         /*
          * One of: 
          *  - RTSP PLAY-command completed. Move forward into state PLAYING
          *  - Got a new RTP Packet. Set up for receiving the next one unless
          */
         /*
          * TODO?: when timeout expired do an options here, with an
          * RTSP_STATE_REFRESH or something like that. The way it is now the
          * options are out of sync with what is happening here
          */
         if (session->state == RTSP_STATE_IN_PLAY)
         {
            setStarted();
            prepareRtpInfo();
            session->state = RTSP_STATE_PLAYING;
            m_keepalive_timer->Start();
         }
         if (session->state == RTSP_STATE_TERMINATING)
         {
            /* 
             *  Fastforward into TERMINATED state. Maybe the server hasn't
             *  received our message, but we're out of here.
             */
            session->state = RTSP_STATE_TERMINATED;
            return next(CURLE_OK);
         }
         /*
          * Even while we're terminating there may still be data coming in, process it
          */
         if (m_transport == StreamSpecification::TRANSPORT_RTSP_TCP)
         {
            // curl_multi_remove_handle(m_multi, session->handle);
            my_curl_easy_setopt(session->handle, CURLOPT_RTSP_REQUEST, (long)CURL_RTSPREQ_RECEIVE); 
         m_error_buffer[0] = '\0';
            curl_multi_restart_handle(m_multi, session->handle);
         }
         break;
      case RTSP_STATE_WAIT_FOR_TERMINATING:
         /*
          * This state we only get in RTP-over-RTSP aka RTP interleaving aka
          * TCP streaming. By waiting for the next packet from the server
          * before initiating the TEARDOWN we can keep the same socket inside
          * libcurl? Since fw 5.60 the Axis camera is sensitive to socket changes,
          * violating a 'SHOULD' in the standard.
          */
         doStop();
         break;
      case RTSP_STATE_IN_PAUSE:
         session->state = RTSP_STATE_PAUSED;
         m_session_state = STATE_PAUSED;
         break;
      case RTSP_STATE_TERMINATED:
         result = handleTerminationCompleted();
         /*
          * From this point on we may be deleted!
          */
         break;
      default:
         LOG(LOG_INFO,"Session %s: Unknown state %i. Stop!", session->url, session->state);
         Teardown();
   }
   return result;
}

void process_sessions(CURLM* multi) {
   int msgs_left = 0;
   int next_result = 0;
   bool relevant_state_change = false;
   while (CURLMsg* msg = curl_multi_info_read(m_multi, &msgs_left))
   {
      if (msg->msg == CURLMSG_DONE)
      {
         RtspRtpSession* session = NULL;
         if (curl_easy_getinfo(msg->easy_handle, CURLINFO_PRIVATE, &session) == CURLE_OK)
         {
            next_result = session_next(session, msg->data.result);
         }
         else
         {
            printf("process_sessions: failed to get session pointer\n");
         }
      }
      else
      {
         /* */
      }
   }
   if ((m_listener != 0) && relevant_state_change)
   {
      (*m_listener)(this, Message::MSG_SESSION_CHANGE);
   }
}

/*------------------------------------------------------------------------------ 
 *
 *
 *    Main program. Choose between easy and multi interface at runtime
 *
 *
 *----------------------------------------------------------------------------*/

int main(int argc, char * const argv[])
{
  RtspSession session;
  session_init(&session);

#if 0
  const char *transport = "RTP/AVP;unicast;client_port=1234-1235";  /* UDP */
#else
  /* TCP */
  const char *transport = "RTP/AVP/TCP;unicast;interleaved=0-1";
#endif
  const char *range = "0.000-";
  int rc = EXIT_SUCCESS;
  char *base_name = NULL;

  int do_multi = 0;

  printf("\nRTSP request %s\n", VERSION_STR);
  printf("    Project web site: "
    "https://github.com/BackupGGCode/rtsprequest\n");
  printf("    Requires curl V7.20 or greater\n\n");

#if defined(_WIN32)
      WSADATA wsaData;
      WSAStartup(MAKEWORD(1,1),&wsaData);
#endif

  /* check command line */
  if(argc < 2) {
    base_name = strrchr(argv[0], '/');
    if(base_name == NULL) {
      base_name = strrchr(argv[0], '\\');
    }
    if(base_name == NULL) {
      base_name = argv[0];
    }
    else {
      base_name++;
    }
    printf("Usage:   %s [-t transport] [-u user:pass] [-m] url\n", base_name);
    printf("         url:          url of video server\n");
    printf("         -u user:pass: (optional) credentials to use\n");
    printf("         -t transport: (optional) specifier for media stream"
    printf("         -m:           (optional) use multi- instead of easy interface"
           " protocol\n");
    printf("         default transport: %s\n", transport);
    printf("Example: %s rtsp://192.168.0.2/media/video1\n\n", base_name);
    rc = EXIT_FAILURE;
  }
  else {
    int arg = 1;
    while (arg < argc) {
      const char *s = argv[arg];
      if (*s == '-')
      {
        if(arg < argc-1) {
          switch (s[1]) {
          case 'u':
            session.credentials = argv[++arg];
            break;
          case 't':
            transport = argv[++arg];
            break;
          case 'm':
            do_multi = 1;
          }
        }
        else {
          printf("Expected more arguments\n");
          rc = EXIT_FAILURE;
        }
      }
      else
      {
        session.url = argv[arg];
      }
      arg++;
    }
    if(session.url == NULL) {
      printf("Need a URL\n");
      rc = EXIT_FAILURE;
    }
  }

  if(rc == EXIT_SUCCESS) {
    char uri[256]session.;
    char sdp_filename[256];
    char control[256];
    CURLcode res;
    get_sdp_filename(session.url, sdp_filename, sizeof(sdp_filename)-1);

    /* initialize curl */
    res = curl_global_init(CURL_GLOBAL_ALL);
    if(res == CURLE_OK) {
      curl_version_info_data *data = curl_version_info(CURLVERSION_NOW);
      CURL *curl;
      fprintf(stderr, "    curl V%s loaded\n", data->version);

      /* initialize this curl session */
      curl = curl_easy_init();
      if(curl != NULL) {
        my_curl_easy_setopt(curl, CURLOPT_VERBOSE, 0L);
        my_curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 1L);
        my_curl_easy_setopt(curl, CURLOPT_HEADERDATA, stdout);
        my_curl_easy_setopt(curl, CURLOPT_URL, session.url);

        if(session.credentials != NULL) {
           printf("Using credentials: %s\n", session.credentials);
           my_curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_DIGEST | CURLAUTH_BASIC);
           my_curl_easy_setopt(curl, CURLOPT_USERPWD, session.credentials);
        }

        /* request server options */
        rtsp_options(curl, session.url);

        if(do_multi == 0) {
          /* EASY */
          /* request session description and write response to sdp file */
          rtsp_describe(curl, session.url, sdp_filename);

          /* get media control attribute from sdp file */
          get_media_control_attribute(sdp_filename, control);

          /* setup media stream */
          if(strncmp(control, "rtsp://", 7)) {
             snprintf(session.uri, sizeof(session.uri)-1, "%s/%s", session.url, control);
          } else {
              strncpy(session.uri, control, sizeof(session.uri)-1);
          }
          rtsp_setup(curl, session.uri, transport);

          /* start playing media stream */
          snprintf(session.uri, sizeof(session.uri)-1, "%s/", session.url);
          rtsp_play(curl, session.uri, range);
          printf("Playing video, press any key to stop ...");
          _getch();
          printf("\n");

          /* teardown session */
          rtsp_teardown(curl, session.uri);
        } else {
          /* MULTI */
          int num_fds = 0;
          CURLM* multi = curl_multi_init();
          CURLMcode code = CURLM_OK;


          for (;;) {

            /*
             * TODO: copy keypress detection from stream_peeker
             */

            code = curl_multi_wait(
                multi,
                &m_socks[0],
                m_socks.size(),
                1000,
                &num_fds
                );
            if (code != CURLM_OK)
            {
              LOG(LOG_WARNING, "curl_multi_wait: %s", curl_multi_strerror(code) );
            }
            int curl_running = 0;
            do
            {
              code = curl_multi_perform(multi, &curl_running);
            }
            while (code == CURLM_CALL_MULTI_PERFORM);

            if (code != CURLM_OK)
            {
              LOG(LOG_WARNING, "curl_multi_perform: %s", curl_multi_strerror(code) );
            }

            process_sessions(multi);
          }

          curl_multi_cleanup(multi);
        }

        /* cleanup */
        curl_easy_cleanup(curl);
        curl = NULL;
      }
      else {
        fprintf(stderr, "curl_easy_init() failed\n");
      }
      curl_global_cleanup();
    }
    else {
      fprintf(stderr, "curl_global_init(%s) failed: %d\n",
              "CURL_GLOBAL_ALL", res);
    }
  }

  return rc;
}
