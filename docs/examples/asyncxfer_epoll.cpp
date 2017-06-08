/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2012 - 2017, Daniel Stenberg, <daniel@haxx.se>, et al.
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

/* <DESC>
 * demonstrate async xfer model using CURLINFO_XFER_STATE info along with multi socket interface.
 * Request transfer(easy handle) state can be used to return control back(to application once 
 * request is written) and also to enforce timeouts(connect/response) at the request level.
 * </DESC>
 */
/*
 * Written by Pugazhenthi Narayanan.
 * This program is in C++ and uses epoll for event handling.
 *
 * This is an adaptation of libcurl's "hiperfifo.c"(by Jeff Pohlmeyer) and "asiohiper.cpp"(by Lijo Antony)
 * sample programs. This example implements a subset of the functionality from
 * hiperfifo.c, for full functionality refer hiperfifo.c or evhiperfifo.c
 *
 * When running, the program creates an easy handle for a URL and
 * uses the curl_multi API to fetch it.
 *
 * Note:
 *  For the sake of simplicity, URLs are hard coded to "http://httpbin.org/"
 *
 * This is purely a demo app, all retrieved data is simply discarded by the
 * write callback.
 */

#include <sys/time.h>
#include <sys/epoll.h>
#include "curl/curl.h"
#include <map>
using namespace std;
 
 
#define MSG_OUT stdout  

typedef struct _SockInfo
{
	CURL *easy;
	curl_socket_t m_sockfd;
	int m_evset;
} SockInfo;

/* Information associated with a specific easy handle */ 
typedef struct _ConnInfo
{
  CURL *easy;
  char *url;
  bool m_ready;
  //ClientInfo *global;
  struct timeval m_response_timeout;
  char error[CURL_ERROR_SIZE];
} ConnInfo;

typedef struct ClientInfo
{
	CURLM* m_curl_multi;
	int m_epfd;
	int m_still_running;
	long m_connect_timeout_ms, m_response_timeout_ms, m_timeout_ms;
	map<CURL*, ConnInfo*> m_req_handle;
	ClientInfo() : m_curl_multi(NULL) {}
} ClientInfo;

ClientInfo* m_client_info = NULL;

void handle_mcode(CURLMcode _code)
{
    //ignore bad socket
    if(_code == CURLM_BAD_SOCKET)
        return;
    if(_code != CURLM_OK)
        fprintf(MSG_OUT, "CURLM Error : %s \n", curl_multi_strerror(_code));
}

void check_multi_info()
{
    CURLMsg* msg;
    int msgs_left = 0;
    CURL* easy;

    while((msg = curl_multi_info_read(m_client_info->m_curl_multi, &msgs_left)))
    {
        if(msg->msg == CURLMSG_DONE)
        {
			easy = msg->easy_handle;
			m_client_info->m_req_handle[easy]->m_ready = true;
            curl_multi_remove_handle(m_client_info->m_curl_multi, easy);
			curl_easy_cleanup(easy);
            curl_multi_socket_action(m_client_info->m_curl_multi,
                                  CURL_SOCKET_TIMEOUT, 0, &(m_client_info->m_still_running));
        }
    }
}

void handle_event(int _fd, short _kind)
{
    int action = (_kind & EPOLLIN ? CURL_CSELECT_IN : 0) |
                    (_kind & EPOLLOUT ? CURL_CSELECT_OUT : 0);

    CURLMcode rc = curl_multi_socket_action(m_client_info->m_curl_multi, _fd, action, &(m_client_info->m_still_running));
    handle_mcode(rc);

    check_multi_info();

}

void handle_timeout(CURL* _easy)
{
    CURLMcode rc = curl_multi_socket_action(m_client_info->m_curl_multi,
                                  CURL_SOCKET_TIMEOUT, 0, &(m_client_info->m_still_running));
    handle_mcode(rc);
    check_multi_info();
    curl_multi_remove_handle(m_client_info->m_curl_multi, _easy);

    //epoll_ctl(m_client_info.m_epfd, EPOLL_CTL_DEL, m_client_info.m_req_handle[_easy]->m_sock_info->m_sockfd, NULL);
}


void compute_timeout(struct timeval& _tv, long _timeout_ms)
{
    gettimeofday(&_tv, NULL);
    _tv.tv_usec += _timeout_ms * 1000;
    while (_tv.tv_usec >= 1000000)
    {
        _tv.tv_usec -= 1000000;
        _tv.tv_sec++;
    }

}
bool check_timeout(struct timeval& _tv)
{
    struct timeval current_time_tv;
    gettimeofday(&current_time_tv, NULL);
    if(timercmp(&current_time_tv, &_tv, >))
        return true;
    return false;
}

void run()
{
    CURLMcode rc = curl_multi_socket_action(m_client_info->m_curl_multi,
                                  CURL_SOCKET_TIMEOUT, 0, &(m_client_info->m_still_running));
    handle_mcode(rc);
    int num_ev;
    struct epoll_event evs[100];
    if(m_client_info->m_timeout_ms > 10)
        m_client_info->m_timeout_ms = 10;
    if((num_ev = epoll_wait(m_client_info->m_epfd, evs, sizeof(evs) / sizeof(struct epoll_event), m_client_info->m_timeout_ms)) > 0)
        for(int i = 0; i < num_ev; i++)
            handle_event(evs[i].data.fd, evs[i].events);

}
bool send(CURL* _easy)
{
    long state = 0;
    bool timeout = false;

    struct timeval connect_timeout_tv, write_timeout_tv;
    compute_timeout(connect_timeout_tv, m_client_info->m_connect_timeout_ms);
    compute_timeout(write_timeout_tv, 200);

    while(state < CURLXFER_TRANSFER)
    {
        run();
        curl_easy_getinfo(_easy, CURLINFO_XFER_STATE, &state);
        timeout = (state >= CURLXFER_WAITDO) ? check_timeout(write_timeout_tv) : check_timeout(connect_timeout_tv);
        if(timeout)
		{
            fprintf(MSG_OUT, "Timeout State : %d \n", state);
            return false;
		}
    }
    fprintf(MSG_OUT, "State : %d \n", state);
    return true;

}
void read(CURL* _easy)
{
    bool read_complete = false;
    do
    {
        run();
        //libcurl state transition remains in transfer so state cannot be used here.
        read_complete = m_client_info->m_req_handle[_easy]->m_ready;
        if(read_complete)
            break;
        struct timeval current_time_struct;
        gettimeofday(&current_time_struct, NULL);
        if(timercmp(&current_time_struct, &(m_client_info->m_req_handle[_easy]->m_response_timeout), >))
        {
            handle_timeout(_easy);
            break;
        }
    }
    while(read_complete == false);
}

int multi_timer_cb(CURLM* _multi, long _timeout_ms, void* _userp)
{
    ClientInfo* client_info = (ClientInfo*) _userp;
    client_info->m_timeout_ms = _timeout_ms;
    return 0;
}

void set_sock(SockInfo* _fd, curl_socket_t _sock, CURL* _easy, int _act, ClientInfo* _client_info)
{
    int kind = (_act & CURL_POLL_IN ? EPOLLIN : 0) | (_act & CURL_POLL_OUT ? EPOLLOUT : 0) | (_act & CURL_POLL_INOUT ? EPOLLIN | EPOLLOUT : 0);


    _fd->m_sockfd = _sock;
    _fd->easy = _easy;

    struct epoll_event ev;
    ev.data.fd = _sock;
    ev.events = kind;
    if(_fd->m_evset)
        epoll_ctl(_client_info->m_epfd, EPOLL_CTL_MOD, _sock, &ev);
    else
        epoll_ctl(_client_info->m_epfd, EPOLL_CTL_ADD, _sock, &ev);
    _fd->m_evset = 1;
}

int sock_cb(CURL* _easy, curl_socket_t _sock, int _what, void* _userp, void* _sockp)
{
    ClientInfo* client_info = (ClientInfo*) _userp;
    SockInfo *fdp = (SockInfo*) _sockp;


    if (_what == CURL_POLL_REMOVE)
    {
        if(fdp)
        {
            if(fdp->m_evset)
                epoll_ctl(client_info->m_epfd, EPOLL_CTL_DEL, _sock, NULL);
            delete(fdp);
        }
    }
    else
    {
        if (!fdp)
        {
            SockInfo *fdp = new SockInfo();
            set_sock(fdp, _sock, _easy, _what, client_info);
            curl_multi_assign(client_info->m_curl_multi, _sock, fdp);
            //client_info->m_req_handle[_easy]->m_sock_info = fdp;
        }
        else
        {
            set_sock(fdp, _sock, _easy, _what, client_info);
        }
    }
    return 0;
}

/* CURLOPT_WRITEFUNCTION */ 
static size_t write_cb(void *ptr, size_t size, size_t nmemb, void *data)
{
  size_t realsize = size * nmemb;
  ConnInfo *conn = (ConnInfo*) data;
  (void)ptr;
  (void)conn;
  return realsize;
}
 
 
/* CURLOPT_PROGRESSFUNCTION */ 
static int prog_cb (void *p, double dltotal, double dlnow, double ult,
                    double uln)
{
  //ConnInfo *conn = (ConnInfo *)p;
  (void)ult;
  (void)uln;
 
  //fprintf(MSG_OUT, "Progress: %s (%g/%g)\n", conn->url, dlnow, dltotal);
  return 0;
}
/* Create a new easy handle, and add it to the global curl_multi */ 
static ConnInfo* new_conn(char *url, ClientInfo *g )
{
  ConnInfo *conn;
  CURLMcode rc;
 
  conn = (ConnInfo*)calloc(1, sizeof(ConnInfo));
  memset(conn, 0, sizeof(ConnInfo));
  conn->error[0]='\0';
  conn->m_ready = false;
 
  conn->easy = curl_easy_init();
  if (!conn->easy) {
    fprintf(MSG_OUT, "curl_easy_init() failed, exiting!\n");
    exit(2);
  }
  //conn->global = g;
  conn->url = strdup(url);
  curl_easy_setopt(conn->easy, CURLOPT_URL, conn->url);
  curl_easy_setopt(conn->easy, CURLOPT_WRITEFUNCTION, write_cb);
  curl_easy_setopt(conn->easy, CURLOPT_WRITEDATA, &conn);
  curl_easy_setopt(conn->easy, CURLOPT_VERBOSE, 1L);
  curl_easy_setopt(conn->easy, CURLOPT_ERRORBUFFER, conn->error);
  curl_easy_setopt(conn->easy, CURLOPT_PRIVATE, conn);
  curl_easy_setopt(conn->easy, CURLOPT_NOPROGRESS, 0L);
  curl_easy_setopt(conn->easy, CURLOPT_PROGRESSFUNCTION, prog_cb);
  curl_easy_setopt(conn->easy, CURLOPT_PROGRESSDATA, conn);
  rc = curl_multi_add_handle(g->m_curl_multi, conn->easy);
  handle_mcode(rc);
 
  return conn; 
  /* note that the add_handle() will set a time-out to trigger very soon so
     that the necessary socket_action() call will be called by this app */ 
}

void init()
{
	m_client_info = new ClientInfo();
    m_client_info->m_curl_multi = curl_multi_init();
    m_client_info->m_epfd = epoll_create(100);
	m_client_info->m_connect_timeout_ms = 1000;
	m_client_info->m_response_timeout_ms = 1000;

  /* setup the generic multi interface options we want */
    curl_multi_setopt(m_client_info->m_curl_multi, CURLMOPT_SOCKETFUNCTION, sock_cb);
    curl_multi_setopt(m_client_info->m_curl_multi, CURLMOPT_SOCKETDATA, m_client_info);
    curl_multi_setopt(m_client_info->m_curl_multi, CURLMOPT_TIMERFUNCTION, multi_timer_cb);
    curl_multi_setopt(m_client_info->m_curl_multi, CURLMOPT_TIMERDATA, m_client_info);
}

void end()
{
    curl_multi_cleanup(m_client_info->m_curl_multi);
    m_client_info->m_curl_multi = NULL;    
}


int main()
{
	init();
	ConnInfo* conn[3];
    char* url[3]= {"http://httpbin.org/xml", "http://httpbin.org/ip", "http://httpbin.org/headers"};
	for(int i=0; i<sizeof(url)/sizeof(char*); i++)
	{
   		fprintf(MSG_OUT, "Send %s!\n", url[i]);
		conn[i] = new_conn(url[i], m_client_info);
		m_client_info->m_req_handle[conn[i]->easy] = conn[i];
     
		if(send(conn[i]->easy) == false)
		{
            curl_multi_remove_handle(m_client_info->m_curl_multi, conn[i]->easy);        
    		fprintf(MSG_OUT, "Send failed, exiting!\n");
			return 0;
		}
		compute_timeout(conn[i]->m_response_timeout, m_client_info->m_response_timeout_ms);
	}
	read(conn[0]->easy);
}

