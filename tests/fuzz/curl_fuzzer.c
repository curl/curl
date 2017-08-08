/*
# Copyright 2016 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################
*/

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include <curl/curl.h>

static const void *cur_data;
static int cur_size = -1;
static int server_fd = -1;
static int client_fd = -1;
static int wrote = 0;

static void fail(const char *why) {
  perror(why);
  exit(1);
}

static curl_socket_t open_sock(void *ctx, curlsocktype purpose,
                               struct curl_sockaddr *address) {
  if(cur_size == -1) {
    fail("not fuzzing");
  }
  if(server_fd != -1 || client_fd != -1) {
    fail("already connected");
  }
  int fds[2];
  if(socketpair(AF_UNIX, SOCK_STREAM, 0, fds)) {
    fail("socketpair");
  }
  server_fd = fds[0];
  client_fd = fds[1];
  if(write(server_fd, cur_data, cur_size) != cur_size) {
    fail("write");
  }
  if(shutdown(server_fd, SHUT_WR)) {
    fail("shutdown");
  }
  return client_fd;
}

static int set_opt(void *ctx, curl_socket_t curlfd, curlsocktype purpose) {
  return CURL_SOCKOPT_ALREADY_CONNECTED;
}

static size_t write_callback(char *ptr, size_t size, size_t n, void *ctx) {
  return size * n;
}

static size_t read_callback(char *buf, size_t size, size_t n, void *ctx) {
  if(wrote || size * n == 0) {
    return 0;
  }
  wrote = 1;
  buf[0] = 'a';
  return 1;
}

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  cur_data = Data;
  cur_size = Size;
  wrote = 0;
  CURL *curl = curl_easy_init();
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
  curl_easy_setopt(curl, CURLOPT_READFUNCTION, read_callback);
  curl_easy_setopt(curl, CURLOPT_OPENSOCKETFUNCTION, open_sock);
  curl_easy_setopt(curl, CURLOPT_SOCKOPTFUNCTION, set_opt);
#if defined(FUZZER_FTP)
  curl_easy_setopt(curl, CURLOPT_URL, "ftp://user@localhost/file.txt");
#elif defined(FUZZER_IMAP)
  curl_easy_setopt(curl, CURLOPT_USERNAME, "user");
  curl_easy_setopt(curl, CURLOPT_PASSWORD, "secret");
  curl_easy_setopt(curl, CURLOPT_URL, "imap://localhost");
#elif defined(FUZZER_POP3)
  curl_easy_setopt(curl, CURLOPT_USERNAME, "user");
  curl_easy_setopt(curl, CURLOPT_PASSWORD, "secret");
  curl_easy_setopt(curl, CURLOPT_URL, "pop3://localhost");
#elif defined(FUZZER_HTTP_UPLOAD)
  curl_easy_setopt(curl, CURLOPT_URL, "http://localhost/");
  curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1);
  curl_easy_setopt(curl, CURLOPT_UPLOAD, 1L);
#elif defined(FUZZER_HTTP2)
  curl_easy_setopt(curl, CURLOPT_URL, "http://localhost/");
  /* use non-TLS HTTP/2 without HTTP/1.1 Upgrade: */
  curl_easy_setopt(curl, CURLOPT_HTTP_VERSION,
                   CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE);
#else
  curl_easy_setopt(curl, CURLOPT_URL, "http://localhost/");
  curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1);
#endif
  curl_easy_perform(curl);
  curl_easy_cleanup(curl);
  close(server_fd);
  close(client_fd);
  server_fd = -1;
  client_fd = -1;
  cur_data = NULL;
  cur_size = -1;
  return 0;
}
