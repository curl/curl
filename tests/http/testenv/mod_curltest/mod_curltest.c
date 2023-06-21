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
#include <apr_optional.h>
#include <apr_optional_hooks.h>
#include <apr_strings.h>
#include <apr_cstr.h>
#include <apr_time.h>
#include <apr_want.h>

#include <httpd.h>
#include <http_protocol.h>
#include <http_request.h>
#include <http_log.h>

static void curltest_hooks(apr_pool_t *pool);
static int curltest_echo_handler(request_rec *r);
static int curltest_put_handler(request_rec *r);
static int curltest_tweak_handler(request_rec *r);
static int curltest_1_1_required(request_rec *r);

AP_DECLARE_MODULE(curltest) = {
  STANDARD20_MODULE_STUFF,
  NULL, /* func to create per dir config */
  NULL,  /* func to merge per dir config */
  NULL, /* func to create per server config */
  NULL,  /* func to merge per server config */
  NULL,              /* command handlers */
  curltest_hooks,
#if defined(AP_MODULE_FLAG_NONE)
  AP_MODULE_FLAG_ALWAYS_MERGE
#endif
};

static int curltest_post_config(apr_pool_t *p, apr_pool_t *plog,
                                apr_pool_t *ptemp, server_rec *s)
{
  void *data = NULL;
  const char *key = "mod_curltest_init_counter";

  (void)plog;(void)ptemp;

  apr_pool_userdata_get(&data, key, s->process->pool);
  if(!data) {
    /* dry run */
    apr_pool_userdata_set((const void *)1, key,
                          apr_pool_cleanup_null, s->process->pool);
    return APR_SUCCESS;
  }

  /* mess with the overall server here */

  return APR_SUCCESS;
}

static void curltest_hooks(apr_pool_t *pool)
{
  ap_log_perror(APLOG_MARK, APLOG_TRACE1, 0, pool, "installing hooks");

  /* Run once after configuration is set, but before mpm children initialize.
   */
  ap_hook_post_config(curltest_post_config, NULL, NULL, APR_HOOK_MIDDLE);

  /* curl test handlers */
  ap_hook_handler(curltest_echo_handler, NULL, NULL, APR_HOOK_MIDDLE);
  ap_hook_handler(curltest_put_handler, NULL, NULL, APR_HOOK_MIDDLE);
  ap_hook_handler(curltest_tweak_handler, NULL, NULL, APR_HOOK_MIDDLE);
  ap_hook_handler(curltest_1_1_required, NULL, NULL, APR_HOOK_MIDDLE);
}

#define SECS_PER_HOUR      (60*60)
#define SECS_PER_DAY       (24*SECS_PER_HOUR)

static apr_status_t duration_parse(apr_interval_time_t *ptimeout, const char *value,
                                   const char *def_unit)
{
  char *endp;
  apr_int64_t n;

  n = apr_strtoi64(value, &endp, 10);
  if(errno) {
    return errno;
  }
  if(!endp || !*endp) {
    if (!def_unit) def_unit = "s";
  }
  else if(endp == value) {
    return APR_EINVAL;
  }
  else {
    def_unit = endp;
  }

  switch(*def_unit) {
  case 'D':
  case 'd':
    *ptimeout = apr_time_from_sec(n * SECS_PER_DAY);
    break;
  case 's':
  case 'S':
    *ptimeout = (apr_interval_time_t) apr_time_from_sec(n);
    break;
  case 'h':
  case 'H':
    /* Time is in hours */
    *ptimeout = (apr_interval_time_t) apr_time_from_sec(n * SECS_PER_HOUR);
    break;
  case 'm':
  case 'M':
    switch(*(++def_unit)) {
    /* Time is in milliseconds */
    case 's':
    case 'S':
      *ptimeout = (apr_interval_time_t) n * 1000;
      break;
    /* Time is in minutes */
    case 'i':
    case 'I':
      *ptimeout = (apr_interval_time_t) apr_time_from_sec(n * 60);
      break;
    default:
      return APR_EGENERAL;
    }
    break;
  case 'u':
  case 'U':
    switch(*(++def_unit)) {
    /* Time is in microseconds */
    case 's':
    case 'S':
      *ptimeout = (apr_interval_time_t) n;
      break;
    default:
      return APR_EGENERAL;
    }
    break;
  default:
    return APR_EGENERAL;
  }
  return APR_SUCCESS;
}

static int status_from_str(const char *s, apr_status_t *pstatus)
{
  if(!strcmp("timeout", s)) {
    *pstatus = APR_TIMEUP;
    return 1;
  }
  else if(!strcmp("reset", s)) {
    *pstatus = APR_ECONNRESET;
    return 1;
  }
  return 0;
}

static int curltest_echo_handler(request_rec *r)
{
  conn_rec *c = r->connection;
  apr_bucket_brigade *bb;
  apr_bucket *b;
  apr_status_t rv;
  char buffer[8192];
  const char *ct;
  long l;

  if(strcmp(r->handler, "curltest-echo")) {
    return DECLINED;
  }
  if(r->method_number != M_GET && r->method_number != M_POST) {
    return DECLINED;
  }

  ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r, "echo_handler: processing");
  r->status = 200;
  r->clength = -1;
  r->chunked = 1;
  apr_table_unset(r->headers_out, "Content-Length");
  /* Discourage content-encodings */
  apr_table_unset(r->headers_out, "Content-Encoding");
  apr_table_setn(r->subprocess_env, "no-brotli", "1");
  apr_table_setn(r->subprocess_env, "no-gzip", "1");

  ct = apr_table_get(r->headers_in, "content-type");
  ap_set_content_type(r, ct? ct : "application/octet-stream");

  bb = apr_brigade_create(r->pool, c->bucket_alloc);
  /* copy any request body into the response */
  if((rv = ap_setup_client_block(r, REQUEST_CHUNKED_DECHUNK))) goto cleanup;
  if(ap_should_client_block(r)) {
    while(0 < (l = ap_get_client_block(r, &buffer[0], sizeof(buffer)))) {
      ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r,
                    "echo_handler: copying %ld bytes from request body", l);
      rv = apr_brigade_write(bb, NULL, NULL, buffer, l);
      if (APR_SUCCESS != rv) goto cleanup;
      rv = ap_pass_brigade(r->output_filters, bb);
      if (APR_SUCCESS != rv) goto cleanup;
      ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r,
                    "echo_handler: passed %ld bytes from request body", l);
    }
  }
  /* we are done */
  b = apr_bucket_eos_create(c->bucket_alloc);
  APR_BRIGADE_INSERT_TAIL(bb, b);
  ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r, "echo_handler: request read");

  if(r->trailers_in && !apr_is_empty_table(r->trailers_in)) {
    ap_log_rerror(APLOG_MARK, APLOG_TRACE2, 0, r,
                  "echo_handler: seeing incoming trailers");
    apr_table_setn(r->trailers_out, "h2test-trailers-in",
                   apr_itoa(r->pool, 1));
  }

  rv = ap_pass_brigade(r->output_filters, bb);

cleanup:
  if(rv == APR_SUCCESS ||
     r->status != HTTP_OK ||
     c->aborted) {
    ap_log_rerror(APLOG_MARK, APLOG_TRACE1, rv, r, "echo_handler: done");
    return OK;
  }
  else {
    /* no way to know what type of error occurred */
    ap_log_rerror(APLOG_MARK, APLOG_TRACE1, rv, r, "echo_handler failed");
    return AP_FILTER_ERROR;
  }
  return DECLINED;
}

static int curltest_tweak_handler(request_rec *r)
{
  conn_rec *c = r->connection;
  apr_bucket_brigade *bb;
  apr_bucket *b;
  apr_status_t rv;
  char buffer[16*1024];
  int i, chunks = 3, error_bucket = 1;
  size_t chunk_size = sizeof(buffer);
  const char *request_id = "none";
  apr_time_t delay = 0, chunk_delay = 0;
  apr_array_header_t *args = NULL;
  int http_status = 200;
  apr_status_t error = APR_SUCCESS, body_error = APR_SUCCESS;

  if(strcmp(r->handler, "curltest-tweak")) {
    return DECLINED;
  }
  if(r->method_number != M_GET && r->method_number != M_POST) {
    return DECLINED;
  }

  if(r->args) {
    args = apr_cstr_split(r->args, "&", 1, r->pool);
    for(i = 0; i < args->nelts; ++i) {
      char *s, *val, *arg = APR_ARRAY_IDX(args, i, char*);
      s = strchr(arg, '=');
      if(s) {
        *s = '\0';
        val = s + 1;
        if(!strcmp("status", arg)) {
          http_status = (int)apr_atoi64(val);
          if(http_status > 0) {
            continue;
          }
        }
        else if(!strcmp("chunks", arg)) {
          chunks = (int)apr_atoi64(val);
          if(chunks >= 0) {
            continue;
          }
        }
        else if(!strcmp("chunk_size", arg)) {
          chunk_size = (int)apr_atoi64(val);
          if(chunk_size >= 0) {
            if(chunk_size > sizeof(buffer)) {
              ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                            "chunk_size %zu too large", chunk_size);
              ap_die(HTTP_BAD_REQUEST, r);
              return OK;
            }
            continue;
          }
        }
        else if(!strcmp("id", arg)) {
          /* just an id for repeated requests with curl's url globbing */
          request_id = val;
          continue;
        }
        else if(!strcmp("error", arg)) {
          if(status_from_str(val, &error)) {
            continue;
          }
        }
        else if(!strcmp("error_bucket", arg)) {
          error_bucket = (int)apr_atoi64(val);
          if(error_bucket >= 0) {
            continue;
          }
        }
        else if(!strcmp("body_error", arg)) {
          if(status_from_str(val, &body_error)) {
            continue;
          }
        }
        else if(!strcmp("delay", arg)) {
          rv = duration_parse(&delay, val, "s");
          if(APR_SUCCESS == rv) {
            continue;
          }
        }
        else if(!strcmp("chunk_delay", arg)) {
          rv = duration_parse(&chunk_delay, val, "s");
          if(APR_SUCCESS == rv) {
            continue;
          }
        }
      }
      ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "query parameter not "
                    "understood: '%s' in %s",
                    arg, r->args);
      ap_die(HTTP_BAD_REQUEST, r);
      return OK;
    }
  }

  ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r, "error_handler: processing "
                "request, %s", r->args? r->args : "(no args)");
  r->status = http_status;
  r->clength = -1;
  r->chunked = 1;
  apr_table_setn(r->headers_out, "request-id", request_id);
  apr_table_unset(r->headers_out, "Content-Length");
  /* Discourage content-encodings */
  apr_table_unset(r->headers_out, "Content-Encoding");
  apr_table_setn(r->subprocess_env, "no-brotli", "1");
  apr_table_setn(r->subprocess_env, "no-gzip", "1");

  ap_set_content_type(r, "application/octet-stream");
  bb = apr_brigade_create(r->pool, c->bucket_alloc);

  if(delay) {
    apr_sleep(delay);
  }
  if(error != APR_SUCCESS) {
    return ap_map_http_request_error(error, HTTP_BAD_REQUEST);
  }
  /* flush response */
  b = apr_bucket_flush_create(c->bucket_alloc);
  APR_BRIGADE_INSERT_TAIL(bb, b);
  rv = ap_pass_brigade(r->output_filters, bb);
  if (APR_SUCCESS != rv) goto cleanup;

  memset(buffer, 'X', sizeof(buffer));
  for(i = 0; i < chunks; ++i) {
    if(chunk_delay) {
      apr_sleep(chunk_delay);
    }
    rv = apr_brigade_write(bb, NULL, NULL, buffer, chunk_size);
    if(APR_SUCCESS != rv) goto cleanup;
    rv = ap_pass_brigade(r->output_filters, bb);
    if(APR_SUCCESS != rv) goto cleanup;
    ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r,
                  "error_handler: passed %lu bytes as response body",
                  (unsigned long)chunk_size);
    if(body_error != APR_SUCCESS) {
      rv = body_error;
      goto cleanup;
    }
  }
  /* we are done */
  b = apr_bucket_eos_create(c->bucket_alloc);
  APR_BRIGADE_INSERT_TAIL(bb, b);
  rv = ap_pass_brigade(r->output_filters, bb);
  apr_brigade_cleanup(bb);
  ap_log_rerror(APLOG_MARK, APLOG_TRACE1, rv, r,
                "error_handler: response passed");

cleanup:
  ap_log_rerror(APLOG_MARK, APLOG_TRACE1, rv, r,
                "error_handler: request cleanup, r->status=%d, aborted=%d",
                r->status, c->aborted);
  if(rv == APR_SUCCESS) {
    return OK;
  }
  if(error_bucket) {
    http_status = ap_map_http_request_error(rv, HTTP_BAD_REQUEST);
    b = ap_bucket_error_create(http_status, NULL, r->pool, c->bucket_alloc);
    ap_log_rerror(APLOG_MARK, APLOG_TRACE1, rv, r,
                  "error_handler: passing error bucket, status=%d",
                  http_status);
    APR_BRIGADE_INSERT_TAIL(bb, b);
    ap_pass_brigade(r->output_filters, bb);
  }
  return AP_FILTER_ERROR;
}

static int curltest_put_handler(request_rec *r)
{
  conn_rec *c = r->connection;
  apr_bucket_brigade *bb;
  apr_bucket *b;
  apr_status_t rv;
  char buffer[16*1024];
  const char *ct;
  apr_off_t rbody_len = 0;
  const char *request_id = "none";
  apr_time_t chunk_delay = 0;
  apr_array_header_t *args = NULL;
  long l;
  int i;

  if(strcmp(r->handler, "curltest-put")) {
    return DECLINED;
  }
  if(r->method_number != M_PUT) {
    return DECLINED;
  }

  if(r->args) {
    args = apr_cstr_split(r->args, "&", 1, r->pool);
    for(i = 0; i < args->nelts; ++i) {
      char *s, *val, *arg = APR_ARRAY_IDX(args, i, char*);
      s = strchr(arg, '=');
      if(s) {
        *s = '\0';
        val = s + 1;
        if(!strcmp("id", arg)) {
          /* just an id for repeated requests with curl's url globbing */
          request_id = val;
          continue;
        }
        else if(!strcmp("chunk_delay", arg)) {
          rv = duration_parse(&chunk_delay, val, "s");
          if(APR_SUCCESS == rv) {
            continue;
          }
        }
      }
      ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "query parameter not "
                    "understood: '%s' in %s",
                    arg, r->args);
      ap_die(HTTP_BAD_REQUEST, r);
      return OK;
    }
  }

  ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r, "put_handler: processing");
  r->status = 200;
  r->clength = -1;
  r->chunked = 1;
  apr_table_unset(r->headers_out, "Content-Length");
  /* Discourage content-encodings */
  apr_table_unset(r->headers_out, "Content-Encoding");
  apr_table_setn(r->subprocess_env, "no-brotli", "1");
  apr_table_setn(r->subprocess_env, "no-gzip", "1");

  ct = apr_table_get(r->headers_in, "content-type");
  ap_set_content_type(r, ct? ct : "text/plain");

  bb = apr_brigade_create(r->pool, c->bucket_alloc);
  /* copy any request body into the response */
  if((rv = ap_setup_client_block(r, REQUEST_CHUNKED_DECHUNK))) goto cleanup;
  if(ap_should_client_block(r)) {
    while(0 < (l = ap_get_client_block(r, &buffer[0], sizeof(buffer)))) {
      ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r,
                    "put_handler: read %ld bytes from request body", l);
      if(chunk_delay) {
        apr_sleep(chunk_delay);
      }
      rbody_len += l;
    }
  }
  /* we are done */
  rv = apr_brigade_printf(bb, NULL, NULL, "%"APR_OFF_T_FMT, rbody_len);
  if(APR_SUCCESS != rv) goto cleanup;
  b = apr_bucket_eos_create(c->bucket_alloc);
  APR_BRIGADE_INSERT_TAIL(bb, b);
  ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r, "put_handler: request read");

  rv = ap_pass_brigade(r->output_filters, bb);

cleanup:
  if(rv == APR_SUCCESS
     || r->status != HTTP_OK
     || c->aborted) {
    ap_log_rerror(APLOG_MARK, APLOG_TRACE1, rv, r, "put_handler: done");
    return OK;
  }
  else {
    /* no way to know what type of error occurred */
    ap_log_rerror(APLOG_MARK, APLOG_TRACE1, rv, r, "put_handler failed");
    return AP_FILTER_ERROR;
  }
  return DECLINED;
}

static int curltest_1_1_required(request_rec *r)
{
  conn_rec *c = r->connection;
  apr_bucket_brigade *bb;
  apr_bucket *b;
  apr_status_t rv;
  char buffer[16*1024];
  const char *ct;
  const char *request_id = "none";
  apr_time_t chunk_delay = 0;
  apr_array_header_t *args = NULL;
  long l;
  int i;

  if(strcmp(r->handler, "curltest-1_1-required")) {
    return DECLINED;
  }

  if (HTTP_VERSION_MAJOR(r->proto_num) > 1) {
    apr_table_setn(r->notes, "ssl-renegotiate-forbidden", "1");
    ap_die(HTTP_FORBIDDEN, r);
    return OK;
  }

  ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r, "1_1_handler: processing");
  r->status = 200;
  r->clength = -1;
  r->chunked = 1;
  apr_table_unset(r->headers_out, "Content-Length");
  /* Discourage content-encodings */
  apr_table_unset(r->headers_out, "Content-Encoding");
  apr_table_setn(r->subprocess_env, "no-brotli", "1");
  apr_table_setn(r->subprocess_env, "no-gzip", "1");

  ct = apr_table_get(r->headers_in, "content-type");
  ap_set_content_type(r, ct? ct : "text/plain");

  bb = apr_brigade_create(r->pool, c->bucket_alloc);
  /* flush response */
  b = apr_bucket_flush_create(c->bucket_alloc);
  APR_BRIGADE_INSERT_TAIL(bb, b);
  rv = ap_pass_brigade(r->output_filters, bb);
  if (APR_SUCCESS != rv) goto cleanup;

  /* we are done */
  rv = apr_brigade_printf(bb, NULL, NULL, "well done!");
  if(APR_SUCCESS != rv) goto cleanup;
  b = apr_bucket_eos_create(c->bucket_alloc);
  APR_BRIGADE_INSERT_TAIL(bb, b);
  ap_log_rerror(APLOG_MARK, APLOG_TRACE1, 0, r, "1_1_handler: request read");

  rv = ap_pass_brigade(r->output_filters, bb);

cleanup:
  if(rv == APR_SUCCESS
     || r->status != HTTP_OK
     || c->aborted) {
    ap_log_rerror(APLOG_MARK, APLOG_TRACE1, rv, r, "1_1_handler: done");
    return OK;
  }
  else {
    /* no way to know what type of error occurred */
    ap_log_rerror(APLOG_MARK, APLOG_TRACE1, rv, r, "1_1_handler failed");
    return AP_FILTER_ERROR;
  }
  return DECLINED;
}
