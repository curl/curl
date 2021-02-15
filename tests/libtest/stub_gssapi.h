#ifndef HEADER_CURL_GSSAPI_STUBS_H
#define HEADER_CURL_GSSAPI_STUBS_H
/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 2017 - 2020, Daniel Stenberg, <daniel@haxx.se>, et al.
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
 ***************************************************************************/

/* Roughly based on Heimdal's gssapi.h */

#include <stdint.h>
#include <stddef.h>

#define GSS_ERROR(status) (status & 0x80000000)

#define GSS_S_COMPLETE 0
#define GSS_S_FAILURE (0x80000000)
#define GSS_S_CONTINUE_NEEDED (1ul)

#define GSS_C_QOP_DEFAULT 0
#define GSS_C_NO_OID ((gss_OID) 0)
#define GSS_C_NO_NAME ((gss_name_t) 0)
#define GSS_C_NO_BUFFER ((gss_buffer_t) 0)
#define GSS_C_NO_CONTEXT ((gss_ctx_id_t) 0)
#define GSS_C_NO_CREDENTIAL ((gss_cred_id_t) 0)
#define GSS_C_NO_CHANNEL_BINDINGS ((gss_channel_bindings_t) 0)

#define GSS_C_NULL_OID GSS_C_NO_OID

#define GSS_C_EMPTY_BUFFER {0, NULL}

#define GSS_C_AF_INET 2

#define GSS_C_GSS_CODE 1
#define GSS_C_MECH_CODE 2

#define GSS_C_DELEG_FLAG 1
#define GSS_C_MUTUAL_FLAG 2
#define GSS_C_REPLAY_FLAG 4
#define GSS_C_CONF_FLAG 16
#define GSS_C_INTEG_FLAG 32

/*
 * Expiration time of 2^32-1 seconds means infinite lifetime for a
 * credential or security context
 */
#define GSS_C_INDEFINITE 0xfffffffful

#define GSS_C_NT_HOSTBASED_SERVICE NULL

typedef uint32_t OM_uint32;

typedef OM_uint32 gss_qop_t;

typedef struct gss_buffer_desc_struct {
  size_t length;
  void *value;
} gss_buffer_desc, *gss_buffer_t;

struct gss_cred_id_t_desc_struct;
typedef struct gss_cred_id_t_desc_struct *gss_cred_id_t;
typedef const struct gss_cred_id_t_desc_struct *gss_const_cred_id_t;

struct gss_ctx_id_t_desc_struct;
typedef struct gss_ctx_id_t_desc_struct *gss_ctx_id_t;
typedef const struct gss_ctx_id_t_desc_struct *gss_const_ctx_id_t;

struct gss_name_t_desc_struct;
typedef struct gss_name_t_desc_struct *gss_name_t;
typedef const struct gss_name_t_desc_struct *gss_const_name_t;

typedef struct gss_OID_desc_struct {
  OM_uint32 length;
  void      *elements;
} gss_OID_desc, *gss_OID;

typedef struct gss_channel_bindings_struct {
  OM_uint32 initiator_addrtype;
  gss_buffer_desc initiator_address;
  OM_uint32 acceptor_addrtype;
  gss_buffer_desc acceptor_address;
  gss_buffer_desc application_data;
} *gss_channel_bindings_t;

OM_uint32 gss_release_buffer(OM_uint32 * /*minor_status*/,
                             gss_buffer_t /*buffer*/);

OM_uint32 gss_init_sec_context(OM_uint32 * /*minor_status*/,
            gss_const_cred_id_t /*initiator_cred_handle*/,
            gss_ctx_id_t * /*context_handle*/,
            gss_const_name_t /*target_name*/,
            const gss_OID /*mech_type*/,
            OM_uint32 /*req_flags*/,
            OM_uint32 /*time_req*/,
            const gss_channel_bindings_t /*input_chan_bindings*/,
            const gss_buffer_t /*input_token*/,
            gss_OID * /*actual_mech_type*/,
            gss_buffer_t /*output_token*/,
            OM_uint32 * /*ret_flags*/,
            OM_uint32 * /*time_rec*/);

OM_uint32 gss_delete_sec_context(OM_uint32 * /*minor_status*/,
                                 gss_ctx_id_t * /*context_handle*/,
                                 gss_buffer_t /*output_token*/);

OM_uint32 gss_inquire_context(OM_uint32 * /*minor_status*/,
                              gss_const_ctx_id_t /*context_handle*/,
                              gss_name_t * /*src_name*/,
                              gss_name_t * /*targ_name*/,
                              OM_uint32 * /*lifetime_rec*/,
                              gss_OID * /*mech_type*/,
                              OM_uint32 * /*ctx_flags*/,
                              int * /*locally_initiated*/,
                              int * /*open_context*/);

OM_uint32 gss_wrap(OM_uint32 * /*minor_status*/,
                   gss_const_ctx_id_t /*context_handle*/,
                   int /*conf_req_flag*/,
                   gss_qop_t /*qop_req*/,
                   const gss_buffer_t /*input_message_buffer*/,
                   int * /*conf_state*/,
                   gss_buffer_t /*output_message_buffer*/);

OM_uint32 gss_unwrap(OM_uint32 * /*minor_status*/,
                     gss_const_ctx_id_t /*context_handle*/,
                     const gss_buffer_t /*input_message_buffer*/,
                     gss_buffer_t /*output_message_buffer*/,
                     int * /*conf_state*/,
                     gss_qop_t * /*qop_state*/);

OM_uint32 gss_seal(OM_uint32 * /*minor_status*/,
                   gss_ctx_id_t /*context_handle*/,
                   int /*conf_req_flag*/,
                   int /*qop_req*/,
                   gss_buffer_t /*input_message_buffer*/,
                   int * /*conf_state*/,
                   gss_buffer_t /*output_message_buffer*/);

OM_uint32 gss_unseal(OM_uint32 * /*minor_status*/,
                     gss_ctx_id_t /*context_handle*/,
                     gss_buffer_t /*input_message_buffer*/,
                     gss_buffer_t /*output_message_buffer*/,
                     int * /*conf_state*/,
                     int * /*qop_state*/);

OM_uint32 gss_import_name(OM_uint32 * /*minor_status*/,
                          const gss_buffer_t /*input_name_buffer*/,
                          const gss_OID /*input_name_type*/,
                          gss_name_t * /*output_name*/);

OM_uint32 gss_release_name(OM_uint32 * /*minor_status*/,
                           gss_name_t * /*input_name*/);

OM_uint32 gss_display_name(OM_uint32 * /*minor_status*/,
                           gss_const_name_t /*input_name*/,
                           gss_buffer_t /*output_name_buffer*/,
                           gss_OID * /*output_name_type*/);

OM_uint32 gss_display_status(OM_uint32 * /*minor_status*/,
                             OM_uint32 /*status_value*/,
                             int /*status_type*/,
                             const gss_OID /*mech_type*/,
                             OM_uint32 * /*message_context*/,
                             gss_buffer_t /*status_string*/);

#endif /* HEADER_CURL_GSSAPI_STUBS_H */
