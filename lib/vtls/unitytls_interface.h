#ifndef HEADER_CURL_UNITYTLS_INTERFACE_H
#define HEADER_CURL_UNITYTLS_INTERFACE_H

#include <stdint.h>

typedef int8_t      SInt8;
typedef int16_t     SInt16;
typedef int32_t     SInt32;
typedef int64_t     SInt64;

typedef uint8_t     UInt8;
typedef uint16_t    UInt16;
typedef uint32_t    UInt32;
typedef uint64_t    UInt64;

/* ------------------------------------ */

#define UNITYTLS_DECLARE_OBJECT(name)     \
    struct name;                          \
    typedef struct name name;             \
    typedef struct                        \
    {                                     \
        UInt64 handle;                    \
    } name##_ref


/* ------------------------------------ */
/* Error Handling */
/* ------------------------------------ */

typedef enum
{
    UNITYTLS_SUCCESS = 0,
    UNITYTLS_INVALID_ARGUMENT,      /* One of the arguments has an invalid value (e.g. null where not allowed) */
    UNITYTLS_INVALID_FORMAT,        /* The passed data does not have a valid format. */
    UNITYTLS_INVALID_PASSWORD,      /* Invalid password */
    UNITYTLS_INVALID_STATE,         /* The object operating being operated on is not in a state that allows this function call. */
    UNITYTLS_BUFFER_OVERFLOW,       /* A passed buffer was not large enough. */
    UNITYTLS_OUT_OF_MEMORY,         /* Out of memory error */
    UNITYTLS_INTERNAL_ERROR,        /* Internal implementation error. */
    UNITYTLS_NOT_SUPPORTED,         /* The requested action is not supported on the current platform/implementation. */
    UNITYTLS_ENTROPY_SOURCE_FAILED, /* Failed to generate requested amount of entropy data. */
    UNITYTLS_STREAM_CLOSED,         /* The operation is not possible because the stream between the peers was closed. */

    UNITYTLS_USER_CUSTOM_ERROR_START    = 0x100000,
    UNITYTLS_USER_WOULD_BLOCK,      /* Can be set by the user to signal that a call (e.g. read/write callback) would block and needs to be called again. */
                                    /* Some implementations may set this if not all bytes have been read/written. */
    UNITYTLS_USER_READ_FAILED,      /* Can be set by the user to indicate a failed read operation. */
    UNITYTLS_USER_WRITE_FAILED,     /* Can be set by the user to indicate a failed write operation. */
    UNITYTLS_USER_UNKNOWN_ERROR,    /* Can be set by the user to indicate a generic error. */
    UNITYTLS_USER_CUSTOM_ERROR_END      = 0x200000,
} unitytls_error_code_t;
typedef UInt32 unitytls_error_code;


typedef struct
{
    UInt32              magic;
    unitytls_error_code code;
    UInt64              reserved;   /* Implementation specific error code/handle. */
} unitytls_errorstate;

/* ------------------------------------ */
/* Public Key */
/* ------------------------------------ */
UNITYTLS_DECLARE_OBJECT(unitytls_pubkey);


/* ------------------------------------ */
/* Private Key */
/* ------------------------------------ */
typedef enum
{
    UNITYTLS_KEY_TYPE_INVALID,
    UNITYTLS_KEY_TYPE_RSA,
    UNITYTLS_KEY_TYPE_EC,
} unitytls_key_type_t;
typedef UInt32 unitytls_key_type;

UNITYTLS_DECLARE_OBJECT(unitytls_key);

/* ------------------------------------ */
/* X.509 Certificate */
/* ------------------------------------ */
UNITYTLS_DECLARE_OBJECT(unitytls_x509);

/* ------------------------------------ */
/* X.509 Certificate List */
/* ------------------------------------ */
UNITYTLS_DECLARE_OBJECT(unitytls_x509list);

/* ------------------------------------ */
/* X.509 Certificate Verification */
/* ------------------------------------ */
typedef enum
{
    UNITYTLS_X509VERIFY_SUCCESS            = 0x00000000,
    UNITYTLS_X509VERIFY_NOT_DONE           = 0x80000000,
    UNITYTLS_X509VERIFY_FATAL_ERROR        = 0xFFFFFFFF,

    UNITYTLS_X509VERIFY_FLAG_EXPIRED       = 0x00000001,
    UNITYTLS_X509VERIFY_FLAG_REVOKED       = 0x00000002, /* requires CRL backend */
    UNITYTLS_X509VERIFY_FLAG_CN_MISMATCH   = 0x00000004,
    UNITYTLS_X509VERIFY_FLAG_NOT_TRUSTED   = 0x00000008,

    UNITYTLS_X509VERIFY_FLAG_USER_ERROR1   = 0x00010000,
    UNITYTLS_X509VERIFY_FLAG_USER_ERROR2   = 0x00020000,
    UNITYTLS_X509VERIFY_FLAG_USER_ERROR3   = 0x00040000,
    UNITYTLS_X509VERIFY_FLAG_USER_ERROR4   = 0x00080000,
    UNITYTLS_X509VERIFY_FLAG_USER_ERROR5   = 0x00100000,
    UNITYTLS_X509VERIFY_FLAG_USER_ERROR6   = 0x00200000,
    UNITYTLS_X509VERIFY_FLAG_USER_ERROR7   = 0x00400000,
    UNITYTLS_X509VERIFY_FLAG_USER_ERROR8   = 0x00800000,

    UNITYTLS_X509VERIFY_FLAG_UNKNOWN_ERROR = 0x08000000,
} unitytls_x509verify_result_t;
typedef UInt32 unitytls_x509verify_result;

typedef unitytls_x509verify_result (*unitytls_x509verify_callback)(void* userData, unitytls_x509_ref cert, unitytls_x509verify_result result, unitytls_errorstate* errorState);

/* ------------------------------------ */
/* TLS Context */
/* ------------------------------------ */
UNITYTLS_DECLARE_OBJECT(unitytls_tlsctx);

typedef struct unitytls_x509name unitytls_x509name;

typedef UInt32 unitytls_ciphersuite;

typedef enum
{
    UNITYTLS_PROTOCOL_TLS_1_0,
    UNITYTLS_PROTOCOL_TLS_1_1,
    UNITYTLS_PROTOCOL_TLS_1_2,

    UNITYTLS_PROTOCOL_INVALID,
} unitytls_protocol_t;
typedef UInt32 unitytls_protocol;

typedef struct
{
    unitytls_protocol min;
    unitytls_protocol max;
} unitytls_tlsctx_protocolrange;
extern const unitytls_tlsctx_protocolrange UNITYTLS_TLSCTX_PROTOCOLRANGE_DEFAULT;

typedef enum
{
    UNITYTLS_HANDSHAKESTATE_BEGIN,                   /* Called right before a handshake is performed. */
    UNITYTLS_HANDSHAKESTATE_DONE,                    /* Called after a handshake was successfully performed. */

    /* TODO: Need to figure out what values to use here */
    UNITYTLS_HANDSHAKESTATE_COUNT
} unitytls_tlsctx_handshakestate_t;
typedef UInt32 unitytls_tlsctx_handshakestate;

/* Called when unitytls wants to output data. Should return the number of bytes it sent or set an error on errorState. */
typedef size_t (*unitytls_tlsctx_write_callback)(void* userData, const UInt8* data, size_t bufferLen, unitytls_errorstate* errorState);
/* Called when unitytls expects incoming data. Should return the number of bytes it received or set an error on errorState. */
typedef size_t (*unitytls_tlsctx_read_callback)(void* userData, UInt8* buffer, size_t bufferLen, unitytls_errorstate* errorState);
/* Called with human readable string to trace the handshake process */
typedef void   (*unitytls_tlsctx_trace_callback)(void* userData, unitytls_tlsctx* ctx, const char* traceMessage, size_t traceMessageLen);
/* Called during a handshake operation, check currentState to determine how to react. */
typedef void   (*unitytls_tlsctx_handshake_callback)(void* userData, unitytls_tlsctx* ctx, unitytls_tlsctx_handshakestate currentState, unitytls_errorstate* errorState);
/* Called during a handshake operation. Client: if server issues a certificate request (client auth), Server: certificate SNI selection. */
typedef void   (*unitytls_tlsctx_certificate_callback)(void* userData, unitytls_tlsctx* ctx, const char* cn, size_t cnLen, unitytls_x509name* caList, size_t caListLen, unitytls_x509list_ref* chain, unitytls_key_ref* key, unitytls_errorstate* errorState);
/* Called during a handshake operation. A raised error state or any failed verification result will abort the handshake process. */
typedef unitytls_x509verify_result (*unitytls_tlsctx_x509verify_callback)(void* userData, unitytls_x509list_ref chain, unitytls_errorstate* errorState);

typedef struct
{
    unitytls_tlsctx_read_callback   read;
    unitytls_tlsctx_write_callback  write;
    void*                           data;
} unitytls_tlsctx_callbacks;


/* ------------------------------------ */
/* Interface struct */
/* ------------------------------------ */

typedef unitytls_errorstate         (*unitytls_errorstate_create_t)();
typedef void                        (*unitytls_errorstate_raise_error_t)(unitytls_errorstate* errorState, unitytls_error_code errorCode);

typedef unitytls_key_ref            (*unitytls_key_get_ref_t)(const unitytls_key* key, unitytls_errorstate* errorState);
typedef unitytls_key*               (*unitytls_key_parse_der_t)(const UInt8* buffer, size_t bufferLen, const char* password, size_t passwordLen, unitytls_errorstate* errorState);
typedef unitytls_key*               (*unitytls_key_parse_pem_t)(const char* buffer, size_t bufferLen, const char* password, size_t passwordLen, unitytls_errorstate* errorState);
typedef void                        (*unitytls_key_free_t)(unitytls_key* key);

typedef size_t                      (*unitytls_x509_export_der_t)(unitytls_x509_ref cert, UInt8* buffer, size_t bufferLen, unitytls_errorstate* errorState);

typedef unitytls_x509list_ref       (*unitytls_x509list_get_ref_t)(const unitytls_x509list* list, unitytls_errorstate* errorState);
typedef unitytls_x509_ref           (*unitytls_x509list_get_x509_t)(unitytls_x509list_ref list, size_t index, unitytls_errorstate* errorState);
typedef unitytls_x509list*          (*unitytls_x509list_create_t)(unitytls_errorstate* errorState);
typedef void                        (*unitytls_x509list_append_t)(unitytls_x509list* list, unitytls_x509_ref cert, unitytls_errorstate* errorState);
typedef void                        (*unitytls_x509list_append_der_t)(unitytls_x509list* list, const UInt8* buffer, size_t bufferLen, unitytls_errorstate* errorState);
typedef size_t                      (*unitytls_x509list_append_pem_t)(unitytls_x509list* list, const char* buffer, size_t bufferLen, unitytls_errorstate* errorState);
typedef void                        (*unitytls_x509list_free_t)(unitytls_x509list* list);

typedef unitytls_x509verify_result  (*unitytls_x509verify_default_ca_t)(unitytls_x509list_ref chain, const char* cn, size_t cnLen, unitytls_x509verify_callback cb, void* userData, unitytls_errorstate* errorState);
typedef unitytls_x509verify_result  (*unitytls_x509verify_explicit_ca_t)(unitytls_x509list_ref chain, unitytls_x509list_ref trustCA, const char* cn, size_t cnLen, unitytls_x509verify_callback cb, void* userData, unitytls_errorstate* errorState);

typedef unitytls_tlsctx*            (*unitytls_tlsctx_create_server_t)(unitytls_tlsctx_protocolrange supportedProtocols, unitytls_tlsctx_callbacks callbacks, unitytls_x509list_ref certChain, unitytls_key_ref leafCertificateKey, unitytls_errorstate* errorState);
typedef unitytls_tlsctx*            (*unitytls_tlsctx_create_client_t)(unitytls_tlsctx_protocolrange supportedProtocols, unitytls_tlsctx_callbacks callbacks, const char* cn, size_t cnLen, unitytls_errorstate* errorState);
typedef void                        (*unitytls_tlsctx_server_require_client_authentication_t)(unitytls_tlsctx* ctx, unitytls_x509list_ref clientAuthCAList, unitytls_errorstate* errorState);
typedef void                        (*unitytls_tlsctx_set_certificate_callback_t)(unitytls_tlsctx* ctx, unitytls_tlsctx_certificate_callback cb, void* userData, unitytls_errorstate* errorState);
typedef void                        (*unitytls_tlsctx_set_trace_callback_t)(unitytls_tlsctx* ctx, unitytls_tlsctx_trace_callback cb, void* userData, unitytls_errorstate* errorState);
typedef void                        (*unitytls_tlsctx_set_x509verify_callback_t)(unitytls_tlsctx* ctx, unitytls_tlsctx_x509verify_callback cb, void* userData, unitytls_errorstate* errorState);
typedef void                        (*unitytls_tlsctx_set_supported_ciphersuites_t)(unitytls_tlsctx* ctx, unitytls_ciphersuite* supportedCiphersuites, size_t supportedCiphersuitesLen, unitytls_errorstate* errorState);
typedef unitytls_ciphersuite        (*unitytls_tlsctx_get_ciphersuite_t)(unitytls_tlsctx* ctx, unitytls_errorstate* errorState);
typedef unitytls_protocol           (*unitytls_tlsctx_get_protocol_t)(unitytls_tlsctx* ctx, unitytls_errorstate* errorState);
typedef unitytls_x509verify_result  (*unitytls_tlsctx_process_handshake_t)(unitytls_tlsctx* ctx, unitytls_errorstate* errorState);
typedef size_t                      (*unitytls_tlsctx_read_t)(unitytls_tlsctx* ctx, UInt8* buffer, size_t bufferLen, unitytls_errorstate* errorState);
typedef size_t                      (*unitytls_tlsctx_write_t)(unitytls_tlsctx* ctx, const UInt8* data, size_t bufferLen, unitytls_errorstate* errorState);
typedef void                        (*unitytls_tlsctx_notify_close_t)(unitytls_tlsctx* ctx, unitytls_errorstate* errorState);
typedef void                        (*unitytls_tlsctx_free_t)(unitytls_tlsctx* ctx);

typedef void                        (*unitytls_tlsctx_set_certificate_callback_t)(unitytls_tlsctx* ctx, unitytls_tlsctx_certificate_callback cb, void* userData, unitytls_errorstate* errorState);

typedef void                        (*unitytls_random_generate_bytes_t)(UInt8* buffer, size_t bufferLen, unitytls_errorstate* errorState);

/* Interface struct used to integrate UnityTLS into external libraries. */
/* See InterfaceStruct.cpp in UnityTLS. */
typedef struct unitytls_interface_struct
{
    UInt64 INVALID_HANDLE;
    unitytls_tlsctx_protocolrange UNITYTLS_TLSCTX_PROTOCOLRANGE_DEFAULT;

    unitytls_errorstate_create_t unitytls_errorstate_create;
    unitytls_errorstate_raise_error_t unitytls_errorstate_raise_error;

    unitytls_key_get_ref_t unitytls_key_get_ref;
    unitytls_key_parse_der_t unitytls_key_parse_der;
    unitytls_key_parse_pem_t unitytls_key_parse_pem;
    unitytls_key_free_t unitytls_key_free;

    unitytls_x509_export_der_t unitytls_x509_export_der;

    unitytls_x509list_get_ref_t unitytls_x509list_get_ref;
    unitytls_x509list_get_x509_t unitytls_x509list_get_x509;
    unitytls_x509list_create_t unitytls_x509list_create;
    unitytls_x509list_append_t unitytls_x509list_append;
    unitytls_x509list_append_der_t unitytls_x509list_append_der;
    unitytls_x509list_append_pem_t unitytls_x509list_append_pem;
    unitytls_x509list_free_t unitytls_x509list_free;

    unitytls_x509verify_default_ca_t unitytls_x509verify_default_ca;
    unitytls_x509verify_explicit_ca_t unitytls_x509verify_explicit_ca;

    unitytls_tlsctx_create_server_t unitytls_tlsctx_create_server;
    unitytls_tlsctx_create_client_t unitytls_tlsctx_create_client;
    unitytls_tlsctx_server_require_client_authentication_t unitytls_tlsctx_server_require_client_authentication;
    unitytls_tlsctx_set_certificate_callback_t unitytls_tlsctx_set_certificate_callback;
    unitytls_tlsctx_set_trace_callback_t unitytls_tlsctx_set_trace_callback;
    unitytls_tlsctx_set_x509verify_callback_t unitytls_tlsctx_set_x509verify_callback;
    unitytls_tlsctx_set_supported_ciphersuites_t unitytls_tlsctx_set_supported_ciphersuites;
    unitytls_tlsctx_get_ciphersuite_t unitytls_tlsctx_get_ciphersuite;
    unitytls_tlsctx_get_protocol_t unitytls_tlsctx_get_protocol;
    unitytls_tlsctx_process_handshake_t unitytls_tlsctx_process_handshake;
    unitytls_tlsctx_read_t unitytls_tlsctx_read;
    unitytls_tlsctx_write_t unitytls_tlsctx_write;
    unitytls_tlsctx_notify_close_t unitytls_tlsctx_notify_close;
    unitytls_tlsctx_free_t unitytls_tlsctx_free;

    unitytls_random_generate_bytes_t unitytls_random_generate_bytes;
} unitytls_interface_struct;


#endif /* HEADER_CURL_UNITYTLS_INTERFACE_H*/
