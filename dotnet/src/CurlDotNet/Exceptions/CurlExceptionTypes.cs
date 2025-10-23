/***************************************************************************
 * Comprehensive curl exception hierarchy
 *
 * Every curl error code gets its own exception type for precise catching
 * Based on curl's libcurl/include/curl/curl.h error codes
 *
 * By Jacob Mellor
 ***************************************************************************/

using System;
using System.Runtime.Serialization;

namespace CurlDotNet.Exceptions
{
    /// <summary>
    /// CURLE_UNSUPPORTED_PROTOCOL (1) - Unsupported protocol
    /// </summary>
    [Serializable]
    public class CurlUnsupportedProtocolException : CurlException
    {
        public string Protocol { get; }

        public CurlUnsupportedProtocolException(string protocol, string command = null)
            : base($"Unsupported protocol: {protocol}", 1, command)
        {
            Protocol = protocol;
        }
    }

    /// <summary>
    /// CURLE_FAILED_INIT (2) - Failed to initialize
    /// </summary>
    [Serializable]
    public class CurlFailedInitException : CurlException
    {
        public CurlFailedInitException(string message, string command = null)
            : base(message, 2, command) { }
    }

    /// <summary>
    /// CURLE_URL_MALFORMAT (3) - Malformed URL
    /// </summary>
    [Serializable]
    public class CurlMalformedUrlException : CurlException
    {
        public string MalformedUrl { get; }

        public CurlMalformedUrlException(string url, string command = null)
            : base($"Malformed URL: {url}", 3, command)
        {
            MalformedUrl = url;
        }
    }

    /// <summary>
    /// CURLE_NOT_BUILT_IN (4) - Feature not built in
    /// </summary>
    [Serializable]
    public class CurlNotBuiltInException : CurlException
    {
        public string Feature { get; }

        public CurlNotBuiltInException(string feature, string command = null)
            : base($"Feature not available: {feature}", 4, command)
        {
            Feature = feature;
        }
    }

    /// <summary>
    /// CURLE_COULDNT_RESOLVE_PROXY (5) - Couldn't resolve proxy
    /// </summary>
    [Serializable]
    public class CurlCouldntResolveProxyException : CurlException
    {
        public string ProxyHost { get; }

        public CurlCouldntResolveProxyException(string proxyHost, string command = null)
            : base($"Could not resolve proxy: {proxyHost}", 5, command)
        {
            ProxyHost = proxyHost;
        }
    }

    /// <summary>
    /// CURLE_COULDNT_RESOLVE_HOST (6) - Couldn't resolve host
    /// </summary>
    [Serializable]
    public class CurlCouldntResolveHostException : CurlException
    {
        public string Hostname { get; }

        public CurlCouldntResolveHostException(string hostname, string command = null)
            : base($"Could not resolve host: {hostname}", 6, command)
        {
            Hostname = hostname;
        }
    }

    /// <summary>
    /// CURLE_COULDNT_CONNECT (7) - Failed to connect to host
    /// </summary>
    [Serializable]
    public class CurlCouldntConnectException : CurlException
    {
        public string Host { get; }
        public int Port { get; }

        public CurlCouldntConnectException(string host, int port, string command = null)
            : base($"Failed to connect to {host}:{port}", 7, command)
        {
            Host = host;
            Port = port;
        }
    }

    /// <summary>
    /// CURLE_WEIRD_SERVER_REPLY (8) - Weird server reply
    /// </summary>
    [Serializable]
    public class CurlWeirdServerReplyException : CurlException
    {
        public CurlWeirdServerReplyException(string message, string command = null)
            : base(message, 8, command) { }
    }

    /// <summary>
    /// CURLE_REMOTE_ACCESS_DENIED (9) - Access denied to remote resource
    /// </summary>
    [Serializable]
    public class CurlRemoteAccessDeniedException : CurlException
    {
        public string Resource { get; }

        public CurlRemoteAccessDeniedException(string resource, string command = null)
            : base($"Access denied to: {resource}", 9, command)
        {
            Resource = resource;
        }
    }

    /// <summary>
    /// CURLE_FTP_ACCEPT_FAILED (10) - FTP accept failed
    /// </summary>
    [Serializable]
    public class CurlFtpAcceptFailedException : CurlException
    {
        public CurlFtpAcceptFailedException(string message, string command = null)
            : base(message, 10, command) { }
    }

    /// <summary>
    /// CURLE_FTP_WEIRD_PASS_REPLY (11) - FTP weird PASS reply
    /// </summary>
    [Serializable]
    public class CurlFtpWeirdPassReplyException : CurlException
    {
        public CurlFtpWeirdPassReplyException(string message, string command = null)
            : base(message, 11, command) { }
    }

    /// <summary>
    /// CURLE_FTP_ACCEPT_TIMEOUT (12) - FTP accept timeout
    /// </summary>
    [Serializable]
    public class CurlFtpAcceptTimeoutException : CurlTimeoutException
    {
        public CurlFtpAcceptTimeoutException(string message, string command = null)
            : base(message, command)
        {
            CurlErrorCode = 12;
        }
    }

    /// <summary>
    /// CURLE_HTTP_RETURNED_ERROR (22) - HTTP returned error
    /// </summary>
    [Serializable]
    public class CurlHttpReturnedErrorException : CurlHttpException
    {
        public CurlHttpReturnedErrorException(int statusCode, string statusText, string body, string command = null)
            : base($"HTTP error {statusCode}: {statusText}", statusCode, statusText, body, command)
        {
            CurlErrorCode = 22;
        }
    }

    /// <summary>
    /// CURLE_WRITE_ERROR (23) - Write error
    /// </summary>
    [Serializable]
    public class CurlWriteErrorException : CurlException
    {
        public string FilePath { get; }

        public CurlWriteErrorException(string filePath, string message, string command = null)
            : base($"Write error for {filePath}: {message}", 23, command)
        {
            FilePath = filePath;
        }
    }

    /// <summary>
    /// CURLE_UPLOAD_FAILED (25) - Upload failed
    /// </summary>
    [Serializable]
    public class CurlUploadFailedException : CurlException
    {
        public string FileName { get; }

        public CurlUploadFailedException(string fileName, string message, string command = null)
            : base($"Upload failed for {fileName}: {message}", 25, command)
        {
            FileName = fileName;
        }
    }

    /// <summary>
    /// CURLE_READ_ERROR (26) - Read error
    /// </summary>
    [Serializable]
    public class CurlReadErrorException : CurlException
    {
        public string FilePath { get; }

        public CurlReadErrorException(string filePath, string message, string command = null)
            : base($"Read error for {filePath}: {message}", 26, command)
        {
            FilePath = filePath;
        }
    }

    /// <summary>
    /// CURLE_OUT_OF_MEMORY (27) - Out of memory
    /// </summary>
    [Serializable]
    public class CurlOutOfMemoryException : CurlException
    {
        public CurlOutOfMemoryException(string command = null)
            : base("Out of memory", 27, command) { }
    }

    /// <summary>
    /// CURLE_OPERATION_TIMEDOUT (28) - Operation timeout
    /// </summary>
    [Serializable]
    public class CurlOperationTimeoutException : CurlTimeoutException
    {
        public CurlOperationTimeoutException(double timeoutSeconds, string command = null)
            : base($"Operation timed out after {timeoutSeconds} seconds", command, TimeSpan.FromSeconds(timeoutSeconds))
        {
            CurlErrorCode = 28;
        }
    }

    /// <summary>
    /// CURLE_HTTP_POST_ERROR (34) - HTTP POST error
    /// </summary>
    [Serializable]
    public class CurlHttpPostErrorException : CurlException
    {
        public CurlHttpPostErrorException(string message, string command = null)
            : base($"HTTP POST error: {message}", 34, command) { }
    }

    /// <summary>
    /// CURLE_SSL_CONNECT_ERROR (35) - SSL connect error
    /// </summary>
    [Serializable]
    public class CurlSslConnectErrorException : CurlSslException
    {
        public CurlSslConnectErrorException(string message, string command = null)
            : base($"SSL connect error: {message}", message, command)
        {
            CurlErrorCode = 35;
        }
    }

    /// <summary>
    /// CURLE_BAD_DOWNLOAD_RESUME (36) - Bad download resume
    /// </summary>
    [Serializable]
    public class CurlBadDownloadResumeException : CurlException
    {
        public long ResumeOffset { get; }

        public CurlBadDownloadResumeException(long offset, string command = null)
            : base($"Bad download resume at offset {offset}", 36, command)
        {
            ResumeOffset = offset;
        }
    }

    /// <summary>
    /// CURLE_FILE_COULDNT_READ_FILE (37) - Couldn't read file
    /// </summary>
    [Serializable]
    public class CurlFileCouldntReadException : CurlException
    {
        public string FilePath { get; }

        public CurlFileCouldntReadException(string filePath, string command = null)
            : base($"Could not read file: {filePath}", 37, command)
        {
            FilePath = filePath;
        }
    }

    /// <summary>
    /// CURLE_FUNCTION_NOT_FOUND (41) - Function not found
    /// </summary>
    [Serializable]
    public class CurlFunctionNotFoundException : CurlException
    {
        public string FunctionName { get; }

        public CurlFunctionNotFoundException(string functionName, string command = null)
            : base($"Function not found: {functionName}", 41, command)
        {
            FunctionName = functionName;
        }
    }

    /// <summary>
    /// CURLE_ABORTED_BY_CALLBACK (42) - Aborted by callback
    /// </summary>
    [Serializable]
    public class CurlAbortedByCallbackException : CurlException
    {
        public CurlAbortedByCallbackException(string command = null)
            : base("Operation aborted by callback", 42, command) { }
    }

    /// <summary>
    /// CURLE_BAD_FUNCTION_ARGUMENT (43) - Bad function argument
    /// </summary>
    [Serializable]
    public class CurlBadFunctionArgumentException : CurlException
    {
        public string ArgumentName { get; }

        public CurlBadFunctionArgumentException(string argumentName, string command = null)
            : base($"Bad function argument: {argumentName}", 43, command)
        {
            ArgumentName = argumentName;
        }
    }

    /// <summary>
    /// CURLE_INTERFACE_FAILED (45) - Interface failed
    /// </summary>
    [Serializable]
    public class CurlInterfaceFailedException : CurlException
    {
        public string InterfaceName { get; }

        public CurlInterfaceFailedException(string interfaceName, string command = null)
            : base($"Interface failed: {interfaceName}", 45, command)
        {
            InterfaceName = interfaceName;
        }
    }

    /// <summary>
    /// CURLE_TOO_MANY_REDIRECTS (47) - Too many redirects
    /// </summary>
    [Serializable]
    public class CurlTooManyRedirectsException : CurlException
    {
        public int RedirectCount { get; }

        public CurlTooManyRedirectsException(int count, string command = null)
            : base($"Too many redirects: {count}", 47, command)
        {
            RedirectCount = count;
        }
    }

    /// <summary>
    /// CURLE_UNKNOWN_OPTION (48) - Unknown option
    /// </summary>
    [Serializable]
    public class CurlUnknownOptionException : CurlInvalidCommandException
    {
        public string OptionName { get; }

        public CurlUnknownOptionException(string optionName, string command = null)
            : base($"Unknown option: {optionName}", optionName, command)
        {
            OptionName = optionName;
            CurlErrorCode = 48;
        }
    }

    /// <summary>
    /// CURLE_SETOPT_OPTION_SYNTAX (49) - Option syntax error
    /// </summary>
    [Serializable]
    public class CurlOptionSyntaxException : CurlInvalidCommandException
    {
        public CurlOptionSyntaxException(string option, string command = null)
            : base($"Option syntax error: {option}", option, command)
        {
            CurlErrorCode = 49;
        }
    }

    /// <summary>
    /// CURLE_GOT_NOTHING (52) - Got nothing (empty reply)
    /// </summary>
    [Serializable]
    public class CurlGotNothingException : CurlException
    {
        public CurlGotNothingException(string command = null)
            : base("Got nothing (empty reply from server)", 52, command) { }
    }

    /// <summary>
    /// CURLE_SSL_ENGINE_NOTFOUND (53) - SSL engine not found
    /// </summary>
    [Serializable]
    public class CurlSslEngineNotFoundException : CurlSslException
    {
        public CurlSslEngineNotFoundException(string engine, string command = null)
            : base($"SSL engine not found: {engine}", engine, command)
        {
            CurlErrorCode = 53;
        }
    }

    /// <summary>
    /// CURLE_SSL_ENGINE_SETFAILED (54) - Failed setting SSL engine
    /// </summary>
    [Serializable]
    public class CurlSslEngineSetFailedException : CurlSslException
    {
        public CurlSslEngineSetFailedException(string message, string command = null)
            : base($"Failed to set SSL engine: {message}", message, command)
        {
            CurlErrorCode = 54;
        }
    }

    /// <summary>
    /// CURLE_SEND_ERROR (55) - Send error
    /// </summary>
    [Serializable]
    public class CurlSendErrorException : CurlException
    {
        public CurlSendErrorException(string message, string command = null)
            : base($"Send error: {message}", 55, command) { }
    }

    /// <summary>
    /// CURLE_RECV_ERROR (56) - Receive error
    /// </summary>
    [Serializable]
    public class CurlReceiveErrorException : CurlException
    {
        public CurlReceiveErrorException(string message, string command = null)
            : base($"Receive error: {message}", 56, command) { }
    }

    /// <summary>
    /// CURLE_SSL_CERTPROBLEM (58) - Problem with local certificate
    /// </summary>
    [Serializable]
    public class CurlSslCertificateProblemException : CurlSslException
    {
        public CurlSslCertificateProblemException(string certError, string command = null)
            : base($"Problem with local certificate: {certError}", certError, command)
        {
            CurlErrorCode = 58;
        }
    }

    /// <summary>
    /// CURLE_SSL_CIPHER (59) - Couldn't use SSL cipher
    /// </summary>
    [Serializable]
    public class CurlSslCipherException : CurlSslException
    {
        public string CipherName { get; }

        public CurlSslCipherException(string cipher, string command = null)
            : base($"Could not use SSL cipher: {cipher}", cipher, command)
        {
            CipherName = cipher;
            CurlErrorCode = 59;
        }
    }

    /// <summary>
    /// CURLE_PEER_FAILED_VERIFICATION (60) - Peer certificate verification failed
    /// </summary>
    [Serializable]
    public class CurlPeerFailedVerificationException : CurlSslException
    {
        public CurlPeerFailedVerificationException(string message, string command = null)
            : base($"Peer certificate verification failed: {message}", message, command)
        {
            CurlErrorCode = 60;
        }
    }

    /// <summary>
    /// CURLE_BAD_CONTENT_ENCODING (61) - Unrecognized content encoding
    /// </summary>
    [Serializable]
    public class CurlBadContentEncodingException : CurlException
    {
        public string Encoding { get; }

        public CurlBadContentEncodingException(string encoding, string command = null)
            : base($"Bad content encoding: {encoding}", 61, command)
        {
            Encoding = encoding;
        }
    }

    /// <summary>
    /// CURLE_FILESIZE_EXCEEDED (63) - File size exceeded
    /// </summary>
    [Serializable]
    public class CurlFileSizeExceededException : CurlException
    {
        public long MaxSize { get; }
        public long ActualSize { get; }

        public CurlFileSizeExceededException(long maxSize, long actualSize, string command = null)
            : base($"File size {actualSize} exceeded maximum {maxSize}", 63, command)
        {
            MaxSize = maxSize;
            ActualSize = actualSize;
        }
    }

    /// <summary>
    /// CURLE_USE_SSL_FAILED (64) - Required SSL level failed
    /// </summary>
    [Serializable]
    public class CurlUseSslFailedException : CurlSslException
    {
        public CurlUseSslFailedException(string message, string command = null)
            : base($"Required SSL level failed: {message}", message, command)
        {
            CurlErrorCode = 64;
        }
    }

    /// <summary>
    /// CURLE_LOGIN_DENIED (67) - Login denied
    /// </summary>
    [Serializable]
    public class CurlLoginDeniedException : CurlAuthenticationException
    {
        public CurlLoginDeniedException(string message, string command = null)
            : base($"Login denied: {message}", "login", command)
        {
            CurlErrorCode = 67;
        }
    }
}