#!/bin/bash

# Fix CurlDnsException in CurlExceptions.cs
sed -i '' 's/: base(\$"Could not resolve host: {hostname}", hostname, null, command)$/: base($"Could not resolve host: {hostname}", 6, command)/' /Users/jacob/Documents/GitHub/curl-dot-net/dotnet/src/CurlDotNet/Exceptions/CurlExceptions.cs
sed -i '' '/CurlDnsException.*{/,/^    }$/ { /CurlErrorCode = 6;/d; }' /Users/jacob/Documents/GitHub/curl-dot-net/dotnet/src/CurlDotNet/Exceptions/CurlExceptions.cs

# Fix CurlProxyException in CurlExceptions.cs
sed -i '' '/public CurlProxyException(string proxyHost, int proxyPort, string command = null)/,/^        }$/ {
    s/: base(\$"Could not resolve proxy: {proxyHost}:{proxyPort}", proxyHost, proxyPort, command)/: base($"Could not resolve proxy: {proxyHost}:{proxyPort}", 5, command)/
    /CurlErrorCode = 5;/d
}' /Users/jacob/Documents/GitHub/curl-dot-net/dotnet/src/CurlDotNet/Exceptions/CurlExceptions.cs

# Fix CurlNotSupportedException in CurlExceptions.cs
sed -i '' '/public CurlNotSupportedException(string feature, string command = null)/,/^        }$/ {
    s/: base(\$"Feature not supported: {feature}", command)/: base($"Feature not supported: {feature}", 1, command)/
    /CurlErrorCode = 1;/d
}' /Users/jacob/Documents/GitHub/curl-dot-net/dotnet/src/CurlDotNet/Exceptions/CurlExceptions.cs

# Fix exceptions in CurlExceptionTypes.cs
# CurlFtpAcceptTimeoutException - 12
sed -i '' '/public CurlFtpAcceptTimeoutException(string message, string command = null)/,/^        }$/ {
    s/: base(message, command)/: base(message, 12, command)/
    /CurlErrorCode = 12;/d
}' /Users/jacob/Documents/GitHub/curl-dot-net/dotnet/src/CurlDotNet/Exceptions/CurlExceptionTypes.cs

# CurlHttpReturnedErrorException - 22
sed -i '' '/public CurlHttpReturnedErrorException(int statusCode, string statusText, string body, string command = null)/,/^        }$/ {
    s/: base(\$"HTTP error {statusCode}: {statusText}", statusCode, statusText, body, command)/: base($"HTTP error {statusCode}: {statusText}", 22, command)/
    /CurlErrorCode = 22;/d
}' /Users/jacob/Documents/GitHub/curl-dot-net/dotnet/src/CurlDotNet/Exceptions/CurlExceptionTypes.cs

# CurlOperationTimeoutException - 28
sed -i '' '/public CurlOperationTimeoutException(double timeoutSeconds, string command = null)/,/^        }$/ {
    s/: base(\$"Operation timed out after {timeoutSeconds} seconds", command, TimeSpan.FromSeconds(timeoutSeconds))/: base($"Operation timed out after {timeoutSeconds} seconds", 28, command)/
    /CurlErrorCode = 28;/d
}' /Users/jacob/Documents/GitHub/curl-dot-net/dotnet/src/CurlDotNet/Exceptions/CurlExceptionTypes.cs

# CurlSslConnectErrorException - 35
sed -i '' '/public CurlSslConnectErrorException(string message, string command = null)/,/^        }$/ {
    s/: base(\$"SSL connect error: {message}", message, command)/: base($"SSL connect error: {message}", 35, command)/
    /CurlErrorCode = 35;/d
}' /Users/jacob/Documents/GitHub/curl-dot-net/dotnet/src/CurlDotNet/Exceptions/CurlExceptionTypes.cs

# CurlUnknownOptionException - 48
sed -i '' '/public CurlUnknownOptionException(string optionName, string command = null)/,/^        }$/ {
    s/: base(\$"Unknown option: {optionName}", optionName, command)/: base($"Unknown option: {optionName}", 48, command)/
    /CurlErrorCode = 48;/d
}' /Users/jacob/Documents/GitHub/curl-dot-net/dotnet/src/CurlDotNet/Exceptions/CurlExceptionTypes.cs

# CurlOptionSyntaxException - 49
sed -i '' '/public CurlOptionSyntaxException(string option, string command = null)/,/^        }$/ {
    s/: base(\$"Option syntax error: {option}", option, command)/: base($"Option syntax error: {option}", 49, command)/
    /CurlErrorCode = 49;/d
}' /Users/jacob/Documents/GitHub/curl-dot-net/dotnet/src/CurlDotNet/Exceptions/CurlExceptionTypes.cs

# CurlSslEngineNotFoundException - 53
sed -i '' '/public CurlSslEngineNotFoundException(string engine, string command = null)/,/^        }$/ {
    s/: base(\$"SSL engine not found: {engine}", engine, command)/: base($"SSL engine not found: {engine}", 53, command)/
    /CurlErrorCode = 53;/d
}' /Users/jacob/Documents/GitHub/curl-dot-net/dotnet/src/CurlDotNet/Exceptions/CurlExceptionTypes.cs

# CurlSslEngineSetFailedException - 54
sed -i '' '/public CurlSslEngineSetFailedException(string message, string command = null)/,/^        }$/ {
    s/: base(\$"Failed to set SSL engine: {message}", message, command)/: base($"Failed to set SSL engine: {message}", 54, command)/
    /CurlErrorCode = 54;/d
}' /Users/jacob/Documents/GitHub/curl-dot-net/dotnet/src/CurlDotNet/Exceptions/CurlExceptionTypes.cs

# CurlSslCertificateProblemException - 58
sed -i '' '/public CurlSslCertificateProblemException(string certError, string command = null)/,/^        }$/ {
    s/: base(\$"Problem with local certificate: {certError}", certError, command)/: base($"Problem with local certificate: {certError}", 58, command)/
    /CurlErrorCode = 58;/d
}' /Users/jacob/Documents/GitHub/curl-dot-net/dotnet/src/CurlDotNet/Exceptions/CurlExceptionTypes.cs

# CurlSslCipherException - 59
sed -i '' '/public CurlSslCipherException(string cipher, string command = null)/,/^        }$/ {
    s/: base(\$"Could not use SSL cipher: {cipher}", cipher, command)/: base($"Could not use SSL cipher: {cipher}", 59, command)/
    /CurlErrorCode = 59;/d
}' /Users/jacob/Documents/GitHub/curl-dot-net/dotnet/src/CurlDotNet/Exceptions/CurlExceptionTypes.cs

# CurlPeerFailedVerificationException - 60
sed -i '' '/public CurlPeerFailedVerificationException(string message, string command = null)/,/^        }$/ {
    s/: base(\$"Peer certificate verification failed: {message}", message, command)/: base($"Peer certificate verification failed: {message}", 60, command)/
    /CurlErrorCode = 60;/d
}' /Users/jacob/Documents/GitHub/curl-dot-net/dotnet/src/CurlDotNet/Exceptions/CurlExceptionTypes.cs

# CurlUseSslFailedException - 64
sed -i '' '/public CurlUseSslFailedException(string message, string command = null)/,/^        }$/ {
    s/: base(\$"Required SSL level failed: {message}", message, command)/: base($"Required SSL level failed: {message}", 64, command)/
    /CurlErrorCode = 64;/d
}' /Users/jacob/Documents/GitHub/curl-dot-net/dotnet/src/CurlDotNet/Exceptions/CurlExceptionTypes.cs

# CurlLoginDeniedException - 67
sed -i '' '/public CurlLoginDeniedException(string message, string command = null)/,/^        }$/ {
    s/: base(\$"Login denied: {message}", "login", command)/: base($"Login denied: {message}", 67, command)/
    /CurlErrorCode = 67;/d
}' /Users/jacob/Documents/GitHub/curl-dot-net/dotnet/src/CurlDotNet/Exceptions/CurlExceptionTypes.cs

echo "Exception fixes complete!"