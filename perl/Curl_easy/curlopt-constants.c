        case 'A':
            if (strEQ(name, "AUTOREFERER")) return CURLOPT_AUTOREFERER;
            break;
        case 'B':
        case 'C':
            if (strEQ(name, "CAINFO")) return CURLOPT_CAINFO;
            if (strEQ(name, "CLOSEFUNCTION")) return CURLOPT_CLOSEFUNCTION;
            if (strEQ(name, "CLOSEPOLICY")) return CURLOPT_CLOSEPOLICY;
            if (strEQ(name, "CONNECTTIMEOUT")) return CURLOPT_CONNECTTIMEOUT;
            if (strEQ(name, "COOKIE")) return CURLOPT_COOKIE;
            if (strEQ(name, "COOKIEFILE")) return CURLOPT_COOKIEFILE;
            if (strEQ(name, "COOKIEJAR")) return CURLOPT_COOKIEJAR;
            if (strEQ(name, "CRLF")) return CURLOPT_CRLF;
            if (strEQ(name, "CUSTOMREQUEST")) return CURLOPT_CUSTOMREQUEST;
            break;
        case 'D':
        case 'E':
            if (strEQ(name, "EGDSOCKET")) return CURLOPT_EGDSOCKET;
            if (strEQ(name, "ERRORBUFFER")) return CURLOPT_ERRORBUFFER;
            break;
        case 'F':
            if (strEQ(name, "FAILONERROR")) return CURLOPT_FAILONERROR;
            if (strEQ(name, "FILE")) return CURLOPT_FILE;
            if (strEQ(name, "FILETIME")) return CURLOPT_FILETIME;
            if (strEQ(name, "FOLLOWLOCATION")) return CURLOPT_FOLLOWLOCATION;
            if (strEQ(name, "FORBID_REUSE")) return CURLOPT_FORBID_REUSE;
            if (strEQ(name, "FRESH_CONNECT")) return CURLOPT_FRESH_CONNECT;
            if (strEQ(name, "FTPAPPEND")) return CURLOPT_FTPAPPEND;
            if (strEQ(name, "FTPASCII")) return CURLOPT_FTPASCII;
            if (strEQ(name, "FTPLISTONLY")) return CURLOPT_FTPLISTONLY;
            if (strEQ(name, "FTPPORT")) return CURLOPT_FTPPORT;
            break;
        case 'G':
        case 'H':
            if (strEQ(name, "HEADER")) return CURLOPT_HEADER;
            if (strEQ(name, "HEADERFUNCTION")) return CURLOPT_HEADERFUNCTION;
            if (strEQ(name, "HTTPGET")) return CURLOPT_HTTPGET;
            if (strEQ(name, "HTTPHEADER")) return CURLOPT_HTTPHEADER;
            if (strEQ(name, "HTTPPOST")) return CURLOPT_HTTPPOST;
            if (strEQ(name, "HTTPPROXYTUNNEL")) return CURLOPT_HTTPPROXYTUNNEL;
            if (strEQ(name, "HTTPREQUEST")) return CURLOPT_HTTPREQUEST;
            break;
        case 'I':
            if (strEQ(name, "INFILE")) return CURLOPT_INFILE;
            if (strEQ(name, "INFILESIZE")) return CURLOPT_INFILESIZE;
            if (strEQ(name, "INTERFACE")) return CURLOPT_INTERFACE;
            break;
        case 'J':
        case 'K':
            if (strEQ(name, "KRB4LEVEL")) return CURLOPT_KRB4LEVEL;
            break;
        case 'L':
            if (strEQ(name, "LOW_SPEED_LIMIT")) return CURLOPT_LOW_SPEED_LIMIT;
            if (strEQ(name, "LOW_SPEED_TIME")) return CURLOPT_LOW_SPEED_TIME;
            break;
        case 'M':
            if (strEQ(name, "MAXCONNECTS")) return CURLOPT_MAXCONNECTS;
            if (strEQ(name, "MAXREDIRS")) return CURLOPT_MAXREDIRS;
            if (strEQ(name, "MUTE")) return CURLOPT_MUTE;
            break;
        case 'N':
            if (strEQ(name, "NETRC")) return CURLOPT_NETRC;
            if (strEQ(name, "NOBODY")) return CURLOPT_NOBODY;
            if (strEQ(name, "NOPROGRESS")) return CURLOPT_NOPROGRESS;
            if (strEQ(name, "NOTHING")) return CURLOPT_NOTHING;
            break;
        case 'O':
        case 'P':
            if (strEQ(name, "PASSWDDATA")) return CURLOPT_PASSWDDATA;
            if (strEQ(name, "PASSWDFUNCTION")) return CURLOPT_PASSWDFUNCTION;
            if (strEQ(name, "PORT")) return CURLOPT_PORT;
            if (strEQ(name, "POST")) return CURLOPT_POST;
            if (strEQ(name, "POSTFIELDS")) return CURLOPT_POSTFIELDS;
            if (strEQ(name, "POSTFIELDSIZE")) return CURLOPT_POSTFIELDSIZE;
            if (strEQ(name, "POSTQUOTE")) return CURLOPT_POSTQUOTE;
            if (strEQ(name, "PROGRESSDATA")) return CURLOPT_PROGRESSDATA;
            if (strEQ(name, "PROGRESSFUNCTION")) return CURLOPT_PROGRESSFUNCTION;
            if (strEQ(name, "PROXY")) return CURLOPT_PROXY;
            if (strEQ(name, "PROXYPORT")) return CURLOPT_PROXYPORT;
            if (strEQ(name, "PROXYUSERPWD")) return CURLOPT_PROXYUSERPWD;
            if (strEQ(name, "PUT")) return CURLOPT_PUT;
            break;
        case 'Q':
            if (strEQ(name, "QUOTE")) return CURLOPT_QUOTE;
            break;
        case 'R':
            if (strEQ(name, "RANDOM_FILE")) return CURLOPT_RANDOM_FILE;
            if (strEQ(name, "RANGE")) return CURLOPT_RANGE;
            if (strEQ(name, "READFUNCTION")) return CURLOPT_READFUNCTION;
            if (strEQ(name, "REFERER")) return CURLOPT_REFERER;
            if (strEQ(name, "RESUME_FROM")) return CURLOPT_RESUME_FROM;
            break;
        case 'S':
            if (strEQ(name, "SSLCERT")) return CURLOPT_SSLCERT;
            if (strEQ(name, "SSLCERTPASSWD")) return CURLOPT_SSLCERTPASSWD;
            if (strEQ(name, "SSLVERSION")) return CURLOPT_SSLVERSION;
            if (strEQ(name, "SSL_CIPHER_LIST")) return CURLOPT_SSL_CIPHER_LIST;
            if (strEQ(name, "SSL_VERIFYHOST")) return CURLOPT_SSL_VERIFYHOST;
            if (strEQ(name, "SSL_VERIFYPEER")) return CURLOPT_SSL_VERIFYPEER;
            if (strEQ(name, "STDERR")) return CURLOPT_STDERR;
            break;
        case 'T':
            if (strEQ(name, "TELNETOPTIONS")) return CURLOPT_TELNETOPTIONS;
            if (strEQ(name, "TIMECONDITION")) return CURLOPT_TIMECONDITION;
            if (strEQ(name, "TIMEOUT")) return CURLOPT_TIMEOUT;
            if (strEQ(name, "TIMEVALUE")) return CURLOPT_TIMEVALUE;
            if (strEQ(name, "TRANSFERTEXT")) return CURLOPT_TRANSFERTEXT;
            break;
        case 'U':
            if (strEQ(name, "UPLOAD")) return CURLOPT_UPLOAD;
            if (strEQ(name, "URL")) return CURLOPT_URL;
            if (strEQ(name, "USERAGENT")) return CURLOPT_USERAGENT;
            if (strEQ(name, "USERPWD")) return CURLOPT_USERPWD;
            break;
        case 'V':
            if (strEQ(name, "VERBOSE")) return CURLOPT_VERBOSE;
            break;
        case 'W':
            if (strEQ(name, "WRITEFUNCTION")) return CURLOPT_WRITEFUNCTION;
            if (strEQ(name, "WRITEHEADER")) return CURLOPT_WRITEHEADER;
            if (strEQ(name, "WRITEINFO")) return CURLOPT_WRITEINFO;
            break;
        case 'X':
        case 'Y':
        case 'Z':
