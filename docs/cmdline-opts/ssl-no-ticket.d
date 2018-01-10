Long: ssl-no-ticket
Help: Disable curl's use of SSL session-ticket rusing(OpenSSL)
Protocols: TLS
Added: 7.59.0
---
(OpenSSL) This option tells curl to disable SSL session ticket during the ssl
handshake.

for example:
$curl https://www.example.com/ --ssl-session-file /tmp/sess.pem --ssl-no-ticket

The first time you execute the above command, the SSL session is written to the
file /tmp/sess.pem:
$cat /tmp/sess.pem
-----BEGIN SSL SESSION PARAMETERS-----
MIIEGQIBAQICAwMEAsAvBCD+4iV0RHu09roLIO7s4P28Ghz2+c7VeTdWulbeihdH
hgQwxD6MexHeC0eQNj0HTse/Ug3Lx7xUMrjjfWwDHs9nJJtZTaYjDmuI7dcu3AaK
2/wRoQYCBFpSIs+iBAICASyjggOIMIIDhDCCAmwCCQCqc+VUkZSK0zANBgkqhkiG
9w0BAQUFADCBgzELMAkGA1UEBhMCY24xEjAQBgNVBAgMCWd1YW5nZG9uZzERMA8G
A1UEBwwIc2hlbnpoZW4xDTALBgNVBAoMBHZpdm8xDTALBgNVBAsMBHZpdm8xFjAU
BgNVBAMMDSoudml2by5jb20uY24xFzAVBgkqhkiG9w0BCQEWCHZpdm8uY29tMB4X
DTE3MTIxNTEwMzgzMFoXDTE4MTIxNTEwMzgzMFowgYMxCzAJBgNVBAYTAmNuMRIw
EAYDVQQIDAlndWFuZ2RvbmcxETAPBgNVBAcMCHNoZW56aGVuMQ0wCwYDVQQKDAR2
aXZvMQ0wCwYDVQQLDAR2aXZvMRYwFAYDVQQDDA0qLnZpdm8uY29tLmNuMRcwFQYJ
KoZIhvcNAQkBFgh2aXZvLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC
ggEBAMSFQ6uXaaaeNiil80dYXugSVurILCLrBry+k1XWArqLyeMsrVOh7AmJs76+
Mk52bmqWMFvXLr7Vg4DqOPj0ZTsSZOwU9D3TJzkNVoq3lL2F9HOs/rq+xPyDJ2Pb
QwdyiEWdDSdPjVVClFIJWEeu2neYF3PO7xcDCtsRq/fPJ0yxZsqHXHyjAkLGLcsf
4PjC+gpWS9AhNUzQKeduKVa+izafu8YjCkuWUsoe8Wt61I5+d+7RvHkmABPlrbw2
OBG3J8SImPgOp5GthOuHpTjNUqm5GCoWTwc7IthZhOZZxWFyZPsQCe4L+yKhXu6P
SfWiFPuio+KyYz1UVgqVqt7UeXMCAwEAATANBgkqhkiG9w0BAQUFAAOCAQEAmX+3
gmsXgemuHt6emAOnBugm4SQuCWtfqaw90kvUKT5LWKOmARrs2vs/m0oQAXJ3wT4E
6Vz0GrN61TlG+D8BT1aDMUeeSoNpQFBPNKPhC4vSUGrrwZAjfioWEUt28MwSv1GY
N964wrL2yIuzo4e3isbLnznDn0b8Z3JLm0/YO4WPXcXQ6uujrxDf2/cYX5mtoznF
k+jKTnzRzy9kt+NL9TRLZ7+ewOYnSSPup0SGIlbgmNXr41uOveboRVx53Fri+Ouh
XgrS+hBQTVE7IGnPjoeIrXqMxEoW/q42Vnc1LGWWUE13tYl3wHfV+F6V1TngBlrQ
owmhfvqqWS08gu924aQCBAClAwIBEqYVBBNqdHRlc3Q0LnZpdm8uY29tLmNu
-----END SSL SESSION PARAMETERS-----

$openssl sess_id -in /tmp/sess.pem -text -noout
SSL-Session:
    Protocol  : TLSv1.2
    Cipher    : C02F
    Session-ID: FEE22574447BB4F6BA0B20EEECE0FDBC1A1CF6F9CED5793756BA56DE8A174786
    Session-ID-ctx:
    Master-Key: C43E8C7B11DE0B4790363D074EC7BF520DCBC7BC5432B8E37D6C031ECF67249B
                594DA6230E6B88EDD72EDC068ADBFC11
    Key-Arg   : None
    Krb5 Principal: None
    PSK identity: None
    PSK identity hint: None
    Start Time: 1515332303
    Timeout   : 300 (sec)
    Verify return code: 18 (self signed certificate)

Obviously, there is no session ticket in the session file.

When the second time the curl command is called with "--ssl-session-file"
option, the session ID will be carried in ClientHello during the SSL handshake,
and if the server caches this session, it will enter the handshake process of
session reuse.

