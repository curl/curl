Long: ssl-session-file
Arg: <file>
Help: File to read SSL session from, or file to write SSL session to
Protocols: TLS
Added: 7.59.0
---
Before SSL handshake, if the specified file contains the available session, then use this session.
When the SSL handshake is complete, this SSL session is written to the specified file.

for example:
    $curl https://www.example.com/ -v --ssl-session-file /tmp/sess.pem

The first time you execute the above command, the SSL session is written to the
file /tmp/sess.pem:
    $cat /tmp/sess.pem
    -----BEGIN SSL SESSION PARAMETERS-----
    MIIEzwIBAQICAwMEAsAvBCB1n7+V5CmvJwZh9ytd2fmvVixK5eB1IKeOb/Ca1RwO
    1gQwxD6MexHeC0eQNj0HTse/Ug3Lx7xUMrjjfWwDHs9nJJtZTaYjDmuI7dcu3AaK
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
    owmhfvqqWS08gu924aQCBAClAwIBEqYVBBNqdHRlc3Q0LnZpdm8uY29tLmNuqoGz
    BIGwx/MVFspvlO2eno639vFTsY1jA2+qR4BWFU1O3bqU/nbOLpR7ah4Aj3Ee5sLX
    1JC1YG5eNn52MvKz57XpaQ+uGdKUZHilBf2xwwoImZLgzXUztilzuHuqLfMqHfoI
    j33RqLBfWqjq911M+Id8anBxZFKNuspvKkO9uGTixJy+4ETjcVn7nJyjhK+Zpx9h
    JKripPkWOxKZWFhvGJslH+coZG95Mfm3qSzPBbaR1Dta5YM=
    -----END SSL SESSION PARAMETERS-----

    $openssl sess_id -in /tmp/sess.pem -text -noout
SSL-Session:
    Protocol  : TLSv1.2
    Cipher    : C02F
    Session-ID: 759FBF95E429AF270661F72B5DD9F9AF562C4AE5E07520A78E6FF09AD51C0ED6
    Session-ID-ctx:
    Master-Key: C43E8C7B11DE0B4790363D074EC7BF520DCBC7BC5432B8E37D6C031ECF67249B594DA6230E6B88EDD72EDC068ADBFC11
    Key-Arg   : None
    Krb5 Principal: None
    PSK identity: None
    PSK identity hint: None
    TLS session ticket:
    0000 - c7 f3 15 16 ca 6f 94 ed-9e 9e 8e b7 f6 f1 53 b1   .....o........S.
    0010 - 8d 63 03 6f aa 47 80 56-15 4d 4e dd ba 94 fe 76   .c.o.G.V.MN....v
    0020 - ce 2e 94 7b 6a 1e 00 8f-71 1e e6 c2 d7 d4 90 b5   ...{j...q.......
    0030 - 60 6e 5e 36 7e 76 32 f2-b3 e7 b5 e9 69 0f ae 19   `n^6~v2.....i...
    0040 - d2 94 64 78 a5 05 fd b1-c3 0a 08 99 92 e0 cd 75   ..dx...........u
    0050 - 33 b6 29 73 b8 7b aa 2d-f3 2a 1d fa 08 8f 7d d1   3.)s.{.-.*....}.
    0060 - a8 b0 5f 5a a8 ea f7 5d-4c f8 87 7c 6a 70 71 64   .._Z...]L..|jpqd
    0070 - 52 8d ba ca 6f 2a 43 bd-b8 64 e2 c4 9c be e0 44   R...o*C..d.....D
    0080 - e3 71 59 fb 9c 9c a3 84-af 99 a7 1f 61 24 aa e2   .qY.........a$..
    0090 - a4 f9 16 3b 12 99 58 58-6f 18 9b 25 1f e7 28 64   ...;..XXo..%..(d
    00a0 - 6f 79 31 f9 b7 a9 2c cf-05 b6 91 d4 3b 5a e5 83   oy1...,.....;Z..

    Start Time: 1515332303
    Timeout   : 300 (sec)
    Verify return code: 18 (self signed certificate)

Obviously, the session file already contains the session ticket

When the curl command is executed for the second time with the --ssl-session-file
option (no --ssl-no-ticket), the session ID and session ticket are taken on in
ClientHello. If the server can decrypt the session ticket will enter the session
reuse handshake process.

