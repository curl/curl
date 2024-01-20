<!-- Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al. -->
<!-- SPDX-License-Identifier: curl -->
# PROTOCOLS
curl supports numerous protocols, or put in URL terms: schemes. Your
particular build may not support them all.
## DICT
Lets you lookup words using online dictionaries.
## FILE
Read or write local files. curl does not support accessing file:// URL
remotely, but when running on Microsoft Windows using the native UNC approach
works.
## FTP(S)
curl supports the File Transfer Protocol with a lot of tweaks and levers. With
or without using TLS.
## GOPHER(S)
Retrieve files.
## HTTP(S)
curl supports HTTP with numerous options and variations. It can speak HTTP
version 0.9, 1.0, 1.1, 2 and 3 depending on build options and the correct
command line options.
## IMAP(S)
Using the mail reading protocol, curl can "download" emails for you. With or
without using TLS.
## LDAP(S)
curl can do directory lookups for you, with or without TLS.
## MQTT
curl supports MQTT version 3. Downloading over MQTT equals "subscribe" to a
topic while uploading/posting equals "publish" on a topic. MQTT over TLS is
not supported (yet).
## POP3(S)
Downloading from a pop3 server means getting a mail. With or without using
TLS.
## RTMP(S)
The **Realtime Messaging Protocol** is primarily used to serve streaming media
and curl can download it.
## RTSP
curl supports RTSP 1.0 downloads.
## SCP
curl supports SSH version 2 scp transfers.
## SFTP
curl supports SFTP (draft 5) done over SSH version 2.
## SMB(S)
curl supports SMB version 1 for upload and download.
## SMTP(S)
Uploading contents to an SMTP server means sending an email. With or without
TLS.
## TELNET
Telling curl to fetch a telnet URL starts an interactive session where it
sends what it reads on stdin and outputs what the server sends it.
## TFTP
curl can do TFTP downloads and uploads.
