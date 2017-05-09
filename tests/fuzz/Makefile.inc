FUZZPROGS = http11 ftp imap pop3 httpupload http2

http11_SOURCES = curl_fuzzer.c
http11_CPPFLAGS = $(AM_CPPFLAGS)

ftp_SOURCES = curl_fuzzer.c
ftp_CPPFLAGS = -DFUZZER_FTP $(AM_CPPFLAGS)

imap_SOURCES = curl_fuzzer.c
imap_CPPFLAGS = -DFUZZER_IMAP $(AM_CPPFLAGS)

pop3_SOURCES = curl_fuzzer.c
pop3_CPPFLAGS = -DFUZZER_POP3 $(AM_CPPFLAGS)

httpupload_SOURCES = curl_fuzzer.c
httpupload_CPPFLAGS = -DFUZZER_HTTP_UPLOAD $(AM_CPPFLAGS)

http2_SOURCES = curl_fuzzer.c
http2_CPPFLAGS = -DFUZZER_HTTP2 $(AM_CPPFLAGS)
