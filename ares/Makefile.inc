CSOURCES = ares_fds.c ares_getsock.c ares_process.c ares_free_hostent.c	\
ares_query.c ares__close_sockets.c ares_free_string.c ares_search.c	\
ares__get_hostent.c ares_gethostbyaddr.c ares_send.c ares__read_line.c	\
ares_gethostbyname.c ares_strerror.c ares_cancel.c ares_init.c		\
ares_timeout.c ares_destroy.c ares_mkquery.c ares_version.c		\
ares_expand_name.c ares_parse_a_reply.c windows_port.c			\
ares_expand_string.c ares_parse_ptr_reply.c ares_parse_aaaa_reply.c	\
ares_getnameinfo.c inet_net_pton.c bitncmp.c inet_ntop.c		\
ares_parse_ns_reply.c

HHEADERS = ares.h ares_private.h setup.h ares_dns.h ares_version.h          \
           nameser.h inet_net_pton.h inet_ntop.h ares_ipv6.h bitncmp.h      \
           setup_once.h 

MANPAGES= ares_destroy.3 ares_expand_name.3 ares_expand_string.3 ares_fds.3 \
 ares_free_hostent.3 ares_free_string.3 ares_gethostbyaddr.3		    \
 ares_gethostbyname.3 ares_init.3 ares_init_options.3 ares_mkquery.3	    \
 ares_parse_a_reply.3 ares_parse_ptr_reply.3 ares_process.3		    \
 ares_query.3 ares_search.3 ares_send.3 ares_strerror.3 ares_timeout.3	    \
 ares_version.3 ares_cancel.3 ares_parse_aaaa_reply.3 ares_getnameinfo.3    \
 ares_getsock.3 ares_parse_ns_reply.3

