struct respctx {
  curl_socket_t sock[2]; /* [0] is curl's end, [1] is the "server" end */
  const char *resp;
  size_t resplen;
  bool handed_out;
};
