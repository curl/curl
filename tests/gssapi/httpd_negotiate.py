#!/usr/bin/python
#
# Copyright (C) 2016, Isaac Boukris <iboukris@gmail.com>
# MIT licensed - see COPYING


import sys
import gssapi
import base64
import argparse
from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer


def parse_args():
  parser = argparse.ArgumentParser(description='HTTP Negotiate Server (GSSAPI)')
  parser.add_argument('--addr', default='127.0.0.1', help="The address to listen on")
  parser.add_argument('--port', default='8040', help="The port to listen on")

  return vars(parser.parse_args())


class negotiateHandler(BaseHTTPRequestHandler):
  protocol_version = 'HTTP/1.1'

  def do_GET(self):
    auth_header = self.headers.get("Authorization")

    if auth_header and auth_header.find("Negotiate") == 0:
      in_token = base64.b64decode(auth_header.split()[1])
      ctx = gssapi.SecurityContext(usage='accept')
      out_token = ctx.step(in_token)

      if ctx.complete:
        body = str(ctx.initiator_name)
        self.send_response(200)

        if out_token:
          self.send_header('WWW-Authenticate',
                           'Negotiate ' + base64.b64encode(out_token))

        self.send_header('Content-Type', 'text/plain')
        self.send_header('Content-Length', len(body))

        self.end_headers()
        self.wfile.write(body)

        return

    self.send_response(401)
    self.send_header('WWW-Authenticate', 'Negotiate')
    self.send_header('Content-Type', 'text/plain')
    self.send_header('Content-Length', '7')
    self.end_headers()
    self.wfile.write('Go away')

    return


if __name__ == '__main__':
  args = parse_args()
  try:
    server = HTTPServer((args['addr'], int(args['port'])), negotiateHandler)
    sys.stderr.write('Serving at: %s:%s\n' % (args['addr'], args['port']))
    sys.stdout.write('ready')
    sys.stdout.flush()

    server.serve_forever()

  finally:
    server.socket.close()

