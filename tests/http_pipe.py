#!/usr/bin/python

# Copyright 2012 Google Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Modified by Linus Nielsen Feltzing for inclusion in the libcurl test
# framework
#
import SocketServer
import argparse
import re
import select
import socket
import time
import pprint
import os

INFO_MESSAGE = '''
This is a test server to test the libcurl pipelining functionality.
It is a modified version if Google's HTTP pipelining test server. More
information can be found here:

http://dev.chromium.org/developers/design-documents/network-stack/http-pipelining

Source code can be found here:

http://code.google.com/p/http-pipelining-test/
'''
MAX_REQUEST_SIZE = 1024  # bytes
MIN_POLL_TIME = 0.01  # seconds. Minimum time to poll, in order to prevent
                      # excessive looping because Python refuses to poll for
                      # small timeouts.
SEND_BUFFER_TIME = 0.5  # seconds
TIMEOUT = 30  # seconds


class Error(Exception):
  pass


class RequestTooLargeError(Error):
  pass


class ServeIndexError(Error):
  pass


class UnexpectedMethodError(Error):
  pass


class RequestParser(object):
  """Parses an input buffer looking for HTTP GET requests."""

  global logfile

  LOOKING_FOR_GET = 1
  READING_HEADERS = 2

  HEADER_RE = re.compile('([^:]+):(.*)\n')
  REQUEST_RE = re.compile('([^ ]+) ([^ ]+) HTTP/(\d+)\.(\d+)\n')

  def __init__(self):
    """Initializer."""
    self._buffer = ""
    self._pending_headers = {}
    self._pending_request = ""
    self._state = self.LOOKING_FOR_GET
    self._were_all_requests_http_1_1 = True
    self._valid_requests = []

  def ParseAdditionalData(self, data):
    """Finds HTTP requests in |data|.

    Args:
      data: (String) Newly received input data from the socket.

    Returns:
      (List of Tuples)
        (String) The request path.
        (Map of String to String) The header name and value.

    Raises:
      RequestTooLargeError: If the request exceeds MAX_REQUEST_SIZE.
      UnexpectedMethodError: On a non-GET method.
      Error: On a programming error.
    """
    logfile = open('log/server.input', 'a')
    logfile.write(data)
    logfile.close()
    self._buffer += data.replace('\r', '')
    should_continue_parsing = True
    while should_continue_parsing:
      if self._state == self.LOOKING_FOR_GET:
        should_continue_parsing = self._DoLookForGet()
      elif self._state == self.READING_HEADERS:
        should_continue_parsing = self._DoReadHeader()
      else:
        raise Error('Unexpected state: ' + self._state)
    if len(self._buffer) > MAX_REQUEST_SIZE:
      raise RequestTooLargeError(
          'Request is at least %d bytes' % len(self._buffer))
    valid_requests = self._valid_requests
    self._valid_requests = []
    return valid_requests

  @property
  def were_all_requests_http_1_1(self):
    return self._were_all_requests_http_1_1

  def _DoLookForGet(self):
    """Tries to parse an HTTTP request line.

    Returns:
      (Boolean) True if a request was found.

    Raises:
      UnexpectedMethodError: On a non-GET method.
    """
    m = self.REQUEST_RE.match(self._buffer)
    if not m:
      return False
    method, path, http_major, http_minor = m.groups()

    if method != 'GET':
      raise UnexpectedMethodError('Unexpected method: ' + method)
    if path in ['/', '/index.htm', '/index.html']:
      raise ServeIndexError()

    if http_major != '1' or http_minor != '1':
      self._were_all_requests_http_1_1 = False

#    print method, path

    self._pending_request = path
    self._buffer = self._buffer[m.end():]
    self._state = self.READING_HEADERS
    return True

  def _DoReadHeader(self):
    """Tries to parse a HTTP header.

    Returns:
      (Boolean) True if it found the end of the request or a HTTP header.
    """
    if self._buffer.startswith('\n'):
      self._buffer = self._buffer[1:]
      self._state = self.LOOKING_FOR_GET
      self._valid_requests.append((self._pending_request,
                                   self._pending_headers))
      self._pending_headers = {}
      self._pending_request = ""
      return True

    m = self.HEADER_RE.match(self._buffer)
    if not m:
      return False

    header = m.group(1).lower()
    value = m.group(2).strip().lower()
    if header not in self._pending_headers:
      self._pending_headers[header] = value
    self._buffer = self._buffer[m.end():]
    return True


class ResponseBuilder(object):
  """Builds HTTP responses for a list of accumulated requests."""

  def __init__(self):
    """Initializer."""
    self._max_pipeline_depth = 0
    self._requested_paths = []
    self._processed_end = False
    self._were_all_requests_http_1_1 = True

  def QueueRequests(self, requested_paths, were_all_requests_http_1_1):
    """Adds requests to the queue of requests.

    Args:
      requested_paths: (List of Strings) Requested paths.
    """
    self._requested_paths.extend(requested_paths)
    self._were_all_requests_http_1_1 = were_all_requests_http_1_1

  def Chunkify(self, data, chunksize):
    """ Divides a string into chunks
    """
    return [hex(chunksize)[2:] + "\r\n" + data[i:i+chunksize] + "\r\n" for i in range(0, len(data), chunksize)]

  def BuildResponses(self):
    """Converts the queue of requests into responses.

    Returns:
      (String) Buffer containing all of the responses.
    """
    result = ""
    self._max_pipeline_depth = max(self._max_pipeline_depth,
                                   len(self._requested_paths))
    for path, headers in self._requested_paths:
      if path == '/verifiedserver':
        body = "WE ROOLZ: {}\r\n".format(os.getpid());
        result += self._BuildResponse(
            '200 OK', ['Server: Apache',
                       'Content-Length: {}'.format(len(body)),
                       'Cache-Control: no-store'], body)

      elif path == '/alphabet.txt':
        body = 'abcdefghijklmnopqrstuvwxyz'
        result += self._BuildResponse(
            '200 OK', ['Server: Apache',
                       'Content-Length: 26',
                       'Cache-Control: no-store'], body)

      elif path == '/reverse.txt':
        body = 'zyxwvutsrqponmlkjihgfedcba'
        result += self._BuildResponse(
            '200 OK', ['Content-Length: 26', 'Cache-Control: no-store'], body)

      elif path == '/chunked.txt':
        body = ('7\r\nchunked\r\n'
                '8\r\nencoding\r\n'
                '2\r\nis\r\n'
                '3\r\nfun\r\n'
                '0\r\n\r\n')
        result += self._BuildResponse(
            '200 OK', ['Transfer-Encoding: chunked', 'Cache-Control: no-store'],
            body)

      elif path == '/cached.txt':
        body = 'azbycxdwevfugthsirjqkplomn'
        result += self._BuildResponse(
            '200 OK', ['Content-Length: 26', 'Cache-Control: max-age=60'], body)

      elif path == '/connection_close.txt':
        body = 'azbycxdwevfugthsirjqkplomn'
        result += self._BuildResponse(
            '200 OK', ['Content-Length: 26', 'Cache-Control: max-age=60', 'Connection: close'], body)
        self._processed_end = True

      elif path == '/1k.txt':
        str = '0123456789abcdef'
        body = ''.join([str for num in xrange(64)])
        result += self._BuildResponse(
            '200 OK', ['Server: Apache',
                       'Content-Length: 1024',
                       'Cache-Control: max-age=60'], body)

      elif path == '/10k.txt':
        str = '0123456789abcdef'
        body = ''.join([str for num in xrange(640)])
        result += self._BuildResponse(
            '200 OK', ['Server: Apache',
                       'Content-Length: 10240',
                       'Cache-Control: max-age=60'], body)

      elif path == '/100k.txt':
        str = '0123456789abcdef'
        body = ''.join([str for num in xrange(6400)])
        result += self._BuildResponse(
            '200 OK',
            ['Server: Apache',
             'Content-Length: 102400',
             'Cache-Control: max-age=60'],
            body)

      elif path == '/100k_chunked.txt':
        str = '0123456789abcdef'
        moo = ''.join([str for num in xrange(6400)])
        body = self.Chunkify(moo, 20480)
        body.append('0\r\n\r\n')
        body = ''.join(body)

        result += self._BuildResponse(
            '200 OK', ['Transfer-Encoding: chunked', 'Cache-Control: no-store'], body)

      elif path == '/stats.txt':
        results = {
            'max_pipeline_depth': self._max_pipeline_depth,
            'were_all_requests_http_1_1': int(self._were_all_requests_http_1_1),
        }
        body = ','.join(['%s:%s' % (k, v) for k, v in results.items()])
        result += self._BuildResponse(
            '200 OK',
            ['Content-Length: %s' % len(body), 'Cache-Control: no-store'], body)
        self._processed_end = True

      else:
        result += self._BuildResponse('404 Not Found', ['Content-Length: 7'], 'Go away')
      if self._processed_end:
          break
    self._requested_paths = []
    return result

  def WriteError(self, status, error):
    """Returns an HTTP response for the specified error.

    Args:
      status: (String) Response code and descrtion (e.g. "404 Not Found")

    Returns:
      (String) Text of HTTP response.
    """
    return self._BuildResponse(
        status, ['Connection: close', 'Content-Type: text/plain'], error)

  @property
  def processed_end(self):
    return self._processed_end

  def _BuildResponse(self, status, headers, body):
    """Builds an HTTP response.

    Args:
      status: (String) Response code and descrtion (e.g. "200 OK")
      headers: (List of Strings) Headers (e.g. "Connection: close")
      body: (String) Response body.

    Returns:
      (String) Text of HTTP response.
    """
    return ('HTTP/1.1 %s\r\n'
            '%s\r\n'
            '\r\n'
            '%s' % (status, '\r\n'.join(headers), body))


class PipelineRequestHandler(SocketServer.BaseRequestHandler):
  """Called on an incoming TCP connection."""

  def _GetTimeUntilTimeout(self):
    return self._start_time + TIMEOUT - time.time()

  def _GetTimeUntilNextSend(self):
    if not self._last_queued_time:
      return TIMEOUT
    return self._last_queued_time + SEND_BUFFER_TIME - time.time()

  def handle(self):
    self._request_parser = RequestParser()
    self._response_builder = ResponseBuilder()
    self._last_queued_time = 0
    self._num_queued = 0
    self._num_written = 0
    self._send_buffer = ""
    self._start_time = time.time()
    try:
      poller = select.epoll(sizehint=1)
      poller.register(self.request.fileno(), select.EPOLLIN)
      while not self._response_builder.processed_end or self._send_buffer:

        time_left = self._GetTimeUntilTimeout()
        time_until_next_send = self._GetTimeUntilNextSend()
        max_poll_time = min(time_left, time_until_next_send) + MIN_POLL_TIME

        events = None
        if max_poll_time > 0:
          if self._send_buffer:
            poller.modify(self.request.fileno(),
                          select.EPOLLIN | select.EPOLLOUT)
          else:
            poller.modify(self.request.fileno(), select.EPOLLIN)
          events = poller.poll(timeout=max_poll_time)

        if self._GetTimeUntilTimeout() <= 0:
          return

        if self._GetTimeUntilNextSend() <= 0:
          self._send_buffer += self._response_builder.BuildResponses()
          self._num_written = self._num_queued
          self._last_queued_time = 0

        for fd, mode in events:
          if mode & select.EPOLLIN:
            new_data = self.request.recv(MAX_REQUEST_SIZE, socket.MSG_DONTWAIT)
            if not new_data:
              return
            new_requests = self._request_parser.ParseAdditionalData(new_data)
            self._response_builder.QueueRequests(
                new_requests, self._request_parser.were_all_requests_http_1_1)
            self._num_queued += len(new_requests)
            self._last_queued_time = time.time()
          elif mode & select.EPOLLOUT:
            num_bytes_sent = self.request.send(self._send_buffer[0:4096])
            self._send_buffer = self._send_buffer[num_bytes_sent:]
            time.sleep(0.05)
          else:
            return

    except RequestTooLargeError as e:
      self.request.send(self._response_builder.WriteError(
          '413 Request Entity Too Large', e))
      raise
    except UnexpectedMethodError as e:
      self.request.send(self._response_builder.WriteError(
          '405 Method Not Allowed', e))
      raise
    except ServeIndexError:
      self.request.send(self._response_builder.WriteError(
          '200 OK', INFO_MESSAGE))
    except Exception as e:
      print e
    self.request.close()


class PipelineServer(SocketServer.ForkingMixIn, SocketServer.TCPServer):
  pass


parser = argparse.ArgumentParser()
parser.add_argument("--port", action="store", default=0,
                  type=int, help="port to listen on")
parser.add_argument("--verbose", action="store", default=0,
                  type=int, help="verbose output")
parser.add_argument("--pidfile", action="store", default=0,
                  help="file name for the PID")
parser.add_argument("--logfile", action="store", default=0,
                  help="file name for the log")
parser.add_argument("--srcdir", action="store", default=0,
                  help="test directory")
parser.add_argument("--id", action="store", default=0,
                  help="server ID")
parser.add_argument("--ipv4", action="store_true", default=0,
                  help="IPv4 flag")
args = parser.parse_args()

if args.pidfile:
    pid = os.getpid()
    f = open(args.pidfile, 'w')
    f.write('{}'.format(pid))
    f.close()

server = PipelineServer(('0.0.0.0', args.port), PipelineRequestHandler)
server.allow_reuse_address = True
server.serve_forever()
