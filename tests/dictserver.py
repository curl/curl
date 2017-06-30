#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
""" DICT server """

from __future__ import (absolute_import, division, print_function,
                        unicode_literals)
import argparse
import os
import sys
import logging
try:  # Python 2
    import SocketServer as socketserver
except ImportError:  # Python 3
    import socketserver


log = logging.getLogger(__name__)
HOST = "localhost"

# The strings that indicate the test framework is checking our aliveness
VERIFIED_REQ = b"verifiedserver"
VERIFIED_RSP = "WE ROOLZ: {pid}"


def dictserver(options):
    """
    Starts up a TCP server with a DICT handler and serves DICT requests
    forever.
    """
    if options.pidfile:
        pid = os.getpid()
        with open(options.pidfile, "w") as f:
            f.write("{0}".format(pid))

    local_bind = (HOST, options.port)
    log.info("[DICT] Listening on %s", local_bind)

    # Need to set the allow_reuse on the class, not on the instance.
    socketserver.TCPServer.allow_reuse_address = True
    server = socketserver.TCPServer(local_bind, DictHandler)
    server.serve_forever()

    return ScriptRC.SUCCESS


class DictHandler(socketserver.BaseRequestHandler):
    """Handler class for DICT connections.

    """
    def handle(self):
        """
        Simple function which responds to all queries with a 552.
        """
        try:
            # First, send a response to allow the server to continue.
            rsp = "220 dictserver <xnooptions> <msgid@msgid>\n"
            self.request.sendall(rsp.encode("utf-8"))

            # Receive the request.
            data = self.request.recv(1024).strip()
            log.debug("[DICT] Incoming data: %r", data)

            if VERIFIED_REQ in data:
                log.debug("[DICT] Received verification request from test "
                          "framework")
                response_data = VERIFIED_RSP.format(pid=os.getpid())
            else:
                log.debug("[DICT] Received normal request")
                response_data = "No matches"

            # Send back a failure to find.
            response = "552 {0}\n".format(response_data)
            log.debug("[DICT] Responding with %r", response)
            self.request.sendall(response.encode("utf-8"))

        except IOError:
            log.exception("[DICT] IOError hit during request")


def get_options():
    parser = argparse.ArgumentParser()

    parser.add_argument("--port", action="store", default=9016,
                        type=int, help="port to listen on")
    parser.add_argument("--verbose", action="store", type=int, default=0,
                        help="verbose output")
    parser.add_argument("--pidfile", action="store",
                        help="file name for the PID")
    parser.add_argument("--logfile", action="store",
                        help="file name for the log")
    parser.add_argument("--srcdir", action="store", help="test directory")
    parser.add_argument("--id", action="store", help="server ID")
    parser.add_argument("--ipv4", action="store_true", default=0,
                        help="IPv4 flag")

    return parser.parse_args()


def setup_logging(options):
    """
    Set up logging from the command line options
    """
    root_logger = logging.getLogger()
    add_stdout = False

    formatter = logging.Formatter("%(asctime)s %(levelname)-5.5s %(message)s")

    # Write out to a logfile
    if options.logfile:
        handler = logging.FileHandler(options.logfile, mode="w")
        handler.setFormatter(formatter)
        handler.setLevel(logging.DEBUG)
        root_logger.addHandler(handler)
    else:
        # The logfile wasn't specified. Add a stdout logger.
        add_stdout = True

    if options.verbose:
        # Add a stdout logger as well in verbose mode
        root_logger.setLevel(logging.DEBUG)
        add_stdout = True
    else:
        root_logger.setLevel(logging.INFO)

    if add_stdout:
        stdout_handler = logging.StreamHandler(sys.stdout)
        stdout_handler.setFormatter(formatter)
        stdout_handler.setLevel(logging.DEBUG)
        root_logger.addHandler(stdout_handler)


class ScriptRC(object):
    """Enum for script return codes"""
    SUCCESS = 0
    FAILURE = 1
    EXCEPTION = 2


class ScriptException(Exception):
    pass


if __name__ == '__main__':
    # Get the options from the user.
    options = get_options()

    # Setup logging using the user options
    setup_logging(options)

    # Run main script.
    try:
        rc = dictserver(options)
    except Exception as e:
        log.exception(e)
        rc = ScriptRC.EXCEPTION

    log.info("[DICT] Returning %d", rc)
    sys.exit(rc)
