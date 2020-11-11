#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) 2017 - 2020, Daniel Stenberg, <daniel@haxx.se>, et al.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution. The terms
# are also available at https://curl.haxx.se/docs/copyright.html.
#
# You may opt to use, copy, modify, merge, publish, distribute and/or sell
# copies of the Software, and permit persons to whom the Software is
# furnished to do so, under the terms of the COPYING file.
#
# This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
# KIND, either express or implied.
#
""" A telnet server which negotiates"""

from __future__ import (absolute_import, division, print_function,
                        unicode_literals)
import argparse
import os
import sys
import logging
if sys.version_info.major >= 3:
    import socketserver
else:
    import SocketServer as socketserver

log = logging.getLogger(__name__)
HOST = "localhost"
IDENT = "NTEL"


# The strings that indicate the test framework is checking our aliveness
VERIFIED_REQ = "verifiedserver"
VERIFIED_RSP = "WE ROOLZ: {pid}"


def telnetserver(options):
    """
    Starts up a TCP server with a telnet handler and serves DICT requests
    forever.
    """
    if options.pidfile:
        pid = os.getpid()
        # see tests/server/util.c function write_pidfile
        if os.name == "nt":
            pid += 65536
        with open(options.pidfile, "w") as f:
            f.write(str(pid))

    local_bind = (HOST, options.port)
    log.info("Listening on %s", local_bind)

    # Need to set the allow_reuse on the class, not on the instance.
    socketserver.TCPServer.allow_reuse_address = True
    server = socketserver.TCPServer(local_bind, NegotiatingTelnetHandler)
    server.serve_forever()

    return ScriptRC.SUCCESS


class NegotiatingTelnetHandler(socketserver.BaseRequestHandler):
    """Handler class for Telnet connections.

    """
    def handle(self):
        """
        Negotiates options before reading data.
        """
        neg = Negotiator(self.request)

        try:
            # Send some initial negotiations.
            neg.send_do("NEW_ENVIRON")
            neg.send_will("NEW_ENVIRON")
            neg.send_dont("NAWS")
            neg.send_wont("NAWS")

            # Get the data passed through the negotiator
            data = neg.recv(1024)
            log.debug("Incoming data: %r", data)

            if VERIFIED_REQ.encode('utf-8') in data:
                log.debug("Received verification request from test framework")
                pid = os.getpid()
                # see tests/server/util.c function write_pidfile
                if os.name == "nt":
                    pid += 65536
                response = VERIFIED_RSP.format(pid=pid)
                response_data = response.encode('utf-8')
            else:
                log.debug("Received normal request - echoing back")
                response_data = data.decode('utf-8').strip().encode('utf-8')

            if response_data:
                log.debug("Sending %r", response_data)
                self.request.sendall(response_data)

        except IOError:
            log.exception("IOError hit during request")


class Negotiator(object):
    NO_NEG = 0
    START_NEG = 1
    WILL = 2
    WONT = 3
    DO = 4
    DONT = 5

    def __init__(self, tcp):
        self.tcp = tcp
        self.state = self.NO_NEG

    def recv(self, bytes):
        """
        Read bytes from TCP, handling negotiation sequences

        :param bytes: Number of bytes to read
        :return: a buffer of bytes
        """
        buffer = bytearray()

        # If we keep receiving negotiation sequences, we won't fill the buffer.
        # Keep looping while we can, and until we have something to give back
        # to the caller.
        while len(buffer) == 0:
            data = self.tcp.recv(bytes)
            if not data:
                # TCP failed to give us any data. Break out.
                break

            for byte_int in bytearray(data):
                if self.state == self.NO_NEG:
                    self.no_neg(byte_int, buffer)
                elif self.state == self.START_NEG:
                    self.start_neg(byte_int)
                elif self.state in [self.WILL, self.WONT, self.DO, self.DONT]:
                    self.handle_option(byte_int)
                else:
                    # Received an unexpected byte. Stop negotiations
                    log.error("Unexpected byte %s in state %s",
                              byte_int,
                              self.state)
                    self.state = self.NO_NEG

        return buffer

    def no_neg(self, byte_int, buffer):
        # Not negotiating anything thus far. Check to see if we
        # should.
        if byte_int == NegTokens.IAC:
            # Start negotiation
            log.debug("Starting negotiation (IAC)")
            self.state = self.START_NEG
        else:
            # Just append the incoming byte to the buffer
            buffer.append(byte_int)

    def start_neg(self, byte_int):
        # In a negotiation.
        log.debug("In negotiation (%s)",
                  NegTokens.from_val(byte_int))

        if byte_int == NegTokens.WILL:
            # Client is confirming they are willing to do an option
            log.debug("Client is willing")
            self.state = self.WILL
        elif byte_int == NegTokens.WONT:
            # Client is confirming they are unwilling to do an
            # option
            log.debug("Client is unwilling")
            self.state = self.WONT
        elif byte_int == NegTokens.DO:
            # Client is indicating they can do an option
            log.debug("Client can do")
            self.state = self.DO
        elif byte_int == NegTokens.DONT:
            # Client is indicating they can't do an option
            log.debug("Client can't do")
            self.state = self.DONT
        else:
            # Received an unexpected byte. Stop negotiations
            log.error("Unexpected byte %s in state %s",
                      byte_int,
                      self.state)
            self.state = self.NO_NEG

    def handle_option(self, byte_int):
        if byte_int in [NegOptions.BINARY,
                        NegOptions.CHARSET,
                        NegOptions.SUPPRESS_GO_AHEAD,
                        NegOptions.NAWS,
                        NegOptions.NEW_ENVIRON]:
            log.debug("Option: %s", NegOptions.from_val(byte_int))

            # No further negotiation of this option needed. Reset the state.
            self.state = self.NO_NEG

        else:
            # Received an unexpected byte. Stop negotiations
            log.error("Unexpected byte %s in state %s",
                      byte_int,
                      self.state)
            self.state = self.NO_NEG

    def send_message(self, message_ints):
        self.tcp.sendall(bytearray(message_ints))

    def send_iac(self, arr):
        message = [NegTokens.IAC]
        message.extend(arr)
        self.send_message(message)

    def send_do(self, option_str):
        log.debug("Sending DO %s", option_str)
        self.send_iac([NegTokens.DO, NegOptions.to_val(option_str)])

    def send_dont(self, option_str):
        log.debug("Sending DONT %s", option_str)
        self.send_iac([NegTokens.DONT, NegOptions.to_val(option_str)])

    def send_will(self, option_str):
        log.debug("Sending WILL %s", option_str)
        self.send_iac([NegTokens.WILL, NegOptions.to_val(option_str)])

    def send_wont(self, option_str):
        log.debug("Sending WONT %s", option_str)
        self.send_iac([NegTokens.WONT, NegOptions.to_val(option_str)])


class NegBase(object):
    @classmethod
    def to_val(cls, name):
        return getattr(cls, name)

    @classmethod
    def from_val(cls, val):
        for k in cls.__dict__.keys():
            if getattr(cls, k) == val:
                return k

        return "<unknown>"


class NegTokens(NegBase):
    # The start of a negotiation sequence
    IAC = 255
    # Confirm willingness to negotiate
    WILL = 251
    # Confirm unwillingness to negotiate
    WONT = 252
    # Indicate willingness to negotiate
    DO = 253
    # Indicate unwillingness to negotiate
    DONT = 254

    # The start of sub-negotiation options.
    SB = 250
    # The end of sub-negotiation options.
    SE = 240


class NegOptions(NegBase):
    # Binary Transmission
    BINARY = 0
    # Suppress Go Ahead
    SUPPRESS_GO_AHEAD = 3
    # NAWS - width and height of client
    NAWS = 31
    # NEW-ENVIRON - environment variables on client
    NEW_ENVIRON = 39
    # Charset option
    CHARSET = 42


def get_options():
    parser = argparse.ArgumentParser()

    parser.add_argument("--port", action="store", default=9019,
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

    formatter = logging.Formatter("%(asctime)s %(levelname)-5.5s "
                                  "[{ident}] %(message)s"
                                  .format(ident=IDENT))

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
        rc = telnetserver(options)
    except Exception as e:
        log.exception(e)
        rc = ScriptRC.EXCEPTION

    log.info("Returning %d", rc)
    sys.exit(rc)
