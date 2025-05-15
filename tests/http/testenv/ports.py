#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#***************************************************************************
#                                  _   _ ____  _
#  Project                     ___| | | |  _ \| |
#                             / __| | | | |_) | |
#                            | (__| |_| |  _ <| |___
#                             \___|\___/|_| \_\_____|
#
# Copyright (C) Daniel Stenberg, <daniel@haxx.se>, et al.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution. The terms
# are also available at https://curl.se/docs/copyright.html.
#
# You may opt to use, copy, modify, merge, publish, distribute and/or sell
# copies of the Software, and permit persons to whom the Software is
# furnished to do so, under the terms of the COPYING file.
#
# This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
# KIND, either express or implied.
#
# SPDX-License-Identifier: curl
#
###########################################################################
#
import logging
import os
import socket
from collections.abc import Callable
from typing import Dict

from filelock import FileLock

log = logging.getLogger(__name__)


def alloc_port_set(port_specs: Dict[str, int]) -> Dict[str, int]:
    socks = []
    ports = {}
    for name, ptype in port_specs.items():
        try:
            s = socket.socket(type=ptype)
            s.bind(('', 0))
            ports[name] = s.getsockname()[1]
            socks.append(s)
        except Exception as e:
            raise e
    for s in socks:
        s.close()
    return ports


def alloc_ports_and_do(port_spec: Dict[str, int],
                       do_func: Callable[[Dict[str, int]], bool],
                       gen_dir, max_tries=1) -> bool:
    lock_file = os.path.join(gen_dir, 'ports.lock')
    with FileLock(lock_file):
        for _ in range(max_tries):
            port_set = alloc_port_set(port_spec)
            if do_func(port_set):
                return True
    return False
