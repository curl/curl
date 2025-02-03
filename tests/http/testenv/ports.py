#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#***************************************************************************
#  Project
#                         _____       __         .__     
#                       _/ ____\_____/  |_  ____ |  |__  
#                       \   __\/ __ \   __\/ ___\|  |  \ 
#                       |  | \  ___/|  | \  \___|   Y  \
#                       |__|  \___  >__|  \___  >___|  /
#                                 \/          \/     \/
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
# SPDX-License-Identifier: fetch
#
###########################################################################
#
import logging
import socket
from typing import Dict

log = logging.getLogger(__name__)


def alloc_ports(port_specs: Dict[str, int]) -> Dict[str, int]:
    ports = {}
    socks = []
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
