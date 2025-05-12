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
import json
import logging
import os
import re
import socket
from json import JSONEncoder
from typing import Dict, List

import pytest
from filelock import FileLock

log = logging.getLogger(__name__)


def alloc_port_sets(n: int, port_specs: Dict[str, int]) -> List[Dict[str, int]]:
    port_sets = []
    socks = []
    for _ in range(n):
        ports = {}
        for name, ptype in port_specs.items():
            try:
                s = socket.socket(type=ptype)
                s.bind(('', 0))
                ports[name] = s.getsockname()[1]
                socks.append(s)
            except Exception as e:
                raise e
        port_sets.append(ports)
    for s in socks:
        s.close()
    return port_sets


def alloc_ports(config: pytest.Config,
                gen_dir,
                testrun_uid,
                worker_id : str,
                port_specs: Dict[str, int]) -> Dict[str, int]:
    if "PYTEST_XDIST_WORKER_COUNT" in os.environ:
        nworkers = int(os.environ["PYTEST_XDIST_WORKER_COUNT"])
    else:
        nworkers = 1
    m = re.match(r'\D+(\d+)', worker_id)
    idx = int(m.group(1)) if m else 0
    assert idx < nworkers
    # several worker processes that need this set of ports. Make
    # a global locked allocation for all of them, store in a file
    #
    # `testrun_uid` is the pytest-xdist generated id of this run.
    lock_file = os.path.join(gen_dir, 'allocated.ports.lock')
    port_file = os.path.join(gen_dir, 'allocated.ports')
    with FileLock(lock_file):
        port_json = None
        if os.path.exists(port_file):
            with open(port_file) as fd:
                port_json = json.load(fd)
            if 'testrun_uid' not in port_json or \
                    port_json['testrun_uid'] != str(testrun_uid):
                # file from other run or garbage file
                port_json = None
        if port_json is None:
            # generate a complete port set for all workers
            port_json = {
                'testrun_uid': str(testrun_uid),
                'sets': alloc_port_sets(nworkers, port_specs),
            }
            with open(port_file, 'w') as fd:
                fd.write(JSONEncoder().encode(port_json))

        assert port_json
        assert len(port_json['sets']) == nworkers
        return port_json['sets'][idx]
