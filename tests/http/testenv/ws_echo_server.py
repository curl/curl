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
import argparse
import asyncio
import logging

from websockets import server
from websockets.exceptions import ConnectionClosedError


async def echo(websocket):
    try:
        async for message in websocket:
            await websocket.send(message)
    except ConnectionClosedError:
        pass


async def run_server(port):
    async with server.serve(echo, "localhost", port):
        await asyncio.Future()  # run forever


def main():
    parser = argparse.ArgumentParser(prog='scorecard', description="""
        Run a websocket echo server.
        """)
    parser.add_argument("--port", type=int,
                        default=9876, help="port to listen on")
    args = parser.parse_args()

    logging.basicConfig(
        format="%(asctime)s %(message)s",
        level=logging.DEBUG,
    )

    asyncio.run(run_server(args.port))


if __name__ == "__main__":
    main()
