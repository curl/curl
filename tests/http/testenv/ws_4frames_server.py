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
import argparse
import asyncio
import logging

import websockets


MESSAGES = [
    "Hello 1",
    "Hello 2",
    "Hello 3",
    "Hello 4",
]


async def handler(websocket):
    peer = websocket.remote_address
    print(f"client from {peer[0]}:{peer[1]}", flush=True)
    print("handshake complete", flush=True)

    await asyncio.sleep(0.1)
    for index, payload in enumerate(MESSAGES, start=1):
        await websocket.send(payload)
        print(f"sent frame {index}: {payload!r}", flush=True)
        # await asyncio.sleep(0.2)

    # await asyncio.sleep(2.0)
    print("server done", flush=True)


async def main():
    parser = argparse.ArgumentParser(prog='scorecard', description="""
        Run a websocket 4frames server.
        """)
    parser.add_argument("--port", type=int,
                        default=9876, help="port to listen on")
    args = parser.parse_args()

    logging.basicConfig(
        format="%(asctime)s %(message)s",
        level=logging.DEBUG,
    )

    print(f"listening on ws://localhost:{args.port}", flush=True)
    async with websockets.serve(handler, 'localhost', args.port):
        await asyncio.Future()


if __name__ == "__main__":
    asyncio.run(main())
