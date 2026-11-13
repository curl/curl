#!/usr/bin/env python3
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
import re

import websockets


def parse_size(m):
    if m is None:
        return None
    size = int(m.group(1))
    if not m.group(2):
        pass
    elif m.group(2).lower() == 'kb':
        size *= 1024
    elif m.group(2).lower() == 'mb':
        size *= 1024 * 1024
    elif m.group(2).lower() == 'gb':
        size *= 1024 * 1024 * 1024
    return size


async def handler(websocket):
    peer = websocket.remote_address
    print(f"client from {peer[0]}:{peer[1]}", flush=True)
    print("handshake complete", flush=True)

    dl_size = parse_size(re.search(r'/(\d+)(mb|kb|gb)?',
                                   websocket.request.path,
                                   flags=re.IGNORECASE))
    print(f"start download of {dl_size} bytes ws data", flush=True)
    if dl_size:
        if dl_size < (16 * 1024):
            frame = b'x' * dl_size
        else:
            frame = b'x' * (16 * 1024)
        nframes = max(int(dl_size / len(frame)), 1)

        for _ in range(nframes):
            await websocket.send(frame)
            # print(f"sent frame {index}, len={len(frame)}", flush=True)

    print("response done", flush=True)


async def main():
    parser = argparse.ArgumentParser(prog='ws_4frames_server', description="""
        Run a websocket 4frames server.
        """)
    parser.add_argument("--port", type=int,
                        default=9876, help="port to listen on")
    args = parser.parse_args()

    logging.basicConfig(
        format="%(asctime)s %(message)s",
        level=logging.WARNING,
    )

    print(f"listening on ws://localhost:{args.port}", flush=True)
    async with websockets.serve(handler, 'localhost', args.port):
        await asyncio.Future()


if __name__ == "__main__":
    asyncio.run(main())
