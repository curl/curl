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
import base64
import hashlib
import logging
import os
import re
import socket
import threading
import time

import pytest
from testenv import CurlClient, Env, LocalClient, WsServer

log = logging.getLogger(__name__)


@pytest.mark.skipif(condition=not Env.curl_has_protocol('ws'),
                    reason='curl lacks ws protocol support')
class TestWebsockets:

    @pytest.fixture(autouse=True, scope='class')
    @classmethod
    def ws_echo(cls, env):
        server = WsServer('ws_echo', env)
        server.startup()
        yield server
        server.shutdown()

    @pytest.fixture(autouse=True, scope='class')
    @classmethod
    def ws_4frames(cls, env):
        server = WsServer('ws_4frames', env)
        server.startup()
        yield server
        server.shutdown()

    @pytest.fixture(autouse=True, scope='class')
    @classmethod
    def ws_dl(cls, env):
        server = WsServer('ws_dl', env)
        server.startup()
        yield server
        server.shutdown()

    def test_20_01_basic(self, env: Env, ws_echo):
        curl = CurlClient(env=env)
        url = f'http://localhost:{ws_echo.port}/'
        r = curl.http_download(urls=[url])
        r.check_response(http_status=426)

    def test_20_02_pingpong_small(self, env: Env, ws_echo):
        payload = 125 * "x"
        client = LocalClient(env=env, name='cli_ws_pingpong')
        if not client.exists():
            pytest.skip(f'example client not built: {client.name}')
        url = f'ws://localhost:{ws_echo.port}/'
        r = client.run(args=[url, payload])
        r.check_exit_code(0)

    # the python websocket server does not like 'large' control frames
    def test_20_03_pingpong_too_large(self, env: Env, ws_echo):
        payload = 127 * "x"
        client = LocalClient(env=env, name='cli_ws_pingpong')
        if not client.exists():
            pytest.skip(f'example client not built: {client.name}')
        url = f'ws://localhost:{ws_echo.port}/'
        r = client.run(args=[url, payload])
        r.check_exit_code(100)  # CURLE_TOO_LARGE

    @pytest.mark.parametrize("model", [
        pytest.param(1, id='multi_perform'),
        pytest.param(2, id='curl_ws_send+recv'),
    ])
    def test_20_04_data_small(self, env: Env, ws_echo, model):
        client = LocalClient(env=env, name='cli_ws_data')
        if not client.exists():
            pytest.skip(f'example client not built: {client.name}')
        url = f'ws://localhost:{ws_echo.port}/'
        r = client.run(args=[f'-{model}', '-c', '10', '-m', str(1), '-M', str(10), url])
        r.check_exit_code(0)

    @pytest.mark.parametrize("model", [
        pytest.param(1, id='multi_perform'),
        pytest.param(2, id='curl_ws_send+recv'),
    ])
    def test_20_05_data_med(self, env: Env, ws_echo, model):
        client = LocalClient(env=env, name='cli_ws_data')
        if not client.exists():
            pytest.skip(f'example client not built: {client.name}')
        url = f'ws://localhost:{ws_echo.port}/'
        r = client.run(args=[f'-{model}', '-m', str(120), '-M', str(130), url])
        r.check_exit_code(0)

    @pytest.mark.parametrize("model", [
        pytest.param(1, id='multi_perform'),
        pytest.param(2, id='curl_ws_send+recv'),
    ])
    def test_20_06_data_large(self, env: Env, ws_echo, model):
        client = LocalClient(env=env, name='cli_ws_data')
        if not client.exists():
            pytest.skip(f'example client not built: {client.name}')
        url = f'ws://localhost:{ws_echo.port}/'
        r = client.run(args=[f'-{model}', '-m', str(65535 - 5), '-M', str(65535 + 5), url])
        r.check_exit_code(0)

    @pytest.mark.parametrize("model", [
        pytest.param(1, id='multi_perform'),
        pytest.param(2, id='curl_ws_send+recv'),
    ])
    def test_20_07_data_large_small_recv(self, env: Env, ws_echo, model):
        run_env = os.environ.copy()
        run_env['CURL_WS_CHUNK_SIZE'] = '1024'
        client = LocalClient(env=env, name='cli_ws_data', run_env=run_env)
        if not client.exists():
            pytest.skip(f'example client not built: {client.name}')
        url = f'ws://localhost:{ws_echo.port}/'
        r = client.run(args=[f'-{model}', '-m', str(65535 - 5), '-M', str(65535 + 5), url])
        r.check_exit_code(0)

    # Send large frames and simulate send blocking on 8192 bytes chunks
    # Simulates error reported in #15865
    @pytest.mark.parametrize("model", [
        pytest.param(1, id='multi_perform'),
        pytest.param(2, id='curl_ws_send+recv'),
    ])
    def test_20_08_data_very_large(self, env: Env, ws_echo, model):
        run_env = os.environ.copy()
        run_env['CURL_WS_CHUNK_EAGAIN'] = '8192'
        client = LocalClient(env=env, name='cli_ws_data', run_env=run_env)
        if not client.exists():
            pytest.skip(f'example client not built: {client.name}')
        url = f'ws://localhost:{ws_echo.port}/'
        count = 10
        large = 20000
        r = client.run(args=[f'-{model}', '-c', str(count), '-m', str(large), url])
        r.check_exit_code(0)

    @pytest.mark.parametrize("model", [
        pytest.param(1, id='multi_perform'),
        pytest.param(2, id='curl_ws_send+recv'),
    ])
    def test_20_09_data_empty(self, env: Env, ws_echo, model):
        client = LocalClient(env=env, name='cli_ws_data')
        if not client.exists():
            pytest.skip(f'example client not built: {client.name}')
        url = f'ws://localhost:{ws_echo.port}/'
        count = 10
        large = 0
        r = client.run(args=[f'-{model}', '-c', str(count), '-m', str(large), url])
        r.check_exit_code(0)

    # use ws:// URL with HTTP proxy, check that it tunnels automatically
    def test_20_10_proxy_http(self, env: Env, httpd, ws_echo):
        curl = CurlClient(env=env)
        url = f'ws://127.0.0.1:{ws_echo.port}/'
        xargs = curl.get_proxy_args(proxys=False)
        xargs.extend([
            '--max-time', '2'
        ])
        r = curl.http_download(urls=[url], alpn_proto='http/1.1', with_stats=True,
                               extra_args=xargs)
        # The CONNECT through the proxy fails as it does not allow it
        r.check_exit_code(7)  # CURLE_COULDNT_CONNECT
        assert r.stats[0]['http_connect'] == 403, f'{r}'

    def test_20_11_crazy_pings(self, env: Env):
        st = {}
        send_rounds = 1

        def srv():
            try:
                with socket.socket() as s:
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    s.bind(("127.0.0.1", 0))
                    s.listen(1)
                    st["p"] = s.getsockname()[1]

                    c, _ = s.accept()
                    c.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
                    c.settimeout(Env.SERVER_TIMEOUT)
                    req = b""
                    while b"\r\n\r\n" not in req:
                        req += c.recv(4096)

                    k = re.search(rb"(?im)^Sec-WebSocket-Key:\s*(\S+)", req).group(1)
                    a = base64.b64encode(
                        hashlib.sha1(k + b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11").digest()
                    ).decode()
                    c.sendall(
                        "HTTP/1.1 101 Switching Protocols\r\n"
                        "Upgrade: websocket\r\n"
                        "Connection: Upgrade\r\n"
                        f"Sec-WebSocket-Accept: {a}\r\n\r\n"
                        .encode()
                    )

                    f = b"\x89\x00" * 65536  # PING frames, many
                    try:
                        for _ in range(send_rounds):
                            c.sendall(f)
                        f = b"\x88\x00"  # CLOSE frame
                        c.sendall(f)
                    except OSError:
                        # Client may close/reset while we intentionally flood frames.
                        # Send errors are expected here, ignore them.
                        pass
                    time.sleep(1)
                    c.close()
            except OSError as e:
                st["err"] = e

        run_env = os.environ.copy()
        if 'CURL_DEBUG' in run_env:
            del run_env['CURL_DEBUG']
        curl = CurlClient(env=env, run_env=run_env)
        send_rounds = 2
        threading.Thread(target=srv, daemon=True).start()
        while "p" not in st and "err" not in st:
            time.sleep(0.01)
        assert "err" not in st, f'ws-ping server failed to start: {st["err"]}'

        url = f'ws://127.0.0.1:{st["p"]}/'
        r = curl.http_download(urls=[url], alpn_proto='http/1.1', with_stats=True,
                               with_profile=True)
        assert r.exit_code in [0, 55, 56], f'{r.dump_logs()}'  # SEND/RECV_ERROR
        assert r.profile, f'{r}'
        rss1 = r.profile.stats['rss-max'] / (1024 * 1024)

        st.clear()
        send_rounds = 10
        threading.Thread(target=srv, daemon=True).start()
        while "p" not in st and "err" not in st:
            time.sleep(0.01)
        assert "err" not in st, f'ws-ping server failed to start: {st["err"]}'

        url = f'ws://127.0.0.1:{st["p"]}/'
        r = curl.http_download(urls=[url], alpn_proto='http/1.1', with_stats=True,
                               with_profile=True)
        assert r.exit_code in [0, 55, 56], f'{r.dump_logs()}'  # SEND/RECV_ERROR
        assert r.profile, f'{r}'
        rss2 = r.profile.stats['rss-max'] / (1024 * 1024)
        assert (rss1 * 1.35) > rss2, 'bad memory increase'

    # test small frames delivery when pausing
    def test_20_12_pause_frames_small(self, env: Env, ws_4frames):
        payload = 127 * "x"
        client = LocalClient(env=env, name='cli_ws_pause')
        if not client.exists():
            pytest.skip(f'example client not built: {client.name}')
        url = f'ws://localhost:{ws_4frames.port}/small'
        r = client.run(args=[url, payload])
        r.check_exit_code(0)

    # test small frames delivery when pausing
    def test_20_13_pause_frames_large(self, env: Env, ws_4frames):
        payload = 127 * "x"
        client = LocalClient(env=env, name='cli_ws_pause')
        if not client.exists():
            pytest.skip(f'example client not built: {client.name}')
        url = f'ws://localhost:{ws_4frames.port}/large'
        r = client.run(args=[url, payload])
        r.check_exit_code(0)

    # test handling of write callback errors
    def test_20_14_write_err(self, env: Env, ws_4frames):
        payload = 127 * "x"
        client = LocalClient(env=env, name='cli_ws_write_err')
        if not client.exists():
            pytest.skip(f'example client not built: {client.name}')
        url = f'ws://localhost:{ws_4frames.port}/small'
        r = client.run(args=[url, payload])
        r.check_exit_code(0)

    def test_20_15_dl_10mb(self, env: Env, httpd, ws_dl):
        curl = CurlClient(env=env)
        url = f'ws://127.0.0.1:{ws_dl.port}/10mb'
        r = curl.http_download(urls=[url], alpn_proto='http/1.1', with_stats=True)
        r.check_exit_code(0)

    @pytest.mark.parametrize('case,accepted', [
        ('valid', True),
        ('connection-token-list', True),
        ('custom-key', True),
        ('requested-subprotocol', True),
        ('missing-accept', False),
        ('wrong-accept', False),
        ('duplicate-accept', False),
        ('missing-upgrade', False),
        ('wrong-upgrade', False),
        ('missing-connection', False),
        ('wrong-connection', False),
        ('unrequested-extension', False),
        ('unrequested-subprotocol', False),
        ('wrong-requested-subprotocol', False),
    ])
    def test_20_16_handshake_validation(self, env: Env, case, accepted):
        ready = threading.Event()
        status = {}

        def server():
            try:
                with socket.socket() as listener:
                    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    listener.bind(('127.0.0.1', 0))
                    listener.listen(1)
                    status['port'] = listener.getsockname()[1]
                    ready.set()
                    with listener.accept()[0] as conn:
                        conn.settimeout(Env.SERVER_TIMEOUT)
                        request = b''
                        while b'\r\n\r\n' not in request:
                            chunk = conn.recv(4096)
                            if not chunk:
                                return
                            request += chunk
                        key = re.search(rb'(?im)^Sec-WebSocket-Key:\s*(\S+)', request).group(1)
                        accept = base64.b64encode(hashlib.sha1(
                            key + b'258EAFA5-E914-47DA-95CA-C5AB0DC85B11'
                        ).digest()).decode()
                        headers = {
                            'Upgrade': 'websocket',
                            'Connection': 'Upgrade',
                            'Sec-WebSocket-Accept': accept,
                        }
                        if case == 'connection-token-list':
                            headers['Connection'] = 'keep-alive, Upgrade'
                        elif case == 'missing-accept':
                            del headers['Sec-WebSocket-Accept']
                        elif case == 'wrong-accept':
                            headers['Sec-WebSocket-Accept'] = 'incorrect'
                        elif case == 'missing-upgrade':
                            del headers['Upgrade']
                        elif case == 'wrong-upgrade':
                            headers['Upgrade'] = 'h2c'
                        elif case == 'missing-connection':
                            del headers['Connection']
                        elif case == 'wrong-connection':
                            headers['Connection'] = 'keep-alive'
                        elif case == 'unrequested-extension':
                            headers['Sec-WebSocket-Extensions'] = 'permessage-deflate'
                        elif case in ('unrequested-subprotocol',
                                      'wrong-requested-subprotocol'):
                            headers['Sec-WebSocket-Protocol'] = 'admin'
                        elif case == 'requested-subprotocol':
                            headers['Sec-WebSocket-Protocol'] = 'chat'
                        lines = ['HTTP/1.1 101 Switching Protocols'] + [
                            f'{name}: {value}' for name, value in headers.items()
                        ]
                        if case == 'duplicate-accept':
                            lines.append(f'Sec-WebSocket-Accept: {accept}')
                        response = ('\r\n'.join(lines) + '\r\n\r\n').encode()
                        conn.sendall(response + b'\x88\x00')
                        time.sleep(0.1)
            except OSError as e:
                status['error'] = e

        worker = threading.Thread(target=server, daemon=True)
        worker.start()
        assert ready.wait(Env.SERVER_TIMEOUT)
        curl = CurlClient(env=env)
        extra_args = ['--max-time', '2']
        if case == 'custom-key':
            extra_args.extend(['-H', 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ=='])
        elif case in ('requested-subprotocol', 'wrong-requested-subprotocol'):
            extra_args.extend(['-H', 'Sec-WebSocket-Protocol: chat, superchat'])
        url = f'ws://127.0.0.1:{status["port"]}/'
        r = curl.http_download(urls=[url], alpn_proto='http/1.1',
                               extra_args=extra_args)
        worker.join(Env.SERVER_TIMEOUT)
        assert 'error' not in status, f'WebSocket test server failed: {status}'
        r.check_exit_code(0 if accepted else 8)

    @pytest.mark.parametrize('offers,selection,accepted', [
        pytest.param(['Sec-WebSocket-Extensions: permessage-deflate'],
                     'permessage-deflate', True, id='raw-requested'),
        pytest.param(['Sec-WebSocket-Extensions: permessage-deflate; '
                      'client_max_window_bits'],
                     'permessage-deflate; client_max_window_bits=12', True,
                     id='raw-negotiated-parameter'),
        pytest.param(['Sec-WebSocket-Extensions: permessage-deflate'],
                     'PERMESSAGE-DEFLATE', True, id='raw-case-insensitive'),
        pytest.param(['Sec-WebSocket-Extensions: permessage-deflate'],
                     'permessage-deflate; client_max_window_bits="12"', True,
                     id='raw-quoted-parameter'),
        pytest.param(['Sec-WebSocket-Extensions: permessage-deflate, x-test'],
                     'permessage-deflate, x-test; mode=fast', True,
                     id='raw-multiple-extensions'),
        pytest.param(['Sec-WebSocket-Extensions: x-test',
                      'Sec-WebSocket-Extensions: permessage-deflate'],
                     'permessage-deflate', True, id='raw-split-request'),
        pytest.param(['Sec-WebSocket-Extensions: permessage-deflate'],
                     'x-unknown', False, id='raw-unrequested'),
        pytest.param(['Sec-WebSocket-Extensions: permessage-deflate'],
                     'permessage-deflate-extra', False,
                     id='raw-name-prefix'),
        pytest.param(['Sec-WebSocket-Extensions: permessage-deflate'],
                     'permessage-deflate,', False, id='raw-trailing-comma'),
        pytest.param(['Sec-WebSocket-Extensions: permessage-deflate'],
                     'permessage-deflate; mode="two words"', False,
                     id='raw-invalid-quoted-value'),
        pytest.param(['-'], 'permessage-deflate', False,
                     id='raw-without-offer'),
        pytest.param([
            'Sec-WebSocket-Extensions: ' +
            ','.join(f'x{i}' for i in range(1000)) + ',x-accepted'],
            ','.join(['x-accepted'] * 300), False,
            id='raw-excessive-extension-scan'),
        pytest.param([
            'Sec-WebSocket-Extensions: ' +
            ','.join(f'x{i}' for i in range(1000)) + ',x-accepted'],
            [','.join(['x-accepted'] * 150)] * 2, False,
            id='raw-excessive-extension-scan-split'),
    ])
    def test_20_17_raw_handshake_extensions(self, env: Env, offers,
                                             selection, accepted):
        client = LocalClient(env=env, name='cli_ws_raw_extensions')
        if not client.exists():
            pytest.skip(f'example client not built: {client.name}')

        ready = threading.Event()
        status = {}

        def server():
            try:
                with socket.socket() as listener:
                    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    listener.bind(('127.0.0.1', 0))
                    listener.listen(1)
                    status['port'] = listener.getsockname()[1]
                    ready.set()
                    with listener.accept()[0] as conn:
                        conn.settimeout(Env.SERVER_TIMEOUT)
                        request = b''
                        while b'\r\n\r\n' not in request:
                            chunk = conn.recv(4096)
                            if not chunk:
                                return
                            request += chunk
                        key = re.search(rb'(?im)^Sec-WebSocket-Key:\s*(\S+)',
                                        request).group(1)
                        accept = base64.b64encode(hashlib.sha1(
                            key + b'258EAFA5-E914-47DA-95CA-C5AB0DC85B11'
                        ).digest()).decode()
                        extensions = ([selection] if isinstance(selection, str)
                                      else selection)
                        response = ('HTTP/1.1 101 Switching Protocols\r\n'
                                    'Upgrade: websocket\r\n'
                                    'Connection: Upgrade\r\n'
                                    f'Sec-WebSocket-Accept: {accept}\r\n' +
                                    ''.join(f'Sec-WebSocket-Extensions: {s}\r\n'
                                            for s in extensions) +
                                    '\r\n').encode()
                        conn.sendall(response)
                        time.sleep(0.1)
            except OSError as e:
                status['error'] = e

        worker = threading.Thread(target=server, daemon=True)
        worker.start()
        assert ready.wait(Env.SERVER_TIMEOUT)
        url = f'ws://127.0.0.1:{status["port"]}/'
        r = client.run(args=[url, *offers])
        worker.join(Env.SERVER_TIMEOUT)
        assert 'error' not in status, f'WebSocket test server failed: {status}'
        r.check_exit_code(0 if accepted else 8)
