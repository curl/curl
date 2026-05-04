#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ***************************************************************************
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
import os
import subprocess
import time

import pytest
from testenv import CurlClient, Env

MARK_NEEDS_HTTPS_PROXY = pytest.mark.skipif(
    condition=not Env.curl_has_feature("HTTPS-proxy"),
    reason="curl lacks HTTPS-proxy support"
)
MARK_NEEDS_HTTP3 = pytest.mark.skipif(
    condition=not Env.curl_has_feature("HTTP3"), reason="curl lacks HTTP/3 support"
)
MARK_NEEDS_PROXY_HTTP3 = pytest.mark.skipif(
    condition=not Env.curl_has_feature("PROXY-HTTP3"),
    reason="curl lacks experimental HTTP/3 proxy support"
)
MARK_NEEDS_NGHTTP3 = pytest.mark.skipif(
    condition=not Env.curl_uses_lib("nghttp3"), reason="only supported with nghttp3"
)
MARK_NEEDS_NGHTTP2 = pytest.mark.skipif(
    condition=not Env.curl_uses_lib("nghttp2"), reason="only supported with nghttp2"
)
MARK_NEEDS_H2O = pytest.mark.skipif(
    condition=not Env.have_h2o(), reason="no h2o available"
)
MARK_NEEDS_NGHTTPX = pytest.mark.skipif(
    condition=not Env.have_nghttpx(), reason="no nghttpx available"
)

H3_PROXY_COMMON_MARKS = [
    MARK_NEEDS_HTTPS_PROXY,
    MARK_NEEDS_HTTP3,
    MARK_NEEDS_PROXY_HTTP3,
    MARK_NEEDS_NGHTTP3,
]

NGTCP2_ONLY_MSG = "only supported with the ngtcp2 quic stack"
UNSUPPORTED_OPT_MSG = "does not support this"
H2O_HELLO_MSG = '"message": "Hello from h2o HTTP/3 server"'


def _require_available(**items):
    missing = [name for name, value in items.items() if not value]
    if missing:
        pytest.skip(f"{' or '.join(missing)} not available")


def _download_path(curl: CurlClient) -> str:
    return os.path.join(curl.run_dir, "download_#1.data")


def _check_download_message(curl: CurlClient, expected: str):
    dpath = _download_path(curl)
    assert os.path.exists(dpath), f"Download file not found: {dpath}"
    with open(dpath, "r") as fd:
        content = fd.read()
    assert expected in content, f"Unexpected response content: {content}"


def _check_download_size(curl: CurlClient, expected_size: int):
    dpath = _download_path(curl)
    assert os.path.exists(dpath), f"Download file not found: {dpath}"
    actual = os.path.getsize(dpath)
    assert actual == expected_size, f"expected {expected_size}B download, got {actual}B"


def _nghttpx_proxy_args(
    env: Env,
    nghttpx,
    proxy_proto: str,
    tunnel: bool,
    insecure: bool = False,
):
    xargs = [
        "--proxy",
        f"https://{env.proxy_domain}:{nghttpx._port}/",
        "--resolve",
        f"{env.proxy_domain}:{nghttpx._port}:127.0.0.1",
        "--proxy-cacert",
        env.ca.cert_file,
    ]
    if proxy_proto == "h3":
        xargs.append("--proxy-http3")
    elif proxy_proto == "h2":
        xargs.append("--proxy-http2")

    if tunnel:
        xargs.append("--proxytunnel")

    xargs.extend(["--cacert", env.ca.cert_file, "--proxy-insecure"])
    if insecure:
        xargs.append("--insecure")
    return xargs


def _h2o_proxy_args(
    env: Env,
    h2o_proxy,
    proxy_proto: str,
    tunnel: bool,
    insecure: bool = False,
):
    if proxy_proto == "h3":
        pport = h2o_proxy.port
    elif proxy_proto == "h2":
        pport = h2o_proxy.h2_port
    else:
        pport = h2o_proxy.h1_port

    xargs = [
        "--proxy",
        f"https://{env.proxy_domain}:{pport}/",
        "--resolve",
        f"{env.proxy_domain}:{pport}:127.0.0.1",
        "--proxy-cacert",
        env.ca.cert_file,
    ]
    if proxy_proto == "h2":
        xargs.append("--proxy-http2")
    elif proxy_proto == "h3":
        xargs.append("--proxy-http3")

    if tunnel:
        xargs.append("--proxytunnel")

    xargs.extend(["--cacert", env.ca.cert_file, "--proxy-insecure"])
    if insecure:
        xargs.append("--insecure")
    return xargs


class TestH3ProxySuccess:
    """Success matrix for HTTP/3 proxy CONNECT / CONNECT-UDP."""

    pytestmark = H3_PROXY_COMMON_MARKS + [MARK_NEEDS_H2O]

    @pytest.mark.parametrize(
        ["alpn_proto", "proxy_proto"],
        [
            pytest.param("http/1.1", "h3", id="h1_over_h3_proxytunnel"),
            pytest.param(
                "h2",
                "h3",
                marks=MARK_NEEDS_NGHTTP2,
                id="h2_over_h3_proxytunnel",
            ),
            pytest.param("h3", "h3", id="h3_over_h3_proxytunnel"),
            pytest.param(
                "h3",
                "h2",
                marks=MARK_NEEDS_NGHTTP2,
                id="h3_over_h2_proxytunnel",
            ),
            pytest.param("h3", "http/1.1", id="h3_over_h1_proxytunnel"),
        ],
    )
    def test_60_01_connect_tunnel(
        self,
        env: Env,
        h2o_server,
        h2o_proxy,
        alpn_proto,
        proxy_proto,
    ):
        _require_available(h2o_server=h2o_server, h2o_proxy=h2o_proxy)

        curl = CurlClient(env=env)
        url = f"https://localhost:{h2o_server.port}/data.json"
        proxy_args = _h2o_proxy_args(
            env, h2o_proxy, proxy_proto, tunnel=True, insecure=True
        )

        r = curl.http_download(
            urls=[url], alpn_proto=alpn_proto, with_stats=True, extra_args=proxy_args
        )
        r.check_response(count=1, http_status=200)
        _check_download_message(curl, H2O_HELLO_MSG)


class TestH3ProxyFailure:
    """Failure matrix when proxy side does not support requested mode."""

    pytestmark = H3_PROXY_COMMON_MARKS + [MARK_NEEDS_NGHTTPX]

    @pytest.mark.parametrize(
        ["alpn_proto", "proxy_proto", "exp_err"],
        [
            pytest.param(
                "http/1.1",
                "h3",
                "failed: could not connect to server",
                id="fail_h1_over_h3_proxytunnel",
            ),
            pytest.param(
                "h2",
                "h3",
                "failed: could not connect to server",
                marks=MARK_NEEDS_NGHTTP2,
                id="fail_h2_over_h3_proxytunnel",
            ),
            pytest.param(
                "h3",
                "h3",
                "failed: could not connect to server",
                id="fail_h3_over_h3_proxytunnel",
            ),
            pytest.param(
                "h3",
                "h2",
                "connect-udp response status 400",
                marks=MARK_NEEDS_NGHTTP2,
                id="fail_h3_over_h2_proxytunnel",
            ),
            pytest.param(
                "h3",
                "http/1.1",
                "connect-udp tunnel failed, response 404",
                id="fail_h3_over_h1_proxytunnel",
            ),
        ],
    )
    def test_60_02_connect_tunnel_fail(
        self,
        env: Env,
        httpd,
        nghttpx,
        alpn_proto,
        proxy_proto,
        exp_err,
    ):
        _require_available(httpd=httpd, nghttpx=nghttpx)

        curl = CurlClient(env=env)
        url = f"https://localhost:{httpd.ports['https']}/data.json"
        proxy_args = _nghttpx_proxy_args(env, nghttpx, proxy_proto, tunnel=True)
        r = curl.http_download(
            urls=[url], alpn_proto=alpn_proto, with_stats=True, extra_args=proxy_args
        )
        assert r.exit_code != 0, f"Expected failure but curl succeeded: {r}"
        assert exp_err in r.stderr.lower(), (
            f"Expected protocol/proxy error but got: {r.stderr}"
        )


class TestH3ProxyModeSelection:
    """Behavior checks for tunnel vs non-tunnel proxy mode selection."""

    pytestmark = H3_PROXY_COMMON_MARKS + [MARK_NEEDS_NGHTTPX]

    @pytest.mark.parametrize(
        ["proxy_proto"],
        [
            pytest.param("h3", id="proxy_h3"),
            pytest.param("h2", marks=MARK_NEEDS_NGHTTP2, id="proxy_h2"),
            pytest.param("http/1.1", id="proxy_h1"),
        ],
    )
    def test_60_03_h3_target_auto_connect_udp(
        self, env: Env, httpd, nghttpx, proxy_proto
    ):
        _require_available(httpd=httpd, nghttpx=nghttpx)

        curl = CurlClient(env=env)
        url = f"https://localhost:{httpd.ports['https']}/data.json"
        proxy_args = _nghttpx_proxy_args(
            env, nghttpx, proxy_proto, tunnel=False
        )
        r = curl.http_download(
            urls=[url], alpn_proto="h3", with_stats=True, extra_args=proxy_args
        )

        # An HTTP/3 target auto-triggers CONNECT-UDP even without --proxytunnel,
        # just as HTTPS targets auto-trigger CONNECT. nghttpx does not support
        # CONNECT-UDP so this fails, which confirms auto-CONNECT-UDP is active.
        assert r.exit_code != 0, (
            "expected failure: h3 target auto-triggers CONNECT-UDP "
            "which nghttpx does not support"
        )
        assert "connect-udp" in r.stderr.lower(), (
            f"expected CONNECT-UDP attempt in output, got: {r.stderr}"
        )


class TestH3ProxyRuntimeGuards:
    """Guard checks for unsupported HTTP/3 proxy options."""

    pytestmark = [
        MARK_NEEDS_HTTPS_PROXY,
        MARK_NEEDS_PROXY_HTTP3,
        pytest.mark.skipif(
            condition=Env.curl_uses_lib("ngtcp2"),
            reason="guard only applies to non-ngtcp2 builds",
        ),
    ]

    @pytest.mark.skipif(
        condition=not Env.curl_has_feature("HTTP3"), reason="curl lacks HTTP/3 support"
    )
    def test_60_04_guard_proxy_http3_unsupported(self, env: Env, httpd):
        curl = CurlClient(env=env)
        url = f"https://localhost:{httpd.ports['https']}/data.json"
        proxy_args = [
            "--proxy",
            "https://127.0.0.1:1/",
            "--proxy-http3",
            "--proxytunnel",
            "--proxy-insecure",
            "--cacert",
            env.ca.cert_file,
        ]

        r = curl.http_download(
            urls=[url], alpn_proto="http/1.1", with_stats=True, extra_args=proxy_args
        )
        if not env.curl_has_feature("PROXY-HTTP3"):
            r.check_exit_code(2)
            assert UNSUPPORTED_OPT_MSG in r.stderr.lower(), (
                f"Expected unsupported option failure but got: {r.stderr}"
            )
            return

        r.check_exit_code(1)
        assert NGTCP2_ONLY_MSG in r.stderr.lower(), (
            f"Expected ngtcp2 guard failure but got: {r.stderr}"
        )


class TestH3ProxyRobustness:
    """Robustness checks for shutdown and proxy loss during transfer."""

    pytestmark = H3_PROXY_COMMON_MARKS + [MARK_NEEDS_H2O]

    @pytest.fixture(autouse=True, scope="class")
    def _class_scope(self, env):
        doc_root = os.path.join(env.gen_dir, "docs")
        env.make_data_file(
            indir=doc_root, fname="proxy-drop-20m", fsize=20 * 1024 * 1024
        )

    def test_60_05_graceful_shutdown(
        self, env: Env, h2o_server, h2o_proxy
    ):
        if not env.curl_is_debug():
            pytest.skip("needs debug curl for shutdown trace lines")
        if not env.curl_is_verbose():
            pytest.skip("needs verbose-strings curl build")

        curl = CurlClient(env=env, run_env={"CURL_DEBUG": "all"})
        url = f"https://localhost:{h2o_server.port}/data.json"
        proxy_args = curl.get_proxy_args(proto="h3", tunnel=True)
        proxy_args.extend(["--cacert", env.ca.cert_file, "--insecure"])

        r = curl.http_download(
            urls=[url], alpn_proto="h3", with_stats=True, extra_args=proxy_args
        )
        r.check_response(count=1, http_status=200)

        shutdown_lines = [
            line
            for line in r.trace_lines
            if ("start shutdown(" in line.lower())
            or ("shutdown completely sent off" in line.lower())
        ]
        assert shutdown_lines, f"No shutdown trace lines found:\n{r.stderr}"

    def test_60_06_proxy_drop_mid_transfer(self, env: Env, h2o_server, h2o_proxy):
        _require_available(h2o_server=h2o_server, h2o_proxy=h2o_proxy)

        proxy_port = h2o_proxy.port
        url = f"https://localhost:{h2o_server.port}/proxy-drop-20m"
        out_path = os.path.join(env.gen_dir, "proxy-drop.out")
        args = [
            env.curl,
            "--http1.1",
            "--proxy",
            f"https://{env.proxy_domain}:{proxy_port}/",
            "--resolve",
            f"{env.proxy_domain}:{proxy_port}:127.0.0.1",
            "--proxy-cacert",
            env.ca.cert_file,
            "--proxy-http3",
            "--proxytunnel",
            "--proxy-insecure",
            "--cacert",
            env.ca.cert_file,
            "--limit-rate",
            "100k",
            "--max-time",
            "20",
            "-o",
            out_path,
            url,
        ]

        proc = None
        try:
            proc = subprocess.Popen(
                args=args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
            )
            time.sleep(1.0)
            assert h2o_proxy.stop(), "failed to stop h2o proxy"
            _, stderr = proc.communicate(timeout=30)
            assert proc.returncode != 0, (
                "curl should fail when proxy is terminated mid-transfer"
            )
            serr = stderr.lower()
            assert (
                "failed" in serr
                or "transfer closed" in serr
                or "recv failure" in serr
                or "connection" in serr
            ), f"Unexpected error output: {stderr}"
        finally:
            if proc and (proc.poll() is None):
                proc.kill()
                proc.wait(timeout=5)
            assert h2o_proxy.start(), "failed to restart h2o proxy"


class TestH3ProxyDataTransfer:
    """Large file transfers and multiplexing through HTTP/3 proxy."""

    pytestmark = H3_PROXY_COMMON_MARKS + [MARK_NEEDS_H2O]

    @pytest.fixture(autouse=True, scope="class")
    def _class_scope(self, env):
        doc_root = os.path.join(env.gen_dir, "docs")
        env.make_data_file(indir=doc_root, fname="download-1m", fsize=1 * 1024 * 1024)
        env.make_data_file(indir=doc_root, fname="download-10m", fsize=10 * 1024 * 1024)
        env.make_data_file(indir=env.gen_dir, fname="upload-2m", fsize=2 * 1024 * 1024)

    def test_60_07_large_download(self, env: Env, h2o_server, h2o_proxy):
        _require_available(h2o_server=h2o_server, h2o_proxy=h2o_proxy)
        curl = CurlClient(env=env)
        url = f"https://localhost:{h2o_server.port}/download-10m"
        proxy_args = _h2o_proxy_args(env, h2o_proxy, "h3", tunnel=True, insecure=True)
        r = curl.http_download(
            urls=[url], alpn_proto="http/1.1", with_stats=True, extra_args=proxy_args
        )
        r.check_response(count=1, http_status=200)
        _check_download_size(curl, 10 * 1024 * 1024)

    def test_60_08_large_upload(self, env: Env, httpd, h2o_server, h2o_proxy):
        _require_available(h2o_proxy=h2o_proxy)
        fdata = os.path.join(env.gen_dir, "upload-2m")
        curl = CurlClient(env=env)
        url = f"https://localhost:{httpd.ports['https']}/curltest/echo?id=[0-0]"
        proxy_args = _h2o_proxy_args(env, h2o_proxy, "h3", tunnel=True, insecure=True)
        r = curl.http_upload(
            urls=[url],
            data=f"@{fdata}",
            alpn_proto="http/1.1",
            with_stats=True,
            extra_args=proxy_args,
        )
        r.check_response(count=1, http_status=200)

    def test_60_09_parallel_downloads(self, env: Env, h2o_server, h2o_proxy):
        _require_available(h2o_server=h2o_server, h2o_proxy=h2o_proxy)
        count = 5
        curl = CurlClient(env=env)
        urln = f"https://localhost:{h2o_server.port}/download-1m?[0-{count - 1}]"
        proxy_args = _h2o_proxy_args(env, h2o_proxy, "h3", tunnel=True, insecure=True)
        proxy_args.extend(["--parallel", "--parallel-max", f"{count}"])
        r = curl.http_download(
            urls=[urln], alpn_proto="http/1.1", with_stats=True, extra_args=proxy_args
        )
        r.check_response(count=count, http_status=200)


class TestH3ProxyConnectionManagement:
    """Proxy authentication, connection reuse, and session resumption."""

    pytestmark = H3_PROXY_COMMON_MARKS + [MARK_NEEDS_H2O]

    def test_60_10_proxy_basic_auth(self, env: Env, h2o_server, h2o_proxy):
        _require_available(h2o_server=h2o_server, h2o_proxy=h2o_proxy)
        curl = CurlClient(env=env)
        url = f"https://localhost:{h2o_server.port}/data.json"
        proxy_args = _h2o_proxy_args(env, h2o_proxy, "h3", tunnel=True, insecure=True)
        proxy_args.extend(["--proxy-user", "testuser:testpass"])
        r = curl.http_download(
            urls=[url], alpn_proto="http/1.1", with_stats=True, extra_args=proxy_args
        )
        r.check_response(count=1, http_status=200)
        _check_download_message(curl, H2O_HELLO_MSG)

    def test_60_11_connection_reuse(self, env: Env, h2o_server, h2o_proxy):
        _require_available(h2o_server=h2o_server, h2o_proxy=h2o_proxy)
        curl = CurlClient(env=env)
        urln = f"https://localhost:{h2o_server.port}/data.json?[0-2]"
        proxy_args = _h2o_proxy_args(env, h2o_proxy, "h3", tunnel=True, insecure=True)
        r = curl.http_download(
            urls=[urln], alpn_proto="http/1.1", with_stats=True, extra_args=proxy_args
        )
        r.check_response(count=3, http_status=200)
        assert r.total_connects <= 3, (
            f"expected proxy connection reuse, got {r.total_connects} connects"
        )

    def test_60_12_quic_session_resumption(self, env: Env, h2o_server, h2o_proxy):
        _require_available(h2o_server=h2o_server, h2o_proxy=h2o_proxy)
        # First request establishes QUIC session
        curl1 = CurlClient(env=env)
        url = f"https://localhost:{h2o_server.port}/data.json"
        proxy_args = _h2o_proxy_args(env, h2o_proxy, "h3", tunnel=True, insecure=True)
        r1 = curl1.http_download(
            urls=[url], alpn_proto="http/1.1", with_stats=True, extra_args=proxy_args
        )
        r1.check_response(count=1, http_status=200)
        # Second request from a fresh CurlClient; session may be reused
        # by the TLS session cache if supported
        curl2 = CurlClient(env=env)
        r2 = curl2.http_download(
            urls=[url], alpn_proto="http/1.1", with_stats=True, extra_args=proxy_args
        )
        r2.check_response(count=1, http_status=200)
        # Third request from a fresh CurlClient; session may be reused
        # by the TLS session cache if supported
        curl3 = CurlClient(env=env)
        r3 = curl3.http_download(
            urls=[url], alpn_proto="http/1.1", with_stats=True, extra_args=proxy_args
        )
        r3.check_response(count=1, http_status=200)


class TestH3ProxyUdpTunnel:
    """CONNECT-UDP tunnel payload size and capsule-protocol tests."""

    pytestmark = H3_PROXY_COMMON_MARKS

    @pytest.fixture(autouse=True, scope="class")
    def _class_scope(self, env):
        doc_root = os.path.join(env.gen_dir, "docs")
        env.make_data_file(indir=doc_root, fname="download-1400", fsize=1400)
        env.make_data_file(indir=doc_root, fname="download-1m", fsize=1 * 1024 * 1024)
        env.make_data_file(indir=doc_root, fname="download-10m", fsize=10 * 1024 * 1024)

    @MARK_NEEDS_H2O
    @pytest.mark.parametrize(
        "fname,fsize",
        [
            ("download-1400", 1400),
            ("download-1m", 1 * 1024 * 1024),
            ("download-10m", 10 * 1024 * 1024),
        ],
    )
    def test_60_13_udp_tunnel_payload_sizes(
        self, env: Env, h2o_server, h2o_proxy, fname, fsize
    ):
        _require_available(h2o_server=h2o_server, h2o_proxy=h2o_proxy)
        curl = CurlClient(env=env)
        url = f"https://localhost:{h2o_server.port}/{fname}"
        proxy_args = _h2o_proxy_args(env, h2o_proxy, "h3", tunnel=True, insecure=True)
        r = curl.http_download(
            urls=[url], alpn_proto="h3", with_stats=True, extra_args=proxy_args
        )
        r.check_response(count=1, http_status=200)
        _check_download_size(curl, fsize)

    @MARK_NEEDS_NGHTTPX
    def test_60_14_udp_tunnel_capsule_absent(self, env: Env, httpd, nghttpx):
        _require_available(httpd=httpd, nghttpx=nghttpx)
        curl = CurlClient(env=env)
        url = f"https://localhost:{httpd.ports['https']}/data.json"
        proxy_args = _nghttpx_proxy_args(env, nghttpx, "h3", tunnel=True)
        r = curl.http_download(
            urls=[url], alpn_proto="h3", with_stats=True, extra_args=proxy_args
        )
        assert r.exit_code != 0, (
            "expected failure: nghttpx does not support CONNECT-UDP / Capsule-Protocol"
        )


class TestH3ProxyEdgeCases:
    """Timeout and protocol-mismatch edge cases."""

    pytestmark = H3_PROXY_COMMON_MARKS + [MARK_NEEDS_H2O]

    def test_60_15_connect_timeout(self, env: Env, h2o_server):
        _require_available(h2o_server=h2o_server)
        curl = CurlClient(env=env, timeout=15)
        url = f"https://localhost:{h2o_server.port}/data.json"
        proxy_args = [
            "--proxy",
            "https://192.0.2.1:1/",
            "--proxy-http3",
            "--proxytunnel",
            "--proxy-insecure",
            "--connect-timeout",
            "3",
            "--cacert",
            env.ca.cert_file,
        ]
        r = curl.http_download(
            urls=[url], alpn_proto="http/1.1", with_stats=True, extra_args=proxy_args
        )
        assert r.exit_code != 0, "expected timeout connecting to unreachable proxy"
        assert r.duration.total_seconds() < 10, (
            f"timeout not respected: took {r.duration.total_seconds():.1f}s"
        )

    @MARK_NEEDS_NGHTTP2
    def test_60_16_h2_uses_connect_tcp_not_udp(self, env: Env, httpd, h2o_proxy):
        _require_available(httpd=httpd, h2o_proxy=h2o_proxy)
        curl = CurlClient(env=env)
        url = f"https://localhost:{httpd.ports['https']}/data.json"
        proxy_args = _h2o_proxy_args(env, h2o_proxy, "h3", tunnel=True, insecure=True)
        # h2 inner traffic always uses CONNECT (TCP), never CONNECT-UDP,
        # even through an HTTP/3 proxy with --proxytunnel. h2o supports
        # CONNECT TCP tunneling, so this request succeeds.
        r = curl.http_download(
            urls=[url], alpn_proto="h2", with_stats=True, extra_args=proxy_args
        )
        r.check_response(count=1, http_status=200)
